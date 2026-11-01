/* ==========================================================
   PASSWORD MANAGER — JavaScript
   Security model:
   - Master password -> PBKDF2 -> two independent secrets:
       1) a login secret sent to Firebase Auth (never the master itself)
       2) an AES-GCM key that stays in memory and never leaves the browser
   - Every entry is encrypted before it is written to Firebase.
   - Data lives at users/<uid>/passwords (see database.rules.json).
   - Nothing sensitive is written to localStorage.
   ========================================================== */

document.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons();

  // =============================================
  // CONFIG
  // =============================================
  const firebaseConfig = {
    apiKey:            "AIzaSyC8H0eXAcZS255Y6n2e_tZtDZm5TRo6ARQ",
    authDomain:        "password-manager-c8fcf.firebaseapp.com",
    databaseURL:       "https://password-manager-c8fcf-default-rtdb.firebaseio.com",
    projectId:         "password-manager-c8fcf",
    storageBucket:     "password-manager-c8fcf.firebasestorage.app",
    messagingSenderId: "933422187854",
    appId:             "1:933422187854:web:7114f0bce7b6b052ec8a1f",
    measurementId:     "G-7YWJ6V68R4"
  };

  const KDF_ITERATIONS   = 600000;        // PBKDF2-HMAC-SHA256 (OWASP 2023 guidance)
  const MIN_MASTER_LEN   = 12;
  const IDLE_LOCK_MS     = 5 * 60 * 1000; // auto-lock after 5 min of inactivity
  const CLIPBOARD_CLEAR  = 30 * 1000;     // clear copied password after 30 s
  const LEGACY_LOCAL_KEY = 'pm_passwords'; // old plaintext cache (migrated, then removed)

  // =============================================
  // DOM REFERENCES
  // =============================================
  const $ = id => document.getElementById(id);

  const form           = $('password-form');
  const websiteInput   = $('website-input');
  const usernameInput  = $('username-input');
  const passwordInput  = $('password-input');
  const saveBtn        = $('save-btn');
  const searchInput    = $('search-input');
  const passwordsList  = $('passwords-list');
  const emptyState     = $('empty-state');
  const countBadge     = $('count-badge');
  const toggleFormPw   = $('toggle-form-pw');
  const strengthFill   = $('strength-fill');
  const strengthText   = $('strength-text');
  const toastEl        = $('toast');

  const connStatus     = $('connection-status');
  const statusDot      = connStatus ? connStatus.querySelector('.status-dot') : null;
  const statusLabel    = connStatus ? connStatus.querySelector('.status-label') : null;

  // Lock screen
  const authForm       = $('auth-form');
  const authEmail      = $('auth-email');
  const authMaster     = $('auth-master');
  const authConfirm    = $('auth-confirm');
  const confirmGroup   = $('confirm-group');
  const lockWarning    = $('lock-warning');
  const lockError      = $('lock-error');
  const lockSub        = $('lock-sub');
  const authSubmit     = $('auth-submit');
  const tabSignin      = $('tab-signin');
  const tabSignup      = $('tab-signup');
  const lockBtn        = $('lock-btn');

  // Generator modal
  const generatorModal = $('generator-modal');
  const navGenerate    = $('nav-generate');
  const navVault       = $('nav-vault');
  const closeGenerator = $('close-generator');
  const generatePwBtn  = $('generate-pw-btn');
  const usePwBtn       = $('use-pw-btn');
  const generatedPw    = $('generated-pw');
  const copyGenerated  = $('copy-generated');
  const pwLengthSlider = $('pw-length');
  const pwLengthVal    = $('pw-length-val');

  // =============================================
  // STATE  (all in memory only)
  // =============================================
  let passwords   = [];     // decrypted entries: { id, website, username, password, createdAt }
  let editingId   = null;
  let cryptoKey   = null;   // non-extractable AES-GCM key
  let passwordsRef = null;
  let auth = null, db = null;
  let signupMode  = false;
  let busy        = false;
  let listenSeq   = 0;      // guards against out-of-order async decrypts
  let idleTimer, clipboardTimer;

  // Old versions cached plaintext here. Migrated after the first unlock.
  const legacyLocal = readLegacyLocal();

  render('');

  // =============================================
  // CRYPTO HELPERS (Web Crypto API)
  // =============================================
  const te = new TextEncoder();
  const td = new TextDecoder();

  const toB64 = buf => {
    let s = '';
    new Uint8Array(buf).forEach(b => { s += String.fromCharCode(b); });
    return btoa(s);
  };
  const fromB64 = str => Uint8Array.from(atob(str), c => c.charCodeAt(0));
  const toHex  = buf => Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');

  async function pbkdf2Bits(master, salt) {
    const base = await crypto.subtle.importKey('raw', te.encode(master), 'PBKDF2', false, ['deriveBits']);
    return crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: te.encode(salt), iterations: KDF_ITERATIONS },
      base, 256
    );
  }

  // Two independent derivations (different salts) so the login secret
  // Firebase sees reveals nothing about the encryption key.
  async function deriveCredentials(email, master) {
    const e = email.trim().toLowerCase();
    const [authBits, keyBits] = await Promise.all([
      pbkdf2Bits(master, 'pm-auth-v1:' + e),
      pbkdf2Bits(master, 'pm-enc-v1:'  + e)
    ]);
    const key = await crypto.subtle.importKey('raw', keyBits, 'AES-GCM', false, ['encrypt', 'decrypt']);
    return { authPassword: toHex(authBits), key };
  }

  async function encryptEntry(obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, te.encode(JSON.stringify(obj)));
    return { v: 1, iv: toB64(iv), ct: toB64(ct) };
  }

  async function decryptEntry(blob) {
    try {
      const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromB64(blob.iv) }, cryptoKey, fromB64(blob.ct)
      );
      return JSON.parse(td.decode(pt));
    } catch { return null; }
  }

  // =============================================
  // STATUS HELPERS
  // =============================================
  function setStatus(type, label) {
    if (statusDot)   statusDot.className = 'status-dot ' + type;
    if (statusLabel) statusLabel.textContent = label;
  }

  // =============================================
  // FIREBASE INIT
  // =============================================
  try {
    firebase.initializeApp(firebaseConfig);
    auth = firebase.auth();
    db   = firebase.database();
    // NONE = session is never persisted, so a reload always returns to the lock screen
    auth.setPersistence(firebase.auth.Auth.Persistence.NONE).catch(() => {});
  } catch (err) {
    console.error('Firebase init failed:', err);
    showLockError('Could not load Firebase. Check your connection and reload.');
    setStatus('offline', 'Unavailable');
  }

  // =============================================
  // LOCK SCREEN — sign in / create vault
  // =============================================
  function setMode(signup) {
    signupMode = signup;
    tabSignin.classList.toggle('active', !signup);
    tabSignup.classList.toggle('active', signup);
    tabSignin.setAttribute('aria-selected', String(!signup));
    tabSignup.setAttribute('aria-selected', String(signup));
    confirmGroup.hidden = !signup;
    lockWarning.hidden  = !signup;
    lockSub.textContent = signup ? 'Create your encrypted vault' : 'Unlock your vault';
    authMaster.autocomplete = signup ? 'new-password' : 'current-password';
    authSubmit.querySelector('span').textContent = signup ? 'Create vault' : 'Unlock vault';
    showLockError('');
  }
  tabSignin.addEventListener('click', () => setMode(false));
  tabSignup.addEventListener('click', () => setMode(true));

  function showLockError(msg) {
    lockError.textContent = msg;
    lockError.hidden = !msg;
  }

  function authMessage(err) {
    switch (err && err.code) {
      case 'auth/email-already-in-use': return 'That email already has a vault. Switch to Unlock.';
      case 'auth/invalid-email':        return 'Enter a valid email address.';
      case 'auth/user-not-found':
      case 'auth/wrong-password':
      case 'auth/invalid-credential':   return 'Wrong email or master password.';
      case 'auth/too-many-requests':    return 'Too many attempts. Wait a few minutes and try again.';
      case 'auth/network-request-failed': return 'Network error. Check your connection.';
      case 'auth/operation-not-allowed':  return 'Email/password sign-in is not enabled in Firebase yet.';
      default: return 'Could not sign in. Try again.';
    }
  }

  authForm.addEventListener('submit', async e => {
    e.preventDefault();
    if (busy || !auth) return;

    const email  = authEmail.value.trim();
    const master = authMaster.value;
    showLockError('');

    if (!authEmail.checkValidity() || !email) return showLockError('Enter a valid email address.');
    if (!master) return showLockError('Enter your master password.');
    if (signupMode) {
      if (master.length < MIN_MASTER_LEN) return showLockError(`Master password must be at least ${MIN_MASTER_LEN} characters.`);
      if (master !== authConfirm.value)   return showLockError('Passwords do not match.');
    }

    busy = true;
    authSubmit.disabled = true;
    authSubmit.querySelector('span').textContent = signupMode ? 'Creating…' : 'Unlocking…';

    try {
      const { authPassword, key } = await deriveCredentials(email, master);
      const cred = signupMode
        ? await auth.createUserWithEmailAndPassword(email, authPassword)
        : await auth.signInWithEmailAndPassword(email, authPassword);
      cryptoKey = key;
      authMaster.value = authConfirm.value = '';
      startSession(cred.user.uid);
    } catch (err) {
      console.warn('Auth failed:', err && err.code);
      showLockError(authMessage(err));
    } finally {
      busy = false;
      authSubmit.disabled = false;
      authSubmit.querySelector('span').textContent = signupMode ? 'Create vault' : 'Unlock vault';
    }
  });

  function startSession(uid) {
    passwordsRef = db.ref('users/' + uid + '/passwords');
    document.body.classList.remove('locked');
    setMode(false);
    resetIdleTimer();

    db.ref('.info/connected').on('value', snap => {
      setStatus(snap.val() === true ? 'online' : 'offline', snap.val() === true ? 'Synced' : 'Offline');
    });

    passwordsRef.on('value', async snapshot => {
      const seq = ++listenSeq;
      const rows = [];
      snapshot.forEach(child => { rows.push({ id: child.key, ...child.val() }); });

      const out = [];
      let failed = 0;
      await Promise.all(rows.map(async r => {
        const data = await decryptEntry(r);
        if (data && typeof data.website === 'string') {
          out.push({ id: r.id, createdAt: r.createdAt || 0, ...data });
        } else { failed++; }
      }));

      if (seq !== listenSeq || !cryptoKey) return; // stale or already locked
      out.sort((a, b) => b.createdAt - a.createdAt);
      passwords = out;
      render(searchInput.value);
      if (failed) showToast(`${failed} entr${failed === 1 ? 'y' : 'ies'} could not be decrypted`);
    }, err => {
      console.error('Firebase listen error:', err && err.code);
      showToast('Cannot read vault. Check database rules.');
    });

    migrateLegacyLocal();
    setTimeout(() => lucide.createIcons(), 0);
    websiteInput.focus();
  }

  function lockVault(reason) {
    if (!document.body.classList.contains('locked')) {
      listenSeq++;
      if (passwordsRef) passwordsRef.off();
      if (db) db.ref('.info/connected').off();
      if (auth) auth.signOut().catch(() => {});
      passwordsRef = null;
      cryptoKey = null;
      passwords = [];
      editingId = null;
      clearTimeout(idleTimer);
      form.reset();
      searchInput.value = '';
      closeGen();
      generatedPw.textContent = 'Click Generate';
      render('');
      setStatus('offline', 'Locked');
      document.body.classList.add('locked');
      authEmail.focus();
      if (reason) showLockError(reason);
    }
  }
  lockBtn.addEventListener('click', () => lockVault());

  // Auto-lock on inactivity
  function resetIdleTimer() {
    clearTimeout(idleTimer);
    if (cryptoKey) idleTimer = setTimeout(() => lockVault('Locked after 5 minutes of inactivity.'), IDLE_LOCK_MS);
  }
  ['pointerdown', 'keydown', 'touchstart', 'scroll'].forEach(ev =>
    document.addEventListener(ev, resetIdleTimer, { passive: true })
  );

  // =============================================
  // LEGACY MIGRATION (old plaintext localStorage -> encrypted)
  // =============================================
  function readLegacyLocal() {
    try {
      const raw = localStorage.getItem(LEGACY_LOCAL_KEY);
      const arr = raw ? JSON.parse(raw) : [];
      return Array.isArray(arr) ? arr.filter(p => p && p.website && p.username && p.password) : [];
    } catch { return []; }
  }

  async function migrateLegacyLocal() {
    if (!legacyLocal.length || !passwordsRef) return;
    try {
      await Promise.all(legacyLocal.map(async p => {
        const blob = await encryptEntry({ website: p.website, username: p.username, password: p.password });
        return passwordsRef.push().set({ ...blob, createdAt: p.createdAt || Date.now() });
      }));
      localStorage.removeItem(LEGACY_LOCAL_KEY);
      showToast(`Encrypted and imported ${legacyLocal.length} older entr${legacyLocal.length === 1 ? 'y' : 'ies'}`);
      legacyLocal.length = 0;
    } catch (err) {
      console.warn('Legacy migration failed:', err && err.code);
    }
  }

  // =============================================
  // RENDER
  // =============================================
  function render(filterText) {
    filterText = (filterText || '').toLowerCase();

    [...passwordsList.children].forEach(ch => {
      if (ch.id !== 'empty-state') ch.remove();
    });

    const filtered = passwords.filter(p =>
      p.website.toLowerCase().includes(filterText) ||
      p.username.toLowerCase().includes(filterText)
    );

    countBadge.textContent = filtered.length;

    if (filtered.length === 0) {
      emptyState.style.display = 'block';
      emptyState.querySelector('h3').textContent = filterText
        ? 'No results found'
        : 'Your vault is empty';
      emptyState.querySelector('p').textContent = filterText
        ? 'Try a different search term.'
        : 'Add your first credential using the form.';
      return;
    }

    emptyState.style.display = 'none';
    const tpl = $('password-card-template');

    filtered.forEach(entry => {
      const clone = tpl.content.cloneNode(true);
      const card  = clone.querySelector('.password-card');
      card.dataset.id = entry.id;
      card.querySelector('.card-website').textContent  = entry.website;
      card.querySelector('.card-username').textContent  = entry.username;
      card.querySelector('.card-password').textContent  = '••••••••';

      card.querySelector('.action-show').addEventListener('click',   () => toggleShow(entry.id, card));
      card.querySelector('.action-copy').addEventListener('click',   () => copyPw(entry.id));
      card.querySelector('.action-edit').addEventListener('click',   () => startEdit(entry.id, card));
      card.querySelector('.action-delete').addEventListener('click', () => deleteEntry(entry.id));

      passwordsList.appendChild(card);
      lucide.createIcons({ nodes: [card] });
    });
  }

  // =============================================
  // CRUD  (encrypted before every write)
  // =============================================

  /* ---- CREATE ---- */
  async function addEntry(website, username, password) {
    if (!passwordsRef) return;
    try {
      const blob = await encryptEntry({ website, username, password });
      await passwordsRef.push().set({ ...blob, createdAt: Date.now() });
      showToast('Saved to vault ✓');
    } catch (err) {
      console.warn('Save failed:', err && err.code);
      showToast('Could not save. Check your connection.');
    }
  }

  /* ---- DELETE ---- */
  function deleteEntry(id) {
    if (!passwordsRef || !confirm('Delete this password?')) return;
    passwordsRef.child(id).remove()
      .then(() => showToast('Deleted ✓'))
      .catch(err => {
        console.warn('Delete failed:', err && err.code);
        showToast('Could not delete. Check your connection.');
      });
  }

  /* ---- EDIT (inline) ---- */
  function startEdit(id, card) {
    const entry = passwords.find(p => p.id === id);
    if (!entry) return;
    editingId = id;
    card.classList.add('editing');

    const info = card.querySelector('.card-info');
    const pw   = card.querySelector('.card-password-row');
    const acts = card.querySelector('.card-actions');

    info.innerHTML = `
      <input type="text" class="edit-website" value="${esc(entry.website)}" />
      <input type="text" class="edit-username" value="${esc(entry.username)}" />`;
    pw.innerHTML = `<input type="text" class="edit-password" value="${esc(entry.password)}" />`;
    acts.innerHTML = `
      <div class="edit-actions">
        <button class="icon-btn confirm" aria-label="Save changes" title="Save changes">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
            stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
        </button>
        <button class="icon-btn cancel" aria-label="Cancel" title="Cancel">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
            stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>`;

    acts.querySelector('.confirm').addEventListener('click', () => confirmEdit(id));
    acts.querySelector('.cancel').addEventListener('click', () => { editingId = null; render(searchInput.value); });
    info.querySelector('.edit-website').focus();
  }

  async function confirmEdit(id) {
    const card = passwordsList.querySelector(`.password-card[data-id="${CSS.escape(id)}"]`);
    if (!card || !passwordsRef) return;
    const w = card.querySelector('.edit-website').value.trim();
    const u = card.querySelector('.edit-username').value.trim();
    const p = card.querySelector('.edit-password').value.trim();
    if (!w || !u || !p) { showToast('All fields required'); return; }

    try {
      const existing = passwords.find(x => x.id === id);
      const blob = await encryptEntry({ website: w, username: u, password: p });
      await passwordsRef.child(id).set({ ...blob, createdAt: existing ? existing.createdAt : Date.now() });
      editingId = null;
      showToast('Updated ✓');
    } catch (err) {
      console.warn('Update failed:', err && err.code);
      showToast('Could not update. Check your connection.');
    }
  }

  // =============================================
  // SHOW / HIDE
  // =============================================
  function toggleShow(id, card) {
    const entry = passwords.find(p => p.id === id);
    if (!entry) return;
    const span = card.querySelector('.card-password');
    const btn  = card.querySelector('.action-show');
    if (span.classList.contains('masked')) {
      span.textContent = entry.password;
      span.classList.replace('masked', 'revealed');
      btn.title = 'Hide Password';
    } else {
      span.textContent = '••••••••';
      span.classList.replace('revealed', 'masked');
      btn.title = 'Show Password';
    }
  }

  // =============================================
  // COPY  (auto-clears the clipboard)
  // =============================================
  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = Object.assign(document.createElement('textarea'), { value: text });
      ta.style.cssText = 'position:fixed;left:-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(() => {
      navigator.clipboard.writeText('').catch(() => {});
    }, CLIPBOARD_CLEAR);
  }

  async function copyPw(id) {
    const entry = passwords.find(p => p.id === id);
    if (!entry) return;
    await copyText(entry.password);
    showToast('Copied · clears in 30s');
  }

  // =============================================
  // SEARCH
  // =============================================
  searchInput.addEventListener('input', () => render(searchInput.value));

  // =============================================
  // BOTTOM NAV
  // =============================================
  if (navVault) {
    navVault.addEventListener('click', () => {
      document.querySelector('.passwords-section')
        .scrollIntoView({ behavior: 'smooth' });
    });
  }

  // =============================================
  // FORM — eye toggle
  // =============================================
  toggleFormPw.addEventListener('click', () => {
    const hide = passwordInput.type === 'password';
    passwordInput.type = hide ? 'text' : 'password';
    toggleFormPw.querySelector('.eye-open').style.display  = hide ? 'none' : '';
    toggleFormPw.querySelector('.eye-closed').style.display = hide ? '' : 'none';
  });

  // =============================================
  // STRENGTH METER
  // =============================================
  passwordInput.addEventListener('input', () => {
    const v = passwordInput.value;
    let s = 0;
    if (v.length >= 6)            s++;
    if (v.length >= 10)           s++;
    if (/[A-Z]/.test(v))          s++;
    if (/[0-9]/.test(v))          s++;
    if (/[^A-Za-z0-9]/.test(v))   s++;
    const colors = ['#ff5c72','#ff5c72','#ffc044','#ffc044','#3cdf8e','#3cdf8e'];
    const labels = ['','Weak','Weak','Fair','Good','Strong'];
    strengthFill.style.width      = (s / 5 * 100) + '%';
    strengthFill.style.background = colors[s];
    strengthText.textContent      = labels[s] || 'Password strength';
    strengthText.style.color      = colors[s] || '';
  });

  // =============================================
  // FORM SUBMIT
  // =============================================
  form.addEventListener('submit', e => {
    e.preventDefault();
    const w = websiteInput.value.trim();
    const u = usernameInput.value.trim();
    const p = passwordInput.value.trim();
    if (!w || !u || !p) { showToast('Please fill all fields'); return; }
    addEntry(w, u, p);
    form.reset();
    strengthFill.style.width = '0%';
    strengthText.textContent = 'Password strength';
    strengthText.style.color = '';
    websiteInput.focus();
  });

  // Ripple
  saveBtn.addEventListener('click', function (e) {
    const r = this.getBoundingClientRect();
    this.style.setProperty('--ripple-x', ((e.clientX - r.left) / r.width * 100) + '%');
    this.style.setProperty('--ripple-y', ((e.clientY - r.top) / r.height * 100) + '%');
    this.classList.remove('ripple');
    void this.offsetWidth;
    this.classList.add('ripple');
  });

  // =============================================
  // PASSWORD GENERATOR
  // =============================================
  navGenerate.addEventListener('click', openGen);
  closeGenerator.addEventListener('click', closeGen);
  generatorModal.addEventListener('click', e => { if (e.target === generatorModal) closeGen(); });

  function openGen() {
    generatorModal.classList.add('open');
    generatorModal.setAttribute('aria-hidden', 'false');
    genPassword();
  }
  function closeGen() {
    generatorModal.classList.remove('open');
    generatorModal.setAttribute('aria-hidden', 'true');
  }

  pwLengthSlider.addEventListener('input', () => {
    pwLengthVal.textContent = pwLengthSlider.value;
  });
  generatePwBtn.addEventListener('click', genPassword);

  // Unbiased random pick (rejection sampling) instead of `v % chars.length`
  function randomIndex(max) {
    const limit = Math.floor(0x100000000 / max) * max;
    const buf = new Uint32Array(1);
    do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
    return buf[0] % max;
  }

  function genPassword() {
    const len = parseInt(pwLengthSlider.value, 10);
    let chars = '';
    if ($('pw-upper').checked)   chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if ($('pw-lower').checked)   chars += 'abcdefghijklmnopqrstuvwxyz';
    if ($('pw-digits').checked)  chars += '0123456789';
    if ($('pw-symbols').checked) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';
    let out = '';
    for (let i = 0; i < len; i++) out += chars[randomIndex(chars.length)];
    generatedPw.textContent = out;
  }

  copyGenerated.addEventListener('click', async () => {
    await copyText(generatedPw.textContent);
    showToast('Copied · clears in 30s');
  });

  usePwBtn.addEventListener('click', () => {
    passwordInput.value = generatedPw.textContent;
    passwordInput.dispatchEvent(new Event('input'));
    closeGen();
    showToast('Password applied');
  });

  // =============================================
  // TOAST
  // =============================================
  let toastTimer;
  function showToast(msg) {
    clearTimeout(toastTimer);
    toastEl.textContent = msg;
    toastEl.classList.add('show');
    toastTimer = setTimeout(() => toastEl.classList.remove('show'), 2200);
  }

  // =============================================
  // HELPERS
  // =============================================
  // Escapes text for use inside an HTML attribute value (quotes included)
  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  setMode(false);
  setStatus('offline', 'Locked');
});
