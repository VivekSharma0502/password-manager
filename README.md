# Password Manager

Zero-knowledge password manager. Entries are encrypted in the browser
(AES-GCM, key derived with PBKDF2) before syncing to Firebase.

- Firebase Auth + per-user Realtime Database rules
- Client-side encryption, auto-lock, clipboard auto-clear
- Deployed on Vercel

Live: https://password-manager-beta-one.vercel.app/