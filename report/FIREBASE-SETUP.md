# Firebase setup (5 minutes)

The site already has the counter + analytics code wired in. It activates the moment you paste your Firebase config into `report/firebase-config.js`.

## 1. Create a Firebase project
1. Go to https://console.firebase.google.com → **Add project** (sign in with your Google account).
2. Name it (e.g. `artex-bank-security`). Enable **Google Analytics** when prompted (needed for the engagement report).

## 2. Register a web app
1. In the project → **Project settings** (gear) → **General** → scroll to **Your apps** → click the **web** icon (`</>`).
2. Give it a nickname, register. Firebase shows a `firebaseConfig = { ... }` block.
3. Copy those values into `report/firebase-config.js` (replace every `PASTE_...`). The `apiKey` is a public client key — safe to commit.

## 3. Turn on Firestore (for the visit counter)
1. Build → **Firestore Database** → **Create database** → start in production mode.
2. Go to the **Rules** tab and paste this (lets anyone read the count and increment it, nothing else):

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /stats/visits {
      allow read: if true;
      allow write: if true;
    }
    match /{document=**} { allow read, write: if false; }
  }
}
```

Publish. (For a hardened counter later, move the increment into a Cloud Function and set `write: if false` here.)

## 4. Done
Push the edited `firebase-config.js`. On next load:
- The **"Site visits"** badge (bottom-left) shows the live total from Firestore.
- **Analytics** → Firebase/Google Analytics dashboard shows active users, **average engagement time**, new vs returning, country, device, and the pages visited — all anonymous.

## What you get vs what you don't
- **Yes (anonymous):** visit counts, time spent, user segments (device/browser/country), traffic sources.
- **No:** visitor names or identities. That is not exposed on the web, and Analytics is anonymous by design. The only way to see a named person is if they **log in** to your site themselves (Firebase Authentication) — and then you only see those who chose to sign in and consent. Ask if you want an optional "Sign in with Google" added for that.
