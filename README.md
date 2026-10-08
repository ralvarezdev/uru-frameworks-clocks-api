# uru-frameworks-clocks-api

**Note:** This repository is archived and read-only. Despite the name, the code only implements authentication; there are no clock-related endpoints.

Clocks API project from the Frameworks college course (URU): an Express.js service (`index.js`) with authentication endpoints backed by Firebase Authentication (email/password and Google sign-in). It uses Express 4, `helmet`, `cookie-parser`, and `@ralvarezdev` helpers for Joi validation, Express responses and mode handling.

## Endpoints

All are `POST`, accept JSON and reply with JSend-style bodies.

- **`/api/sign-up`** — create a user with email and password
- **`/api/sign-in`** — sign in with email and password
- **`/api/sign-in/google`** — sign in with Google (popup provider)
- **`/api/sign-out`** — sign out and clear the access-token cookie

On sign-in, the user ID is stored in an `httpOnly` cookie (`secure` in production).

## Configuration

Create a `.env` with `URU_FRAMEWORKS_CLOCKS_API_PORT`, `..._COOKIE_ACCESS_TOKEN_NAME`, `..._COOKIE_ACCESS_TOKEN_MAX_AGE` (seconds), and the Firebase settings `..._FIREBASE_API_KEY`, `_AUTH_DOMAIN`, `_PROJECT_ID`, `_STORAGE_BUCKET`, `_MESSAGING_SENDER_ID`, `_APP_ID`, `_MEASUREMENT_ID` (all prefixed `URU_FRAMEWORKS_CLOCKS_API_`).

## Running

```bash
npm install
npm run dev     # also: npm run debug, npm run prod
```

No tests are defined.

## License

GNU General Public License v3.0 (see `LICENSE`). `package.json` declares `ISC`, which disagrees with it.
