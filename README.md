# L33t Store

L33t Store is a deliberately small Express/EJS e-commerce teaching app with two route groups:

- `/vulnerable` demonstrates common web security mistakes.
- `/secure` fixes the same flows with clear code comments.

Demo users:

- `wiener:peter`
- `carlos:montoya`

## Run

```bash
npm install
npm start
```

Then open `http://localhost:3000`.

## Included Lessons

- Client-side price trust
- Negative quantity cart logic
- Username enumeration by different responses
- Subtle username enumeration response
- Timing username enumeration
- Broken brute-force protection
- Account lock enumeration
- 2FA simple bypass
- 2FA broken logic using a `verify` parameter
- Weak stay-logged-in cookie using `base64(username:md5(password))`
- CSRF with no defenses
- CSRF where token validation only applies to POST but not GET

The SQLite database is created automatically at `l33t-store.sqlite` on first run.
