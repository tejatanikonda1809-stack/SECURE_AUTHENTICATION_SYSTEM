# Test cases and expected results

Run the automated suite with `python -m pytest -q`. Every pytest database is temporary and isolated.

| Test | Expected outcome |
|---|---|
| Register a valid account | Redirects to sign-in; database contains PBKDF2 hash, not submitted password. |
| Register duplicate email | Rejected with a generic duplicate message. |
| Register malformed identity/password | Rejected; no row is created. |
| Sign in with valid credentials | Redirects to dashboard; failures reset; last login is updated. |
| Sign in with invalid credentials | Generic invalid-credentials message. |
| Five consecutive incorrect passwords | Account is locked for five minutes; correct password is rejected during lock. |
| SQL-shaped identity | No authentication bypass; value is handled as data. |
| Missing or forged CSRF token | HTTP 400 from Flask-WTF. |
| Request dashboard without a session | Redirect to sign-in. |
| Sign out | Session is cleared; dashboard request redirects. |
| Change password | Current password required; new password works; old session is cleared. |
| Normal user requests admin route | HTTP 403, including after adding a client-controlled `role=admin` session field. |
| Password checker | Provides a strength result; candidate is absent from stored hashes and login event data. |
| Session timeout/cookie | Stale session redirects to sign-in; cookie is HttpOnly and SameSite=Lax. |
| Development security lab | Runs against a temporary isolated database; results show each check and actual PASS/FAIL. |

The security lab is exposed only when `ENVIRONMENT` is `development` or `testing` and the feature is enabled. Its route additionally requires an authenticated user. The app deliberately does not render example credentials or seed a real admin account.
