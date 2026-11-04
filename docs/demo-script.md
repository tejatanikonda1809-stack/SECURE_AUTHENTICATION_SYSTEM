# Five-minute SecureAuth demonstration

## 0:00–0:35 — Project overview

Introduce SecureAuth as a local Flask/SQLite authentication assignment. Show the architecture diagram and point out that security checks use a disposable test database, not the demonstration user's database.

## 0:35–1:20 — Registration

Open the registration page, enter a made-up name, email and username, and demonstrate the client-side strength meter. Submit a policy-compliant test password. Explain that server validation is authoritative and only a PBKDF2-SHA256 hash is stored.

## 1:20–2:05 — Login and dashboard

Sign in with the synthetic demonstration account. Show the protected dashboard, account metadata, role, last-login field, and security status. Explain that login queries use bound SQL parameters and that session state is replaced after authentication.

## 2:05–2:55 — Password tools and settings

Run the password checker with a newly invented sample value; note that the value is not saved or logged. Show account settings and explain current-password verification, password policy, and session invalidation on password change. Do not change the demonstration credential unless prepared to sign in again.

## 2:55–4:20 — Controlled security tests

Open the Security Testing Center in the development environment and run the test suite. Explain that the temporary database contains a dedicated synthetic test account and is removed after execution. Review the actual PASS/FAIL outcomes for SQL injection resistance, lockout, hashing, CSRF, access control, and session behavior. Do not claim a check passed if the displayed result is FAIL.

## 4:20–5:00 — Wrap-up

Show the pytest command and report. Summarize the controls and limitations: no MFA, email verification, recovery workflow, or production server configuration is included. Mention that production requires a managed secret, HTTPS, and a production WSGI server.
