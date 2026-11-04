# SecureAuth security report

## Scope and evidence

The starting project directory contained no application files. There was therefore no existing login implementation or historical insecure version to inspect. This report describes the implemented controls and the checks that can be run on demand. A run's actual results appear in the development-only Security Testing Center and in pytest output; this document does not pre-claim test outcomes.

The security lab creates a separate Flask application and a disposable SQLite database in a temporary directory, inserts one synthetic test account, and runs its checks using an isolated Flask test client. It never uses the application's user database or contacts external targets. The temporary directory is removed after the run. Pytest uses separate temporary database files. A separate test-only baseline simulation uses its own pytest temporary SQLite file to demonstrate the consequences of string-concatenated authentication and plaintext password storage; that simulator is not imported by or exposed through the application.

Handover verification on 2026-11-04: the complete pytest suite reported **17 passed**, including the two baseline behaviors in an isolated temporary database. The browser-run security lab reported **10/10 PASS**. The local browser also exercised registration, sign-in, dashboard, password checking, settings, and sign-out. These results establish current-run behavior; rerun the documented commands to reproduce them.

## Mechanisms implemented

| Mechanism | Implementation |
|---|---|
| Password hashing | Werkzeug `generate_password_hash`/`check_password_hash` with PBKDF2-SHA256 and 600,000 iterations. The database stores only the resulting salted hash. |
| Brute-force protection | Failed attempts are counted for known accounts. Five consecutive failures set a lock expiry five minutes ahead; successful authentication clears the count and expiry. Login events never store passwords. |
| SQL injection prevention | All user-derived SQL values are bound parameters. Usernames/emails are validated and length-capped. |
| Session management | Flask signed sessions; state is cleared on login before setting identity, and on logout/password change. Cookies are HttpOnly and SameSite=Lax; Secure is controlled by HTTPS deployment configuration. Activity is expired after 30 minutes. |
| Input validation | Server checks name length, email shape/length, username pattern/length, password length/composition, and password confirmation. HTML constraints are supplementary only. |
| CSRF | Flask-WTF `CSRFProtect` is initialized globally. State-changing forms include a CSRF token; missing or invalid values are rejected. |
| Role authorization | Administrator routes query the current role from SQLite on each request. The public registration form does not accept a role. `create-admin` verifies the existing account password before promotion. |

## Before-and-after comparison

No insecure production behavior was present in the starting directory, and SecureAuth does not ship a weakened authentication route. Accordingly, the “before” column is a controlled baseline description of the failure mode this implementation is designed to prevent—not a claim that the project previously exhibited that vulnerability.

| Area | Controlled insecure baseline behavior | SecureAuth countermeasure | Evidence to collect |
|---|---|---|---|
| Password storage | Plaintext or fast unsalted password storage would expose credentials after database disclosure. | PBKDF2-SHA256 salted password hash and verifier. | Run “Password storage verification”; inspect only the synthetic lab record. |
| Brute force | Unlimited guesses provide no per-account delay. | Lock the synthetic account for five minutes after five failed attempts. | Run “Repeated incorrect password attempts”; inspect count and future lock timestamp. |
| SQL injection | Concatenating identity input into query text can alter query logic. | Parameterized lookups treat the submitted identity as data. | Run “SQL injection authentication bypass”; confirm no authentication and no matching record. |
| Protected pages | An unauthenticated request may disclose account information. | Server-side authenticated route guard redirects to login. | Run “Unauthorized dashboard access”. |
| Registration validation | Unchecked values can create malformed or policy-violating records. | Server-side format, length, password, and duplicate checks. | Run “Invalid registration input”. |
| CSRF | A state-changing request without a valid form token could be accepted. | Global Flask-WTF verification rejects missing and invalid tokens. | Run the two CSRF checks. |
| Session lifecycle | A stale session may remain usable after inactivity or logout. | Idle timeout and explicit session clearing on logout/password change. | Run logout/cookie and idle-expiration checks. |
| Role authorization | Trusting client-supplied role values can grant admin access. | Current role is read from the database for each admin request. | Run “Normal-user role restriction”; pytest also tampers with a client session field. |

## Limitations and operational notes

- Lockout is per account and can be abused to temporarily deny service to a known user; deployment should pair this with monitoring, recovery, and possibly network-level rate limiting.
- `login_events` retains attempted identities and should be covered by an appropriate retention policy in a real deployment.
- The email check is syntactic, not proof of mailbox ownership.
- Flask's built-in development server is for local use only. Set a high-entropy secret key, HTTPS, `APP_ENV=production`, and a production WSGI server for deployment.
- MFA, password reset, email verification, breached-password checks, and distributed rate limiting are outside this assignment implementation.
