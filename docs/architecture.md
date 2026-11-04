# SecureAuth architecture

```mermaid
flowchart LR
    Browser[Browser: HTML, CSS, JS] -->|HTTPS in deployment; CSRF form token| Flask[Flask application]
    Flask --> Auth[Registration and login routes]
    Flask --> Pages[Authenticated pages]
    Flask --> RBAC[Database-backed role authorization]
    Flask --> CSRF[Flask-WTF CSRF middleware]
    Auth --> Validation[Input and password policy]
    Auth --> Hashing[Werkzeug PBKDF2-SHA256]
    Auth --> Lockout[Five failures / five-minute lock]
    Auth --> SQL[Parameterized SQL]
    Pages --> SQL
    SQL --> SQLite[(SQLite users and login_events)]
    Lab[Development-only security lab] --> TempDB[(Disposable test SQLite)]
    Lab --> TestClient[Isolated Flask test client]
    TestClient --> Flask
```

## Components

- `secureauth/__init__.py` constructs the Flask application, configures cookies and idle expiry, registers blueprints, and exposes the administrator promotion CLI command.
- `secureauth/auth.py` validates registrations, verifies password hashes, tracks lockout state and login events, and creates/clears session state.
- `secureauth/db.py` owns the schema and request-scoped SQLite connection.
- `secureauth/pages.py` implements authenticated views and role checks. Roles are loaded from SQLite, not accepted from request data or the session.
- `secureauth/testing_center.py` creates a separate app and temporary database per run; it uses only a synthetic test account.
- Templates use a shared responsive layout. JavaScript reveals passwords and estimates composition strength in the browser; authoritative validation remains server-side.

## Database

`users` stores a password hash, constrained role, failed-attempt count, lock expiry, creation time, and last successful login. Case-insensitive unique indexes prevent duplicate usernames and emails. `login_events` stores a user reference where known, the attempted identity, success flag, and UTC timestamp. It has no password field.
