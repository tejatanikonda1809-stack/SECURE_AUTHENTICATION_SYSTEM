# SecureAuth

SecureAuth is a local-first Flask authentication application for a secure-computing assignment. It uses SQLite, Werkzeug PBKDF2-SHA256 password hashes, Flask-WTF CSRF protection, server-side authorization checks, and an isolated development security lab.

## Requirements

- Python 3.10 or newer
- Windows PowerShell (commands below use Windows paths)

## Install and run

From the project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
$env:APP_ENV = "development"
python run.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). The first run creates `instance\secureauth.sqlite`. Keep `SECRET_KEY` private; generate a new value for local use and set a stable secret through your deployment's secret manager in production. To run behind HTTPS, set `$env:HTTPS_ONLY = "true"` so the session cookie receives the Secure attribute. Flask debug mode is off by default; opt in for local debugging with `$env:FLASK_DEBUG = "true"`.

For production, set `APP_ENV=production`, configure a strong stable `SECRET_KEY`, run behind HTTPS, and use a production WSGI server rather than Flask's development server. The security testing center is not available in production.

## Tests

```powershell
python -m pytest -q
```

Tests create disposable SQLite databases under pytest's temporary directory. They do not use the application database or real accounts.

## Features

- Registration with normalized email, username constraints, password policy, and duplicate prevention.
- Username/email sign-in, optional browser-session persistence, five-failure/five-minute account lockout, and login event history without password values.
- Authenticated dashboard, password strength checker, account settings, password update, and POST-only logout.
- PBKDF2-SHA256 password storage; parameterized SQL; CSRF tokens for all state-changing forms.
- HttpOnly, SameSite=Lax cookies; Secure cookies when HTTPS is enabled; 30-minute idle and permanent-session expiration.
- Database-backed role checks and an administrator-only directory. Promote an existing account with `flask --app run create-admin`; the command prompts for its current password.
- Development/testing security lab using a dedicated synthetic test account and a temporary isolated database. Each run deletes its database afterward.

## Structure

```text
secureauth/
  __init__.py             Flask factory, session policy, CLI command
  auth.py                 Registration, login, lockout, logout
  db.py                   SQLite schema and connection lifecycle
  pages.py                Protected pages and role authorization
  security.py             Input and password policy
  testing_center.py       Isolated security-check runner
  static/css/style.css    Responsive dark interface
  static/js/app.js        Password reveal and strength meter
  templates/              Jinja pages and shared layout
tests/
  conftest.py
  test_baseline_simulation.py
  test_authentication.py
  test_security_center.py
docs/
  architecture.md
  flowcharts.md
  security-report.md
  test-cases.md
  screenshot-checklist.md
  demo-script.md
```

## Documentation

- [Architecture](docs/architecture.md)
- [Registration and login flows](docs/flowcharts.md)
- [Security mechanisms and before/after comparison](docs/security-report.md)
- [Test cases and expected outcomes](docs/test-cases.md)
- [Screenshot checklist](docs/screenshot-checklist.md)
- [Five-minute demo script](docs/demo-script.md)

## Limitations

This is an academic/local application, not a fully managed identity service. It does not provide email verification, password reset, MFA, breached-password screening, distributed rate limiting, or account lockout notifications. Use HTTPS and a production-grade WSGI server when deploying beyond localhost.
