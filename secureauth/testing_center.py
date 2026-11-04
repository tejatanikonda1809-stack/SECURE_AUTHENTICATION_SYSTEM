import os
import re
import tempfile
import time

from flask import Blueprint, abort, current_app, flash, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash

from .auth import LOCKOUT_LIMIT
from .db import get_db, init_db
from .pages import login_required

bp = Blueprint("testing_center", __name__)


def run_security_checks():
    results = []
    with tempfile.TemporaryDirectory(prefix="secureauth-tests-") as directory:
        path = os.path.join(directory, "security-test.sqlite")
        from . import create_app

        isolated = create_app(
            {
                "TESTING": True,
                "ENVIRONMENT": "testing",
                "SECURITY_TESTING_ENABLED": True,
                "SECRET_KEY": "isolated-security-test-key",
                "DATABASE": path,
                "WTF_CSRF_ENABLED": True,
                "SESSION_COOKIE_SECURE": False,
            }
        )
        with isolated.app_context():
            init_db()
            db = get_db()
            test_hash = generate_password_hash("TestingStrong!Pass123", method=isolated.config["PASSWORD_HASH_METHOD"])
            db.execute(
                "INSERT INTO users (full_name, email, username, password_hash) VALUES (?, ?, ?, ?)",
                ("Security Test User", "security-test@example.invalid", "security_test", test_hash),
            )
            db.commit()
            user_id = db.execute("SELECT id FROM users WHERE username = ?", ("security_test",)).fetchone()["id"]

        client = isolated.test_client()

        def result(name, description, expected, actual_ok, explanation):
            results.append(
                {
                    "name": name,
                    "description": description,
                    "expected": expected,
                    "actual": "Observed the expected secure behavior." if actual_ok else "Observed behavior did not match expectation.",
                    "status": "PASS" if actual_ok else "FAIL",
                    "explanation": explanation,
                }
            )

        response = client.post(
            "/login",
            data={
                "csrf_token": _csrf_token(client, "/login"),
                "identity": "' OR 1=1 --",
                "password": "anything",
            },
            follow_redirects=False,
        )
        with isolated.app_context():
            no_bypass = get_db().execute(
                "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE",
                ("' OR 1=1 --", "' OR 1=1 --"),
            ).fetchone() is None
        result(
            "SQL injection authentication bypass",
            "Submit a classic SQL-shaped identity to the isolated login endpoint.",
            "Authentication is not granted and parameterized lookup treats the input as data.",
            response.status_code == 200 and no_bypass,
            "Bound SQL parameters prevent submitted text from changing query structure.",
        )

        for _ in range(LOCKOUT_LIMIT):
            token = _csrf_token(client, "/login")
            client.post(
                "/login",
                data={"csrf_token": token, "identity": "security_test", "password": "incorrect"},
            )
        with isolated.app_context():
            locked_user = get_db().execute("SELECT failed_attempts, locked_until FROM users WHERE id = ?", (user_id,)).fetchone()
            lockout_ok = locked_user["failed_attempts"] >= LOCKOUT_LIMIT and locked_user["locked_until"] > int(time.time())
        result(
            "Repeated incorrect password attempts",
            "Submit five incorrect passwords for the dedicated test account.",
            "The account is locked for five minutes after the fifth consecutive failure.",
            lockout_ok,
            "A persisted attempt counter and lockout timestamp throttle repeated account guesses.",
        )
        with isolated.app_context():
            get_db().execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user_id,),
            )
            get_db().commit()

        with isolated.app_context():
            stored_hash = get_db().execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()["password_hash"]
        result(
            "Password storage verification",
            "Inspect only the dedicated test account's database password field.",
            "The stored value is a PBKDF2-SHA256 hash and does not equal the test password.",
            stored_hash != "TestingStrong!Pass123" and stored_hash.startswith("pbkdf2:sha256:"),
            "Werkzeug PBKDF2 hashing stores a salted verifier, never the submitted password.",
        )

        anonymous = isolated.test_client()
        response = anonymous.get("/dashboard", follow_redirects=False)
        result(
            "Unauthorized dashboard access",
            "Request the protected dashboard without an authenticated session.",
            "The request redirects to the login page.",
            response.status_code == 302 and "/login" in response.headers.get("Location", ""),
            "Authentication is enforced by a server-side route decorator.",
        )

        token = _csrf_token(anonymous, "/register")
        response = anonymous.post(
            "/register",
            data={
                "csrf_token": token,
                "full_name": "Invalid",
                "email": "not-an-email",
                "username": "bad",
                "password": "weak",
                "confirm_password": "weak",
            },
        )
        with isolated.app_context():
            invalid_not_saved = get_db().execute("SELECT 1 FROM users WHERE email = 'not-an-email'").fetchone() is None
        result(
            "Invalid registration input",
            "Submit malformed email and out-of-policy username/password values.",
            "No account is created from malformed registration data.",
            response.status_code == 200 and invalid_not_saved,
            "Server-side validation rejects malformed inputs before any insert.",
        )

        response = anonymous.post("/login", data={"identity": "security_test", "password": "x"})
        result(
            "Missing CSRF token",
            "POST to login without a CSRF token.",
            "Flask-WTF rejects the request with HTTP 400.",
            response.status_code == 400,
            "CSRF middleware validates every state-changing form submission.",
        )
        response = anonymous.post("/login", data={"csrf_token": "invalid", "identity": "security_test"})
        result(
            "Invalid CSRF token",
            "POST to login with a forged token.",
            "Flask-WTF rejects the request with HTTP 400.",
            response.status_code == 400,
            "A token must be signed for this application session; arbitrary values are rejected.",
        )

        token = _csrf_token(anonymous, "/login")
        response = anonymous.post(
            "/login",
            data={"csrf_token": token, "identity": "security_test", "password": "TestingStrong!Pass123"},
        )
        logged_in = response.status_code == 302
        cookie = anonymous.get_cookie(isolated.config["SESSION_COOKIE_NAME"])
        token = _csrf_token(anonymous, "/dashboard")
        logout_response = anonymous.post("/logout", data={"csrf_token": token}, follow_redirects=False)
        dashboard_response = anonymous.get("/dashboard", follow_redirects=False)
        result(
            "Session logout and cookie security",
            "Authenticate, sign out, then request the dashboard again.",
            "Logout clears authentication; the session cookie is HttpOnly and SameSite=Lax.",
            logged_in
            and logout_response.status_code == 302
            and dashboard_response.status_code == 302
            and cookie is not None
            and cookie.http_only
            and cookie.same_site.lower() == "lax",
            "Authentication state is cleared on logout and browser cookie protections are enabled.",
        )

        token = _csrf_token(anonymous, "/login")
        anonymous.post(
            "/login",
            data={"csrf_token": token, "identity": "security_test", "password": "TestingStrong!Pass123"},
        )
        with anonymous.session_transaction() as browser_session:
            browser_session["last_activity"] = int(time.time()) - isolated.config["SESSION_IDLE_TIMEOUT"] - 1
        expired = anonymous.get("/dashboard", follow_redirects=False)
        result(
            "Session idle expiration",
            "Age the dedicated test session beyond the configured idle timeout.",
            "The application expires the session and redirects to sign-in.",
            expired.status_code == 302 and "expired=1" in expired.headers.get("Location", ""),
            "The server checks last activity and clears stale authentication state.",
        )

        normal_client = isolated.test_client()
        token = _csrf_token(normal_client, "/login")
        normal_client.post(
            "/login",
            data={"csrf_token": token, "identity": "security_test", "password": "TestingStrong!Pass123"},
        )
        admin_response = normal_client.get("/admin")
        result(
            "Normal-user role restriction",
            "Sign in as the dedicated normal user and request the administrator page.",
            "The server denies access with HTTP 403.",
            admin_response.status_code == 403,
            "The role is read from the database, not accepted from browser-controlled session or form data.",
        )
    return results


def _csrf_token(client, path):
    response = client.get(path)
    if response.status_code != 200:
        raise RuntimeError(f"Unable to obtain a test CSRF token from {path}: HTTP {response.status_code}")
    match = re.search(rb'<input type="hidden" name="csrf_token" value="([^"]+)"', response.data)
    if match is None:
        raise RuntimeError(f"No CSRF token was rendered by {path}.")
    return match.group(1).decode("ascii")


@bp.route("/security-center", methods=("GET", "POST"))
@login_required
def security_center():
    if not current_app.config["SECURITY_TESTING_ENABLED"] or current_app.config["ENVIRONMENT"] not in {"development", "testing"}:
        abort(404)
    results = None
    if request.method == "POST":
        results = run_security_checks()
        passed = sum(test["status"] == "PASS" for test in results)
        flash(f"Security checks complete: {passed}/{len(results)} passed in an isolated temporary database.", "success" if passed == len(results) else "error")
    return render_template("pages/security_center.html", results=results)
