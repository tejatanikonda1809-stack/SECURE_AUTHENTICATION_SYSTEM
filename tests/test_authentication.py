from werkzeug.security import check_password_hash

from secureauth.db import get_db
from tests.conftest import PASSWORD, csrf_token, login, register


def test_registration_creates_account_with_pbkdf2_hash(app, client):
    response = register(client)
    assert response.status_code == 302
    with app.app_context():
        user = get_db().execute("SELECT * FROM users WHERE username = ?", ("new_user",)).fetchone()
    assert user is not None
    assert user["password_hash"] != PASSWORD
    assert user["password_hash"].startswith("pbkdf2:sha256:")
    assert check_password_hash(user["password_hash"], PASSWORD)


def test_duplicate_registration_is_rejected(client):
    response = register(client, email="TEST@example.invalid")
    assert response.status_code == 200
    assert b"already registered" in response.data


def test_invalid_registration_is_rejected(client):
    response = register(
        client,
        email="invalid",
        username="no",
        password="weak",
        confirm_password="weak",
    )
    assert response.status_code == 200
    assert b"valid email" in response.data


def test_login_success_resets_attempts_and_sets_session(app, client):
    with app.app_context():
        get_db().execute("UPDATE users SET failed_attempts = 2 WHERE username = 'test_user'")
        get_db().commit()
    response = login(client, remember="on")
    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]
    with app.app_context():
        user = get_db().execute("SELECT failed_attempts, locked_until, last_login FROM users WHERE username = 'test_user'").fetchone()
    assert user["failed_attempts"] == 0
    assert user["locked_until"] is None
    assert user["last_login"] is not None
    assert client.get("/dashboard").status_code == 200


def test_invalid_password_fails_and_fifth_attempt_locks_account(app, client):
    for _ in range(4):
        response = login(client, password="WrongPassword!123")
        assert response.status_code == 200
        assert b"Invalid username/email or password" in response.data
    response = login(client, password="WrongPassword!123")
    assert response.status_code == 200
    assert b"temporarily locked" in response.data
    with app.app_context():
        user = get_db().execute("SELECT failed_attempts, locked_until FROM users WHERE username = 'test_user'").fetchone()
    assert user["failed_attempts"] == 5
    assert user["locked_until"] is not None
    response = login(client, password=PASSWORD)
    assert b"temporarily locked" in response.data


def test_sql_injection_identity_cannot_bypass_authentication(client):
    response = login(client, identity="' OR 1=1 --", password="anything")
    assert response.status_code == 200
    assert b"Invalid username/email or password" in response.data
    assert client.get("/dashboard").status_code == 302


def test_login_event_logs_identity_but_not_password(app, client):
    login(client, password="NeverLogThis!Password")
    with app.app_context():
        events = get_db().execute("SELECT attempted_identity FROM login_events").fetchall()
    assert events
    assert all("NeverLogThis!Password" not in event["attempted_identity"] for event in events)


def test_csrf_rejects_missing_and_invalid_tokens(client):
    missing = client.post("/login", data={"identity": "test_user", "password": PASSWORD})
    invalid = client.post("/login", data={"csrf_token": "forged", "identity": "test_user"})
    assert missing.status_code == 400
    assert invalid.status_code == 400


def test_logout_clears_session(client):
    login(client)
    assert client.get("/dashboard").status_code == 200
    token = csrf_token(client, "/dashboard")
    response = client.post("/logout", data={"csrf_token": token})
    assert response.status_code == 302
    assert client.get("/dashboard").status_code == 302


def test_password_checker_does_not_store_or_log_candidate(app, client):
    login(client)
    candidate = "PrivateChecker!Pass456"
    response = client.post(
        "/password-checker",
        data={"csrf_token": csrf_token(client, "/password-checker"), "password": candidate},
    )
    assert response.status_code == 200
    with app.app_context():
        user_values = get_db().execute("SELECT password_hash FROM users").fetchall()
        events = get_db().execute("SELECT attempted_identity FROM login_events").fetchall()
    assert all(candidate not in user["password_hash"] for user in user_values)
    assert all(candidate not in event["attempted_identity"] for event in events)


def test_password_change_requires_current_password_and_clears_session(client):
    login(client)
    response = client.post(
        "/settings",
        data={
            "csrf_token": csrf_token(client, "/settings"),
            "current_password": PASSWORD,
            "new_password": "Replacement!Password456",
            "confirm_password": "Replacement!Password456",
        },
    )
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    assert client.get("/dashboard").status_code == 302
    assert login(client, password=PASSWORD).status_code == 200
    assert login(client, password="Replacement!Password456").status_code == 302


def test_normal_user_cannot_access_admin_and_client_cannot_set_role(app, client):
    login(client)
    assert client.get("/admin").status_code == 403
    with client.session_transaction() as browser_session:
        browser_session["role"] = "admin"
    assert client.get("/admin").status_code == 403


def test_session_cookie_settings_and_idle_expiration(app, client):
    login(client)
    cookie = client.get_cookie(app.config["SESSION_COOKIE_NAME"])
    assert cookie.http_only is True
    assert cookie.same_site.lower() == "lax"
    assert cookie.secure is False
    with client.session_transaction() as browser_session:
        browser_session["last_activity"] = 1
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "expired=1" in response.headers["Location"]
