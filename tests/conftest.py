import re

import pytest
from werkzeug.security import generate_password_hash

from secureauth import create_app
from secureauth.db import get_db, init_db


PASSWORD = "SecureTest!Password123"


@pytest.fixture
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "ENVIRONMENT": "testing",
            "SECURITY_TESTING_ENABLED": True,
            "SECRET_KEY": "pytest-only-secret-key",
            "DATABASE": str(tmp_path / "test.sqlite"),
            "WTF_CSRF_ENABLED": True,
            "SESSION_COOKIE_SECURE": False,
        }
    )
    with application.app_context():
        init_db()
        get_db().execute(
            "INSERT INTO users (full_name, email, username, password_hash) VALUES (?, ?, ?, ?)",
            (
                "Test User",
                "test@example.invalid",
                "test_user",
                generate_password_hash(PASSWORD, method=application.config["PASSWORD_HASH_METHOD"]),
            ),
        )
        get_db().commit()
    yield application


@pytest.fixture
def client(app):
    return app.test_client()


def csrf_token(client, path):
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(rb'<input type="hidden" name="csrf_token" value="([^"]+)"', response.data)
    assert match is not None, f"No CSRF token found on {path}"
    return match.group(1).decode("ascii")


def register(client, **overrides):
    data = {
        "full_name": "New User",
        "email": "new@example.invalid",
        "username": "new_user",
        "password": PASSWORD,
        "confirm_password": PASSWORD,
    }
    data.update(overrides)
    data["csrf_token"] = csrf_token(client, "/register")
    return client.post("/register", data=data, follow_redirects=False)


def login(client, identity="test_user", password=PASSWORD, **extra):
    data = {"identity": identity, "password": password, "csrf_token": csrf_token(client, "/login")}
    data.update(extra)
    return client.post("/login", data=data, follow_redirects=False)
