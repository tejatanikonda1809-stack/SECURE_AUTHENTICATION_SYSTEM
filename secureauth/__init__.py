import os
import time
from datetime import timedelta

import click
from flask import Flask, redirect, request, session, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash

from .db import close_db, get_db, init_db, init_db_command

csrf = CSRFProtect()


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    environment = os.environ.get("APP_ENV", "development").lower()
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        DATABASE=os.path.join(app.instance_path, "secureauth.sqlite"),
        ENVIRONMENT=environment,
        SECURITY_TESTING_ENABLED=environment in {"development", "testing"},
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ONLY", "").lower() == "true",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_IDLE_TIMEOUT=30 * 60,
        MAX_CONTENT_LENGTH=16 * 1024,
        PASSWORD_HASH_METHOD="pbkdf2:sha256:600000",
    )
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("Set SECRET_KEY in the environment before starting SecureAuth.")

    os.makedirs(app.instance_path, exist_ok=True)
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    csrf.init_app(app)

    from .auth import bp as auth_bp
    from .pages import bp as pages_bp
    from .testing_center import bp as testing_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(pages_bp)
    app.register_blueprint(testing_bp)

    @app.before_request
    def enforce_idle_expiration():
        if "user_id" not in session:
            return None
        last_activity = session.get("last_activity")
        now = int(time.time())
        if not isinstance(last_activity, int) or now - last_activity > app.config["SESSION_IDLE_TIMEOUT"]:
            session.clear()
            return redirect(url_for("auth.login", expired=1))
        if request.endpoint != "static":
            session["last_activity"] = now
        return None

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    def create_admin(username):
        """Promote an existing account to administrator without client-supplied roles."""
        from getpass import getpass

        password = getpass("Admin command password (verification only): ")
        db = get_db()
        user = db.execute(
            "SELECT id, password_hash FROM users WHERE username = ? COLLATE NOCASE",
            (username.strip(),),
        ).fetchone()
        if user is None:
            raise click.ClickException("No account has that username.")
        from werkzeug.security import check_password_hash

        if not check_password_hash(user["password_hash"], password):
            raise click.ClickException("Password verification failed.")
        db.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user["id"],))
        db.commit()
        click.echo("Administrator role assigned.")

    return app
