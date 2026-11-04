import sqlite3
import time

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db
from .security import validate_email, validate_password, validate_username

bp = Blueprint("auth", __name__)
LOCKOUT_LIMIT = 5
LOCKOUT_SECONDS = 5 * 60


def get_current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def required_user():
    user = get_current_user()
    if user is None:
        return None
    return user


def _record_login(db, user_id, identity, success):
    db.execute(
        "INSERT INTO login_events (user_id, attempted_identity, success) VALUES (?, ?, ?)",
        (user_id, identity[:254], int(success)),
    )


@bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        error = None

        if not 1 <= len(full_name) <= 100:
            error = "Enter your full name (up to 100 characters)."
        elif not validate_email(email):
            error = "Enter a valid email address."
        elif not validate_username(username):
            error = "Username must be 4–30 letters, numbers, or underscores."
        else:
            valid, error = validate_password(password)
            if valid and password != confirmation:
                error = "The passwords do not match."
            elif valid:
                error = None

        db = get_db()
        if error is None:
            duplicate = db.execute(
                "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE",
                (email, username),
            ).fetchone()
            if duplicate:
                error = "That email or username is already registered."

        if error is None:
            try:
                db.execute(
                    "INSERT INTO users (full_name, email, username, password_hash) VALUES (?, ?, ?, ?)",
                    (
                        full_name,
                        email,
                        username,
                        generate_password_hash(password, method=current_app.config["PASSWORD_HASH_METHOD"]),
                    ),
                )
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
                flash("That email or username is already registered.", "error")
                return render_template("auth/register.html")
            flash("Your account is ready. Sign in to continue.", "success")
            return redirect(url_for("auth.login"))
        flash(error, "error")
    return render_template("auth/register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = None
        if identity and len(identity) <= 254:
            user = db.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE",
                (identity, identity),
            ).fetchone()
        now = int(time.time())

        if user is None:
            _record_login(db, None, identity, False)
            db.commit()
            flash("Invalid username/email or password.", "error")
        elif user["locked_until"] is not None and user["locked_until"] > now:
            _record_login(db, user["id"], identity, False)
            db.commit()
            remaining = max(1, (user["locked_until"] - now + 59) // 60)
            flash(f"Account temporarily locked. Try again in about {remaining} minute(s).", "error")
        elif not check_password_hash(user["password_hash"], password):
            attempts = user["failed_attempts"] + 1
            locked_until = now + LOCKOUT_SECONDS if attempts >= LOCKOUT_LIMIT else None
            db.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            _record_login(db, user["id"], identity, False)
            db.commit()
            if locked_until is not None:
                flash("Account temporarily locked after five failed attempts. Try again in five minutes.", "error")
            else:
                flash("Invalid username/email or password.", "error")
        else:
            db.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?",
                (user["id"],),
            )
            _record_login(db, user["id"], identity, True)
            db.commit()
            session.clear()
            session.permanent = request.form.get("remember") == "on"
            session["user_id"] = user["id"]
            session["last_activity"] = int(time.time())
            flash("You are securely signed in.", "success")
            return redirect(url_for("pages.dashboard"))
    return render_template("auth/login.html", expired=request.args.get("expired") == "1")


@bp.post("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))


@bp.app_context_processor
def inject_current_user():
    return {"current_user": get_current_user()}
