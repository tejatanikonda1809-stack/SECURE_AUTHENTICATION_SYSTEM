from functools import wraps

from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .auth import get_current_user
from .db import get_db
from .security import password_feedback, validate_password

bp = Blueprint("pages", __name__)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if get_current_user() is None:
            flash("Sign in to access that page.", "error")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


@bp.get("/")
def home():
    if get_current_user() is not None:
        return redirect(url_for("pages.dashboard"))
    return redirect(url_for("auth.login"))


@bp.get("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    return render_template("pages/dashboard.html", user=user)


@bp.route("/password-checker", methods=("GET", "POST"))
@login_required
def password_checker():
    result = None
    if request.method == "POST":
        candidate = request.form.get("password", "")
        if len(candidate) > 128:
            flash("Password checker accepts at most 128 characters.", "error")
        else:
            result = password_feedback(candidate)
    return render_template("pages/password_checker.html", result=result)


@bp.route("/settings", methods=("GET", "POST"))
@login_required
def settings():
    user = get_current_user()
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirmation = request.form.get("confirm_password", "")
        if not check_password_hash(user["password_hash"], current_password):
            flash("Current password is incorrect.", "error")
        else:
            valid, error = validate_password(new_password)
            if not valid:
                flash(error, "error")
            elif new_password != confirmation:
                flash("The new passwords do not match.", "error")
            elif check_password_hash(user["password_hash"], new_password):
                flash("Choose a password different from your current password.", "error")
            else:
                db = get_db()
                db.execute(
                    "UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?",
                    (
                        generate_password_hash(
                            new_password,
                            method=current_app_hash_method(),
                        ),
                        user["id"],
                    ),
                )
                db.commit()
                session.clear()
                flash("Password updated. Sign in again with your new password.", "success")
                return redirect(url_for("auth.login"))
    return render_template("pages/settings.html", user=user)


def current_app_hash_method():
    from flask import current_app

    return current_app.config["PASSWORD_HASH_METHOD"]


@bp.get("/admin")
@admin_required
def admin():
    users = get_db().execute(
        "SELECT id, full_name, email, username, role, created_at, last_login FROM users ORDER BY id"
    ).fetchall()
    return render_template("pages/admin.html", users=users)
