import sqlite3

from werkzeug.security import generate_password_hash


def _create_baseline_database(path):
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE baseline_users (username TEXT NOT NULL, password TEXT NOT NULL)"
    )
    connection.execute(
        "INSERT INTO baseline_users (username, password) VALUES (?, ?)",
        ("baseline_user", "LegacySample!Password123"),
    )
    connection.commit()
    return connection


def test_isolated_baseline_simulates_injection_and_plaintext_storage(tmp_path):
    connection = _create_baseline_database(tmp_path / "baseline.sqlite")
    try:
        identity = "' OR 1=1 -- "
        password = "not-the-account-password"
        insecure_query = (
            "SELECT username FROM baseline_users "
            f"WHERE username = '{identity}' AND password = '{password}'"
        )
        baseline_bypass = connection.execute(insecure_query).fetchone()
        stored_plaintext = connection.execute(
            "SELECT password FROM baseline_users WHERE username = ?",
            ("baseline_user",),
        ).fetchone()[0]

        assert baseline_bypass is not None
        assert stored_plaintext == "LegacySample!Password123"

        secure_hash = generate_password_hash(
            "LegacySample!Password123",
            method="pbkdf2:sha256:600000",
        )
        secure_lookup = connection.execute(
            "SELECT username FROM baseline_users WHERE username = ?",
            (identity,),
        ).fetchone()
        assert secure_lookup is None
        assert secure_hash != stored_plaintext
        assert secure_hash.startswith("pbkdf2:sha256:")
    finally:
        connection.close()
