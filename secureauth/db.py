import os
import sqlite3

import click
from flask import current_app, g


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL CHECK(length(full_name) BETWEEN 1 AND 100),
    email TEXT NOT NULL,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK(failed_attempts >= 0),
    locked_until INTEGER,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_login TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email COLLATE NOCASE);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique ON users(username COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    attempted_identity TEXT NOT NULL,
    success INTEGER NOT NULL CHECK(success IN (0, 1)),
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS login_events_user_timestamp ON login_events(user_id, timestamp);
"""


def get_db():
    if "db" not in g:
        database = current_app.config["DATABASE"]
        if database != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(database)), exist_ok=True)
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db():
    get_db().executescript(SCHEMA)
    get_db().commit()


@click.command("init-db")
def init_db_command():
    """Create the SecureAuth database tables."""
    init_db()
    click.echo("Initialized the database.")
