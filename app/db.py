"""SQLite access layer and database schema.

Three tables:
  requests      certificate requests and the RA's decision on each one
  certificates  every certificate the Issuing CA has issued (plus its revocation state)
  audit_log     who did what, and when
"""
import sqlite3
from pathlib import Path

import click
from flask import current_app, g
from flask.cli import with_appcontext

# Timestamps are stored as UTC text like 2026-10-19T09:30:00Z (ISO-8601). SQLite fills the
# "now" columns itself through the DEFAULT clause, so the Python code does not have to.
SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    tracking_id    TEXT    NOT NULL UNIQUE,      -- public ID the applicant keeps, e.g. REQ-1A2B3C4D
    name           TEXT    NOT NULL,             -- identity data typed on the enrollment form;
    email          TEXT    NOT NULL,             -- it counts as RA-verified once the admin approves
    reg_no         TEXT    NOT NULL,
    role           TEXT    NOT NULL CHECK (role IN ('student', 'faculty')),
    template       TEXT    NOT NULL,             -- student_auth, faculty_email, server_tls, code_signing
    dns_names      TEXT,                         -- comma-separated; only used by server_tls
    demo_mode      INTEGER NOT NULL DEFAULT 0,   -- 1 = the server generates the key + CSR (demo only)
    csr_pem        TEXT,                         -- uploaded CSR; empty in demo mode until approval
    status         TEXT    NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending', 'approved', 'rejected')),
    reject_reason  TEXT,
    p12_path       TEXT,                         -- demo mode only: the generated PKCS#12 file
    p12_password   TEXT,                         -- demo mode only: kept until first shown, then wiped
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    decided_at     TEXT,
    decided_by     TEXT
);

CREATE TABLE IF NOT EXISTS certificates (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex          TEXT    NOT NULL UNIQUE, -- 128-bit serial as 32 hex digits (too big for SQLite INTEGER)
    request_id          INTEGER REFERENCES requests (id),   -- empty when issued directly from the CLI
    template            TEXT    NOT NULL,
    subject_cn          TEXT    NOT NULL,
    subject_dn          TEXT    NOT NULL,        -- the full subject name
    email               TEXT,
    reg_no              TEXT,
    key_type            TEXT    NOT NULL,        -- e.g. RSA-2048 or EC-P256
    fingerprint_sha256  TEXT    NOT NULL,
    not_before          TEXT    NOT NULL,
    not_after           TEXT    NOT NULL,
    pem_path            TEXT    NOT NULL,        -- the certificate file under ca/issued/
    status              TEXT    NOT NULL DEFAULT 'valid' CHECK (status IN ('valid', 'revoked')),
                                                 -- "expired" is never stored: it is worked out from not_after
    revoked_at          TEXT,
    revocation_reason   TEXT,
    issued_at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),  -- when
    actor    TEXT NOT NULL,   -- who: the applicant's email, 'ra-admin', 'cli' or 'system'
    action   TEXT NOT NULL,   -- what: REQUEST_SUBMITTED, REQUEST_APPROVED, CERT_ISSUED, CERT_REVOKED, ...
    target   TEXT,            -- what it was done to: a tracking ID or a certificate serial
    details  TEXT             -- extra context such as the template or the rejection reason
);
"""


def get_db():
    """Return this request's SQLite connection (opened the first time it is needed)."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row            # rows behave like dicts: row["name"]
        g.db.execute("PRAGMA foreign_keys = ON")  # SQLite ignores foreign keys unless told to check them
    return g.db


def close_db(exc=None):
    """Close the connection when the request (app context) ends."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create the database file and tables if they do not exist yet.

    The schema uses CREATE TABLE IF NOT EXISTS, so running this again never deletes data.
    """
    Path(current_app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()


def list_tables():
    """Names of the tables in the database."""
    rows = get_db().execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )
    return [row["name"] for row in rows]


@click.command("init-db")
@with_appcontext
def init_db_command():
    """Create the database tables (safe to run again)."""
    init_db()
    click.echo(f"Database ready: {current_app.config['DATABASE']}")
    click.echo("Tables: " + ", ".join(list_tables()))


def init_app(app):
    """Hook the database helpers into the Flask app (called from create_app)."""
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
