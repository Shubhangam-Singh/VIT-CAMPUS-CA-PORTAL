"""Phase 0 checks: the app starts, the home page loads, init-db creates the three tables."""
import re
import sqlite3

import pytest

from app.db import get_db, init_db

EXPECTED_TABLES = {"requests", "certificates", "audit_log"}


def tables_in(db_path):
    """Table names read with a plain sqlite3 connection (independent of the app code)."""
    con = sqlite3.connect(db_path)
    try:
        return {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    finally:
        con.close()


def test_home_page_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"VIT Campus CA Portal" in response.data


def test_init_db_creates_the_three_tables(app):
    # the `app` fixture has already called init_db()
    assert EXPECTED_TABLES <= tables_in(app.config["DATABASE"])


def test_init_db_can_run_twice_without_losing_data(app):
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO audit_log (actor, action) VALUES ('system', 'TEST')")
        db.commit()
        init_db()  # second run: CREATE TABLE IF NOT EXISTS must not wipe anything
        assert db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1


def test_init_db_command(app):
    result = app.test_cli_runner().invoke(args=["init-db"])
    assert result.exit_code == 0, result.output
    for table in EXPECTED_TABLES:
        assert table in result.output


def test_schema_defaults_and_constraints(app):
    insert_request = (
        "INSERT INTO requests (tracking_id, name, email, reg_no, role, template) "
        "VALUES (?, 'Asha Rao', 'asha@vit.ac.in', '21BCE0001', ?, 'student_auth')"
    )
    with app.app_context():
        db = get_db()
        db.execute(insert_request, ("REQ-00000001", "student"))
        row = db.execute("SELECT * FROM requests").fetchone()
        assert row["status"] == "pending"     # default
        assert row["demo_mode"] == 0          # default
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", row["created_at"])  # UTC ISO-8601

        with pytest.raises(sqlite3.IntegrityError):   # role must be student or faculty
            db.execute(insert_request, ("REQ-00000002", "janitor"))

        with pytest.raises(sqlite3.IntegrityError):   # tracking IDs are unique
            db.execute(insert_request, ("REQ-00000001", "student"))

        with pytest.raises(sqlite3.IntegrityError):   # foreign key: request 999 does not exist
            db.execute(
                "INSERT INTO certificates (serial_hex, request_id, template, subject_cn, subject_dn, "
                "key_type, fingerprint_sha256, not_before, not_after, pem_path) "
                "VALUES ('00', 999, 't', 'cn', 'dn', 'RSA-2048', 'ff', 'a', 'b', 'p')"
            )
