"""RA dashboard: the Registration Authority approves or rejects certificate requests.

DEMO SHORTCUT: there is no login. Anyone who can open /admin acts as the RA (that is why the app
only listens on 127.0.0.1). A real RA would sign in with MFA and only see its own department.
"""
import secrets
from pathlib import Path

from cryptography import x509
from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from .audit import log_event
from .ca_core import (Identity, IssuanceError, build_pkcs12, check_csr, demo_csr, generate_demo_key,
                      issue_certificate, load_csr)
from .db import get_db
from .templates_def import ROLE_TEMPLATES, TEMPLATES

bp = Blueprint("admin", __name__, url_prefix="/admin")

RA_ACTOR = "ra-admin"      # who the audit log says made the decision (one shared identity in the demo)

# Columns the dashboard reads. The demo .p12 password is deliberately NOT among them:
# the RA must never see it.
REQUEST_COLUMNS = ("id, tracking_id, name, email, reg_no, role, template, dns_names, demo_mode, csr_pem,"
                   " status, reject_reason, created_at, decided_at")


def describe_csr_key(row):
    """What kind of key the applicant sent, for the RA to see (e.g. 'RSA-2048 key, signature OK')."""
    if row["demo_mode"]:
        return "demo mode: the server will generate the key"
    try:
        return check_csr(load_csr(row["csr_pem"].encode("ascii")), TEMPLATES[row["template"]]) + " key, CSR signature OK"
    except IssuanceError as err:
        return f"problem: {err}"


@bp.route("/")
def dashboard():
    db = get_db()
    pending = db.execute(f"SELECT {REQUEST_COLUMNS} FROM requests WHERE status = 'pending' ORDER BY id").fetchall()
    decided = db.execute(
        "SELECT r.tracking_id, r.name, r.template, r.status, r.reject_reason, r.decided_at, c.serial_hex"
        " FROM requests r LEFT JOIN certificates c ON c.request_id = r.id"
        " WHERE r.status != 'pending' ORDER BY r.decided_at DESC, r.id DESC LIMIT 20").fetchall()
    key_info = {row["id"]: describe_csr_key(row) for row in pending}
    return render_template("admin.html", pending=pending, decided=decided, key_info=key_info, templates=TEMPLATES)


def pending_request(request_id):
    """The request row if it is still waiting for a decision, else None."""
    return get_db().execute(f"SELECT {REQUEST_COLUMNS} FROM requests WHERE id = ? AND status = 'pending'",
                            (request_id,)).fetchone()


def approve_request(row):
    """Issue the certificate for a pending request. Returns its serial (hex). Raises IssuanceError."""
    if row["template"] not in ROLE_TEMPLATES.get(row["role"], ()):     # checked at enrollment too
        raise IssuanceError(f"a {row['role']} may not have a {row['template']} certificate")
    dns_names = tuple(row["dns_names"].split(",")) if row["dns_names"] else ()
    identity = Identity(row["name"], row["email"], row["reg_no"], dns_names)

    demo_key = None
    if row["demo_mode"]:
        # DEMO ONLY: the server makes the key pair. In a real PKI it never leaves the applicant.
        demo_key = generate_demo_key(TEMPLATES[row["template"]])
        csr = demo_csr(demo_key)
    else:
        csr = load_csr(row["csr_pem"].encode("ascii"))

    result = issue_certificate(csr, identity, row["template"], request_id=row["id"], actor=RA_ACTOR)

    p12_name = p12_password = None
    if demo_key is not None:
        # Pack key + certificate + CA chain into a .p12 protected by a random password. The password
        # is shown to the applicant once (on their status page) and the key itself is not kept.
        p12_password = secrets.token_urlsafe(12)
        chain = x509.load_pem_x509_certificates((Path(current_app.config["ISSUING_DIR"]) / "chain.pem").read_bytes())
        p12_bytes = build_pkcs12(demo_key, result.certificate, chain, p12_password.encode(), row["name"])
        p12_name = f"{result.serial_hex}.p12"
        (Path(current_app.config["ISSUED_DIR"]) / p12_name).write_bytes(p12_bytes)

    db = get_db()
    db.execute(
        "UPDATE requests SET status = 'approved', decided_by = ?, decided_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),"
        " p12_path = ?, p12_password = ? WHERE id = ?",
        (RA_ACTOR, p12_name, p12_password, row["id"]))
    db.commit()
    log_event(RA_ACTOR, "REQUEST_APPROVED", row["tracking_id"], f"certificate {result.serial_hex}")
    return result.serial_hex


@bp.post("/requests/<int:request_id>/approve")
def approve(request_id):
    row = pending_request(request_id)
    if row is None:
        flash("That request is not pending any more (already decided?).", "error")
        return redirect(url_for("admin.dashboard"))
    try:
        serial = approve_request(row)
    except IssuanceError as err:
        log_event(RA_ACTOR, "APPROVAL_FAILED", row["tracking_id"], str(err))
        flash(f"Could not issue a certificate for {row['tracking_id']}: {err}", "error")
    else:
        flash(f"Approved {row['tracking_id']}: certificate {serial} issued.", "success")
    return redirect(url_for("admin.dashboard"))


@bp.post("/requests/<int:request_id>/reject")
def reject(request_id):
    row = pending_request(request_id)
    reason = " ".join(request.form.get("reason", "").split())[:300]
    if row is None:
        flash("That request is not pending any more (already decided?).", "error")
    elif not reason:
        flash("Give a reason when you reject a request: the applicant will see it.", "error")
    else:
        db = get_db()
        db.execute(
            "UPDATE requests SET status = 'rejected', reject_reason = ?, decided_by = ?,"
            " decided_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?",
            (reason, RA_ACTOR, request_id))
        db.commit()
        log_event(RA_ACTOR, "REQUEST_REJECTED", row["tracking_id"], reason)
        flash(f"Rejected {row['tracking_id']}.", "success")
    return redirect(url_for("admin.dashboard"))
