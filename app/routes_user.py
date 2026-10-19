"""Public (user-facing) pages: home, enrollment, request status and downloads.

The applicant never talks to the CA directly. They submit a request here; the RA approves or
rejects it on /admin; once approved, they download their certificate with the tracking ID.
"""
import re
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, send_file, url_for

from .audit import log_event
from .ca_core import Identity, IssuanceError, check_csr, check_identity, load_csr
from .db import get_db
from .templates_def import ROLE_TEMPLATES, TEMPLATES, templates_for_role

bp = Blueprint("user", __name__)


@bp.route("/")
def home():
    return render_template("home.html")


# --------------------------------------------------------------------------------------
# Enrollment
# --------------------------------------------------------------------------------------

def check_enrollment(role, form, upload):
    """Validate the form. Returns (identity, template, demo_mode, csr_pem) or raises IssuanceError.

    The same checks run again when the RA approves, but doing them now tells the applicant
    about a mistake straight away instead of after a rejection.
    """
    template_name = form.get("template", "")
    if template_name not in ROLE_TEMPLATES[role]:
        raise IssuanceError(f"a {role} may not request the {template_name or '(no template)'} template")
    template = TEMPLATES[template_name]

    dns_names = tuple(host for host in re.split(r"[,\s]+", form.get("dns_names", "")) if host)
    identity = check_identity(
        Identity(form.get("name", ""), form.get("email", ""), form.get("reg_no", ""), dns_names), template)

    demo_mode = form.get("demo_mode") == "on"
    has_csr = upload is not None and upload.filename != ""
    if demo_mode and has_csr:
        raise IssuanceError("choose ONE: upload a CSR, or tick demo mode (not both)")
    if not demo_mode and not has_csr:
        raise IssuanceError("upload a CSR file, or tick demo mode")

    csr_pem = None
    if has_csr:
        csr = load_csr(upload.read())
        check_csr(csr, template)            # signature (proof of possession) + key type and size
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return identity, template, demo_mode, csr_pem


def new_tracking_id():
    """A hard-to-guess public ID such as REQ-3F9A1C07B2D4 (48 random bits)."""
    return "REQ-" + secrets.token_hex(6).upper()


@bp.route("/enroll", methods=["GET", "POST"])
def enroll():
    role = request.values.get("role")
    if role not in ROLE_TEMPLATES:                     # step 1: who are you?
        return render_template("enroll.html", role=None)

    templates = templates_for_role(role)               # step 2: only the templates this role may use
    if request.method == "GET":
        return render_template("enroll.html", role=role, templates=templates, form={})

    try:
        identity, template, demo_mode, csr_pem = check_enrollment(role, request.form, request.files.get("csr_file"))
    except IssuanceError as err:
        return render_template("enroll.html", role=role, templates=templates, form=request.form, error=str(err)), 400

    tracking_id = new_tracking_id()
    db = get_db()
    db.execute(
        "INSERT INTO requests (tracking_id, name, email, reg_no, role, template, dns_names, demo_mode, csr_pem)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (tracking_id, identity.name, identity.email, identity.reg_no, role, template.name,
         ",".join(identity.dns_names) or None, int(demo_mode), csr_pem))
    db.commit()
    log_event(identity.email, "REQUEST_SUBMITTED", tracking_id,
              f"role={role}; template={template.name}; {'demo mode' if demo_mode else 'CSR uploaded'}")

    flash(f"Request submitted. Your tracking ID is {tracking_id} - keep it to check the status.", "success")
    return redirect(url_for("user.request_status", tracking_id=tracking_id))


# --------------------------------------------------------------------------------------
# Status and downloads
# --------------------------------------------------------------------------------------

def find_request(tracking_id):
    row = get_db().execute("SELECT * FROM requests WHERE tracking_id = ?", (tracking_id,)).fetchone()
    if row is None:
        abort(404)
    return row


def certificate_for(request_row):
    return get_db().execute("SELECT * FROM certificates WHERE request_id = ?", (request_row["id"],)).fetchone()


@bp.route("/status")
def status_lookup():
    """The 'check a request' box on the home page."""
    tracking_id = request.args.get("tracking_id", "").strip().upper()
    if not tracking_id:
        return redirect(url_for("user.home"))
    return redirect(url_for("user.request_status", tracking_id=tracking_id))


@bp.route("/request/<tracking_id>")
def request_status(tracking_id):
    row = find_request(tracking_id)
    cert = certificate_for(row) if row["status"] == "approved" else None

    # Demo mode: the .p12 password is shown exactly ONCE, on the first visit after approval,
    # and then wiped from the database.
    p12_password = None
    if row["p12_password"]:
        p12_password = row["p12_password"]
        db = get_db()
        db.execute("UPDATE requests SET p12_password = NULL WHERE id = ?", (row["id"],))
        db.commit()
        log_event(row["email"], "P12_PASSWORD_SHOWN", tracking_id, "shown once, then wiped from the database")

    response = render_template("request_status.html", req=row, cert=cert, p12_password=p12_password,
                               template=TEMPLATES[row["template"]])
    return response, 200, {"Cache-Control": "no-store"}


# The files an approved applicant can download, and their MIME types.
DOWNLOADS = {"cert.pem": "application/x-pem-file", "chain.pem": "application/x-pem-file",
             "cert.p12": "application/x-pkcs12"}


@bp.route("/request/<tracking_id>/<filename>")
def download(tracking_id, filename):
    row = find_request(tracking_id)
    if filename not in DOWNLOADS or row["status"] != "approved":
        abort(404)

    issued_dir = Path(current_app.config["ISSUED_DIR"])
    if filename == "cert.pem":
        path = issued_dir / certificate_for(row)["pem_path"]
    elif filename == "chain.pem":                       # Issuing CA + Root CA certificates
        path = Path(current_app.config["ISSUING_DIR"]) / "chain.pem"
    elif row["p12_path"]:                               # cert.p12: only demo-mode requests have one
        path = issued_dir / row["p12_path"]
    else:
        abort(404)

    log_event(row["email"], "DOWNLOAD", tracking_id, filename)
    return send_file(path, mimetype=DOWNLOADS[filename], as_attachment=True,
                     download_name=f"{tracking_id}-{filename}")
