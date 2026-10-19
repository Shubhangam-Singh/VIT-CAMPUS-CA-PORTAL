"""Public (user-facing) pages: home, enrollment, request status and downloads.

The applicant never talks to the CA directly. They submit a request here; the RA approves or
rejects it on /admin; once approved, they download their certificate with the tracking ID.
"""
import os
import re
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from flask import (Blueprint, Response, abort, current_app, flash, jsonify, redirect, render_template, request,
                   send_file, url_for)
from werkzeug.utils import secure_filename

from .audit import log_event
from .ca_core import (Identity, IssuanceError, build_ocsp_response, certificate_status, check_csr, check_identity,
                      current_crl, find_certificate, load_csr, lookup_status)
from .db import get_db
from .signing import (SigningError, load_crl, load_p12, parse_signature_file, sign_with_p12, subject_value, to_json,
                      verify_signature)
from .templates_def import ROLE_TEMPLATES, TEMPLATES, templates_for_role

bp = Blueprint("user", __name__)


@bp.app_context_processor
def ca_health():
    """Shown on every page: is the CA set up, and can its key be unlocked?
    (So "no Issuing CA found" is explained before anyone presses Approve.)"""
    issuing_dir = Path(current_app.config["ISSUING_DIR"])
    return {"ca_ready": (issuing_dir / "issuing-ca.crt").is_file(),
            "ca_key_available": "issuing_ca" in current_app.extensions or bool(os.environ.get("ISSUING_CA_PASS"))}


@bp.route("/")
def home():
    db = get_db()
    stats = {
        "pending": db.execute("SELECT COUNT(*) FROM requests WHERE status = 'pending'").fetchone()[0],
        "issued": db.execute("SELECT COUNT(*) FROM certificates").fetchone()[0],
        "revoked": db.execute("SELECT COUNT(*) FROM certificates WHERE status = 'revoked'").fetchone()[0],
    }
    return render_template("home.html", stats=stats)


# --------------------------------------------------------------------------------------
# Help: a guided tour of the whole certificate lifecycle, and frequently asked questions
# --------------------------------------------------------------------------------------

@bp.route("/guide")
def guide():
    return render_template("guide.html")


@bp.route("/faq")
def faq():
    return render_template("faq.html")


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
    """'Track a request': a form, or a jump straight to the request when a tracking ID is given."""
    tracking_id = request.args.get("tracking_id", "").strip().upper()
    if not tracking_id:
        return render_template("track.html")
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
                               cert_status=certificate_status(cert) if cert else None,
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


# --------------------------------------------------------------------------------------
# Revocation information - public, anyone may check a certificate (Phase 4)
# --------------------------------------------------------------------------------------

@bp.route("/crl.pem")
def crl_pem():
    """The CRL Distribution Point written into every certificate."""
    crl = current_crl()
    return Response(crl.public_bytes(serialization.Encoding.PEM), mimetype="application/x-pem-file")


@bp.route("/crl.der")
def crl_der():
    crl = current_crl()
    return Response(crl.public_bytes(serialization.Encoding.DER), mimetype="application/pkix-crl")


@bp.route("/api/status/<serial>")
def api_status(serial):
    """OCSP-like lookup: {"status": "good" | "revoked" | "expired" | "unknown", "revocation_time": ...}"""
    return jsonify(lookup_status(serial))


@bp.post("/ocsp")
def ocsp_responder():
    """A real OCSP responder (RFC 6960): try  openssl ocsp -url http://127.0.0.1:5000/ocsp ..."""
    response = build_ocsp_response(request.get_data())
    return Response(response.public_bytes(serialization.Encoding.DER), mimetype="application/ocsp-response")


# --------------------------------------------------------------------------------------
# Sign and verify files (Phase 5)
# --------------------------------------------------------------------------------------

def our_chain():
    """Issuing CA + Root CA certificates, added to a signature if the .p12 carries none."""
    path = Path(current_app.config["ISSUING_DIR"]) / "chain.pem"
    return x509.load_pem_x509_certificates(path.read_bytes()) if path.is_file() else []


@bp.route("/sign", methods=["GET", "POST"])
def sign_page():
    """DEMO ONLY: a real signer runs tools/sign_file.py on their own computer; here the .p12 is uploaded."""
    if request.method == "GET":
        return render_template("sign.html")

    p12_file, target = request.files.get("p12_file"), request.files.get("file")
    if not p12_file or not p12_file.filename or not target or not target.filename:
        return render_template("sign.html", error="choose both your .p12 file and the file to sign"), 400
    filename = secure_filename(target.filename) or "file"
    p12_bytes, password = p12_file.read(), request.form.get("password", "")
    try:
        _, cert, _ = load_p12(p12_bytes, password)
        # The server knows what the offline tool cannot: refuse a revoked certificate straight away.
        row = find_certificate(f"{cert.serial_number:032x}")
        if row is not None and row["status"] == "revoked":
            raise SigningError(f"this certificate was revoked on {row['revoked_at']} ({row['revocation_reason']}): "
                               "every verifier would reject the signature")
        document = sign_with_p12(target.read(), filename, p12_bytes, password, our_chain())
    except SigningError as err:
        return render_template("sign.html", error=str(err)), 400

    signer = x509.load_pem_x509_certificate(document["signer_certificate"].encode("ascii"))
    log_event(subject_value(signer, NameOID.EMAIL_ADDRESS), "FILE_SIGNED", f"{signer.serial_number:032x}",
              f"{filename}; sha256={document['sha256']}")
    # Nothing is kept on the server: not the .p12, not the password, not the file.
    return Response(to_json(document), mimetype="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{filename}.sig.json"'})


def crl_for_verification():
    """The current CRL, or the last published one if the CA key is locked, or None if there is none."""
    try:
        return current_crl()
    except IssuanceError:
        path = Path(current_app.config["CRL_DIR"]) / "crl.pem"
        return load_crl(path.read_bytes()) if path.is_file() else None


@bp.route("/verify", methods=["GET", "POST"])
def verify_page():
    if request.method == "GET":
        return render_template("verify.html")

    target, sig_file = request.files.get("file"), request.files.get("sig_file")
    if not target or not target.filename or not sig_file or not sig_file.filename:
        return render_template("verify.html", error="choose both the signed file and its .sig.json"), 400
    root_path = Path(current_app.config["ISSUING_DIR"]) / "root-ca.crt"
    if not root_path.is_file():
        return render_template("verify.html", error="the CA is not set up yet (no root-ca.crt)"), 503
    try:
        document = parse_signature_file(sig_file.read().decode("utf-8"))
    except (SigningError, UnicodeDecodeError) as err:
        message = str(err) if isinstance(err, SigningError) else "the signature file is not UTF-8 text"
        return render_template("verify.html", error=message), 400

    result = verify_signature(target.read(), document, x509.load_pem_x509_certificate(root_path.read_bytes()),
                              crl_for_verification())
    failed = [check.name.split(".")[0] for check in result.checks if not check.passed]
    log_event("anyone", "FILE_VERIFIED", secure_filename(target.filename) or "file",
              "VALID" if result.passed else f"NOT VALID (failed check {', '.join(failed)})")
    return render_template("verify.html", result=result, filename=target.filename)
