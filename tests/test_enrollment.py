"""Phase 3 checks: enrollment, the RA's approve / reject workflow, downloads and the audit log.

Everything goes through real HTTP requests to the app (Flask's test client).
"""
import io
import re

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from app.db import get_db
from csr_factory import make_csr, tamper

STUDENT = {"name": "Asha Rao", "email": "asha.rao@vit.ac.in", "reg_no": "21BCE0001", "template": "student_auth"}
FACULTY = {"name": "Dr. Meera Iyer", "email": "meera.iyer@vit.ac.in", "reg_no": "FAC1001", "template": "faculty_email"}


@pytest.fixture
def web(ca_app):
    return ca_app.test_client()


def pem(csr):
    return csr.public_bytes(serialization.Encoding.PEM)


def enroll(web, role, fields, csr_bytes=None, demo=False):
    """Submit the enrollment form. Returns the response (not followed)."""
    data = {"role": role, **fields}
    if csr_bytes is not None:
        data["csr_file"] = (io.BytesIO(csr_bytes), "request.csr")
    if demo:
        data["demo_mode"] = "on"
    return web.post(f"/enroll?role={role}", data=data, content_type="multipart/form-data")


def submit(web, role, fields, csr_bytes=None, demo=False):
    """Submit and return the tracking ID from the redirect."""
    response = enroll(web, role, fields, csr_bytes, demo)
    assert response.status_code == 302, response.get_data(as_text=True)
    return re.search(r"/request/(REQ-[0-9A-F]{12})$", response.headers["Location"]).group(1)


def request_row(app, tracking_id):
    with app.app_context():
        return get_db().execute("SELECT * FROM requests WHERE tracking_id = ?", (tracking_id,)).fetchone()


def audit_rows(app):
    with app.app_context():
        return [tuple(r) for r in get_db().execute("SELECT actor, action, target FROM audit_log ORDER BY id")]


def text(response):
    return response.get_data(as_text=True)


# ---------------------------------------------------------------- enrollment form

def test_enroll_asks_for_the_role_first_and_offers_only_that_roles_templates(web):
    assert "I am a student" in text(web.get("/enroll"))

    student_page = text(web.get("/enroll?role=student"))
    assert 'value="student_auth"' in student_page and 'value="code_signing"' in student_page
    assert 'value="faculty_email"' not in student_page and 'value="server_tls"' not in student_page
    assert "dns_names" not in student_page                      # students cannot get server certs

    faculty_page = text(web.get("/enroll?role=faculty"))
    for name in ("faculty_email", "code_signing", "server_tls"):
        assert f'value="{name}"' in faculty_page
    assert 'value="student_auth"' not in faculty_page
    assert "DEMO ONLY - in real PKI the private key never leaves the user" in faculty_page


def test_enroll_with_a_csr_creates_a_pending_request(ca_app, web, keys):
    tracking_id = submit(web, "student", STUDENT, pem(make_csr(keys.rsa2048)))

    row = request_row(ca_app, tracking_id)
    assert (row["status"], row["role"], row["template"], row["demo_mode"]) == ("pending", "student", "student_auth", 0)
    assert row["csr_pem"].startswith("-----BEGIN CERTIFICATE REQUEST-----")
    page = text(web.get(f"/request/{tracking_id}"))
    assert "PENDING" in page and tracking_id in page and "Waiting for the RA" in page
    assert audit_rows(ca_app) == [("asha.rao@vit.ac.in", "REQUEST_SUBMITTED", tracking_id)]


@pytest.mark.parametrize("role, fields, key, demo, message", [
    ("student", {**STUDENT, "template": "server_tls"}, "ec256", False, "may not request the server_tls"),
    ("student", {**STUDENT, "template": "faculty_email"}, "rsa2048", False, "may not request the faculty_email"),
    ("student", STUDENT, "rsa2048", True, "choose ONE"),
    ("student", STUDENT, None, False, "upload a CSR file, or tick demo mode"),
    ("student", STUDENT, "rsa1024", False, "too small"),
    ("student", STUDENT, "bad signature", False, "signature is invalid"),
    ("student", STUDENT, "junk", False, "not a readable certificate request"),
    ("student", {**STUDENT, "email": "nope"}, "rsa2048", False, "not a valid e-mail"),
    ("faculty", {**FACULTY, "template": "server_tls"}, "ec256", False, "at least one DNS name"),
    ("faculty", {**FACULTY, "template": "code_signing", "dns_names": "x.vit.local"}, "rsa3072", False,
     "only used by the server_tls"),
])
def test_bad_enrollments_are_refused_with_a_message(ca_app, web, keys, role, fields, key, demo, message):
    if key == "bad signature":
        csr_bytes = pem(tamper(make_csr(keys.rsa2048)))
    elif key == "junk":
        csr_bytes = b"not a csr"
    else:
        csr_bytes = pem(make_csr(getattr(keys, key))) if key else None

    response = enroll(web, role, fields, csr_bytes, demo)

    assert response.status_code == 400
    assert message in text(response)
    with ca_app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0


def test_a_server_tls_request_keeps_its_dns_names(ca_app, web, keys):
    fields = {**FACULTY, "template": "server_tls", "dns_names": "LAB1.vit.local, www.lab1.vit.local"}
    tracking_id = submit(web, "faculty", fields, pem(make_csr(keys.ec256)))
    assert request_row(ca_app, tracking_id)["dns_names"] == "lab1.vit.local,www.lab1.vit.local"


def test_unknown_tracking_id_is_404(web):
    assert web.get("/request/REQ-000000000000").status_code == 404
    assert web.get("/request/REQ-000000000000/cert.pem").status_code == 404


def test_status_lookup_form_redirects(web):
    response = web.get("/status?tracking_id=req-abc")
    assert response.status_code == 302 and response.headers["Location"].endswith("/request/REQ-ABC")


# ---------------------------------------------------------------- RA dashboard

def test_dashboard_lists_pending_requests_and_says_auth_is_omitted(web, keys):
    tracking_id = submit(web, "student", STUDENT, pem(make_csr(keys.rsa2048)))
    page = text(web.get("/admin/"))
    assert "Authentication omitted in demo" in page
    assert tracking_id in page and "Asha Rao" in page and "21BCE0001" in page
    assert "RSA-2048 key, CSR signature OK" in page


def test_approving_a_csr_request_issues_the_certificate(ca_app, web, keys, issuing_ca):
    applicant_key = keys.rsa2048
    tracking_id = submit(web, "student", STUDENT, pem(make_csr(applicant_key, "Somebody Else")))
    request_id = request_row(ca_app, tracking_id)["id"]

    response = web.post(f"/admin/requests/{request_id}/approve", follow_redirects=True)
    assert f"Approved {tracking_id}" in text(response)

    row = request_row(ca_app, tracking_id)
    assert (row["status"], row["decided_by"]) == ("approved", "ra-admin") and row["decided_at"]
    assert row["p12_path"] is None and row["p12_password"] is None       # not demo mode: no .p12

    page = text(web.get(f"/request/{tracking_id}"))
    assert "APPROVED" in page and "cert.pem" in page and "chain.pem" in page and "cert.p12" not in page

    cert_response = web.get(f"/request/{tracking_id}/cert.pem")
    assert cert_response.status_code == 200
    assert f'filename={tracking_id}-cert.pem' in cert_response.headers["Content-Disposition"]
    cert = x509.load_pem_x509_certificate(cert_response.data)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Asha Rao"   # not the CSR's CN
    assert cert.public_key().public_numbers() == applicant_key.public_key().public_numbers()
    cert.verify_directly_issued_by(issuing_ca.cert)

    chain = x509.load_pem_x509_certificates(web.get(f"/request/{tracking_id}/chain.pem").data)
    assert [c.subject.rfc4514_string() for c in chain] == ["CN=VIT Issuing CA,O=VIT-PKI,C=IN",
                                                            "CN=VIT Root CA,O=VIT-PKI,C=IN"]
    assert web.get(f"/request/{tracking_id}/cert.p12").status_code == 404

    with ca_app.app_context():
        cert_row = get_db().execute("SELECT * FROM certificates").fetchone()
    assert cert_row["request_id"] == row["id"] and cert_row["serial_hex"] == f"{cert.serial_number:032x}"


def test_demo_mode_gives_a_p12_whose_password_is_shown_once(ca_app, web):
    tracking_id = submit(web, "faculty", FACULTY, demo=True)
    request_id = request_row(ca_app, tracking_id)["id"]
    assert "demo mode" in text(web.get("/admin/"))

    web.post(f"/admin/requests/{request_id}/approve")
    assert request_row(ca_app, tracking_id)["p12_password"]                 # waiting to be shown
    admin_page = text(web.get("/admin/"))

    first = web.get(f"/request/{tracking_id}")
    password = re.search(r'<code class="p12-password">([^<]+)</code>', text(first)).group(1)
    assert "DEMO ONLY - in real PKI the private key never leaves the user" in text(first)
    assert first.headers["Cache-Control"] == "no-store"
    assert password not in admin_page                                       # the RA never sees it

    second = text(web.get(f"/request/{tracking_id}"))
    assert password not in second and "shown once" in second                # ... and it is gone
    assert request_row(ca_app, tracking_id)["p12_password"] is None

    p12 = web.get(f"/request/{tracking_id}/cert.p12")
    assert p12.status_code == 200 and p12.mimetype == "application/x-pkcs12"
    with pytest.raises(ValueError):
        pkcs12.load_key_and_certificates(p12.data, b"wrong password")
    key, cert, extra = pkcs12.load_key_and_certificates(p12.data, password.encode())
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()
    assert key.key_size == 2048                                             # faculty_email: RSA-2048
    assert cert == x509.load_pem_x509_certificate(web.get(f"/request/{tracking_id}/cert.pem").data)
    assert [c.subject.rfc4514_string() for c in extra] == ["CN=VIT Issuing CA,O=VIT-PKI,C=IN",
                                                            "CN=VIT Root CA,O=VIT-PKI,C=IN"]
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.RFC822Name) == ["meera.iyer@vit.ac.in"]


def test_demo_mode_server_tls_gets_an_ec_key(ca_app, web):
    fields = {**FACULTY, "template": "server_tls", "dns_names": "lab1.vit.local"}
    tracking_id = submit(web, "faculty", fields, demo=True)
    web.post(f"/admin/requests/{request_row(ca_app, tracking_id)['id']}/approve")
    password = re.search(r'<code class="p12-password">([^<]+)</code>', text(web.get(f"/request/{tracking_id}"))).group(1)
    key, cert, _ = pkcs12.load_key_and_certificates(web.get(f"/request/{tracking_id}/cert.p12").data, password.encode())
    assert key.curve.name == "secp256r1"


def test_rejecting_needs_a_reason_and_the_applicant_sees_it(ca_app, web, keys):
    tracking_id = submit(web, "student", {**STUDENT, "template": "code_signing"}, pem(make_csr(keys.rsa3072)))
    request_id = request_row(ca_app, tracking_id)["id"]

    no_reason = web.post(f"/admin/requests/{request_id}/reject", data={"reason": "   "}, follow_redirects=True)
    assert "Give a reason" in text(no_reason)
    assert request_row(ca_app, tracking_id)["status"] == "pending"

    web.post(f"/admin/requests/{request_id}/reject", data={"reason": "Registration number does not match ID card"})
    row = request_row(ca_app, tracking_id)
    assert (row["status"], row["reject_reason"]) == ("rejected", "Registration number does not match ID card")

    page = text(web.get(f"/request/{tracking_id}"))
    assert "REJECTED" in page and "Registration number does not match ID card" in page
    for filename in ("cert.pem", "chain.pem", "cert.p12"):
        assert web.get(f"/request/{tracking_id}/{filename}").status_code == 404
    with ca_app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 0


def test_a_decided_request_cannot_be_decided_again(ca_app, web, keys):
    tracking_id = submit(web, "student", STUDENT, pem(make_csr(keys.rsa2048)))
    request_id = request_row(ca_app, tracking_id)["id"]
    web.post(f"/admin/requests/{request_id}/approve")

    again = web.post(f"/admin/requests/{request_id}/approve", follow_redirects=True)
    assert "not pending any more" in text(again)
    web.post(f"/admin/requests/{request_id}/reject", data={"reason": "too late"})
    assert request_row(ca_app, tracking_id)["status"] == "approved"
    with ca_app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 1


def test_if_the_ca_cannot_issue_the_request_stays_pending(app, keys, monkeypatch):
    """`app` has no Issuing CA, and ISSUING_CA_PASS is unset: approval fails cleanly."""
    monkeypatch.delenv("ISSUING_CA_PASS", raising=False)
    web = app.test_client()
    tracking_id = submit(web, "student", STUDENT, pem(make_csr(keys.rsa2048)))
    request_id = request_row(app, tracking_id)["id"]

    page = text(web.post(f"/admin/requests/{request_id}/approve", follow_redirects=True))
    assert "Could not issue a certificate" in page
    assert request_row(app, tracking_id)["status"] == "pending"
    assert ("ra-admin", "APPROVAL_FAILED", tracking_id) in audit_rows(app)


# ---------------------------------------------------------------- audit log

def test_every_step_is_in_the_audit_log(ca_app, web, keys):
    approved = submit(web, "student", STUDENT, pem(make_csr(keys.rsa2048)))
    rejected = submit(web, "student", {**STUDENT, "template": "code_signing"}, pem(make_csr(keys.rsa3072)))
    web.post(f"/admin/requests/{request_row(ca_app, approved)['id']}/approve")
    web.post(f"/admin/requests/{request_row(ca_app, rejected)['id']}/reject", data={"reason": "duplicate"})
    web.get(f"/request/{approved}/cert.pem")

    actions = [(actor, action) for actor, action, _ in audit_rows(ca_app)]
    assert actions == [
        ("asha.rao@vit.ac.in", "REQUEST_SUBMITTED"),
        ("asha.rao@vit.ac.in", "REQUEST_SUBMITTED"),
        ("ra-admin", "CERT_ISSUED"),
        ("ra-admin", "REQUEST_APPROVED"),
        ("ra-admin", "REQUEST_REJECTED"),
        ("asha.rao@vit.ac.in", "DOWNLOAD"),
    ]
    with ca_app.app_context():
        times = [r[0] for r in get_db().execute("SELECT ts FROM audit_log")]
    assert all(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", t) for t in times)     # when
