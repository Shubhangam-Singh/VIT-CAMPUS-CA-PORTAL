"""Phase 4 checks: certificate list and detail pages, revocation, the CRL, the status API,
the audit log page / CSV export, and the OCSP responder."""
import csv
import io
import re
import shutil
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import ocsp

from app import ca_core, cli
from app.audit import log_event
from app.ca_core import Identity, issue_certificate
from app.db import get_db
from csr_factory import make_csr

ASHA = Identity("Asha Rao", "asha.rao@vit.ac.in", "21BCE0001")
MEERA = Identity("Dr. Meera Iyer", "meera.iyer@vit.ac.in", "FAC1001")


@pytest.fixture
def web(ca_app):
    return ca_app.test_client()


def issue(ca_app, key, identity=ASHA, template="student_auth"):
    with ca_app.app_context():
        return issue_certificate(make_csr(key), identity, template, actor="test")


def set_not_after(ca_app, serial_hex, moment):
    with ca_app.app_context():
        db = get_db()
        db.execute("UPDATE certificates SET not_after = ? WHERE serial_hex = ?", (ca_core.iso(moment), serial_hex))
        db.commit()


def load_crl(ca_app):
    return x509.load_pem_x509_crl((ca_app.config["CRL_DIR"] / "crl.pem").read_bytes())


def crl_number(crl):
    return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number


def text(response):
    return response.get_data(as_text=True)


# ---------------------------------------------------------------- list and detail pages

def test_certificate_list_shows_status_and_days_left_and_highlights_expiring(ca_app, web, keys):
    fresh = issue(ca_app, keys.rsa2048).serial_hex
    soon = issue(ca_app, keys.rsa2048).serial_hex
    old = issue(ca_app, keys.rsa2048).serial_hex
    now = ca_core.now_utc()
    set_not_after(ca_app, soon, now + timedelta(days=10, hours=1))
    set_not_after(ca_app, old, now - timedelta(days=1))

    page = text(web.get("/admin/certs"))
    rows = {serial: re.search(rf'<tr class="([^"]*)">\s*<td><a href="/admin/certs/{serial}">.*?</tr>', page, re.S)
            for serial in (fresh, soon, old)}
    assert all(rows.values())
    # a fresh 365-day certificate has 365 whole days left in the same second it was issued, 364 a moment later
    assert "VALID" in rows[fresh].group(0) and re.search(r">36[45]<", rows[fresh].group(0))
    assert rows[fresh].group(1) == ""
    assert "VALID" in rows[soon].group(0) and ">10<" in rows[soon].group(0) and rows[soon].group(1) == "expiring"
    assert "EXPIRED" in rows[old].group(0) and rows[old].group(1) == ""
    tiles = dict((label, int(value)) for value, label in
                 re.findall(r'kpi-value">(\d+)</span>\s*<span class="kpi-label">([^<]+)<', page))
    assert tiles == {"valid": 2, "expire within 30 days": 1, "expired": 1, "revoked": 0}

    expiring_tab = text(web.get("/admin/certs?show=expiring"))     # filter tabs
    assert soon in expiring_tab and fresh not in expiring_tab and old not in expiring_tab


def test_detail_page_shows_the_parsed_certificate(ca_app, web, keys):
    serial = issue(ca_app, keys.rsa2048, MEERA, "faculty_email").serial_hex
    page = text(web.get(f"/admin/certs/{serial}"))
    for expected in ("C=IN, O=VIT, CN=Dr. Meera Iyer, emailAddress=meera.iyer@vit.ac.in, serialNumber=FAC1001",
                     "C=IN, O=VIT-PKI, CN=VIT Issuing CA", "RSA-2048", "CA:FALSE (critical)",
                     "Digital Signature, Key Encipherment (critical)", "E-mail protection (emailProtection)",
                     "email: meera.iyer@vit.ac.in", "http://localhost:5000/crl.pem", "SHA-256 fingerprint",
                     "BEGIN CERTIFICATE", "Revoke this certificate"):
        assert expected in page, expected

    colon_form = ":".join(re.findall("..", serial)).upper()          # how OpenSSL prints serials
    assert web.get(f"/admin/certs/{colon_form}").status_code == 200
    assert web.get("/admin/certs/" + "0" * 32).status_code == 404
    assert web.get("/admin/certs/not-a-serial").status_code == 404


# ---------------------------------------------------------------- revocation and the CRL

def test_revoking_publishes_a_signed_crl_listing_the_certificate(ca_app, web, keys, issuing_ca):
    serial = issue(ca_app, keys.rsa2048).serial_hex
    page = text(web.post(f"/admin/certs/{serial}/revoke", data={"reason": "keyCompromise"}, follow_redirects=True))
    assert f"Certificate {serial} revoked. CRL #1 published" in page
    assert "REVOKED" in page and "keyCompromise" in page and "Revoke this certificate" not in page

    with ca_app.app_context():
        row = get_db().execute("SELECT * FROM certificates WHERE serial_hex = ?", (serial,)).fetchone()
    assert row["status"] == "revoked" and row["revocation_reason"] == "keyCompromise" and row["revoked_at"]

    crl = load_crl(ca_app)
    assert crl.is_signature_valid(issuing_ca.cert.public_key())        # signed by the Issuing CA
    assert crl.issuer == issuing_ca.cert.subject
    assert crl_number(crl) == 1
    assert crl.next_update_utc - crl.last_update_utc == timedelta(days=7)
    aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    assert aki.key_identifier == issuing_ca.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    entry = crl.get_revoked_certificate_by_serial_number(int(serial, 16))
    assert entry.revocation_date_utc == ca_core.parse_iso(row["revoked_at"])
    assert entry.extensions.get_extension_for_class(x509.CRLReason).value.reason == x509.ReasonFlags.key_compromise
    der = x509.load_der_x509_crl((ca_app.config["CRL_DIR"] / "crl.der").read_bytes())
    assert der == crl                                                   # same CRL in both formats


def test_each_revocation_makes_a_new_crl_with_the_next_number(ca_app, web, keys):
    first = issue(ca_app, keys.rsa2048).serial_hex
    second = issue(ca_app, keys.rsa3072, ASHA, "code_signing").serial_hex
    web.post(f"/admin/certs/{first}/revoke", data={"reason": "superseded"})
    web.post(f"/admin/certs/{second}/revoke", data={"reason": "affiliationChanged"})

    crl = load_crl(ca_app)
    assert crl_number(crl) == 2
    reasons = {f"{e.serial_number:032x}": e.extensions.get_extension_for_class(x509.CRLReason).value.reason
               for e in crl}
    assert reasons == {first: x509.ReasonFlags.superseded, second: x509.ReasonFlags.affiliation_changed}


def test_bad_revocations_are_refused(ca_app, web, keys):
    serial = issue(ca_app, keys.rsa2048).serial_hex
    page = text(web.post(f"/admin/certs/{serial}/revoke", data={"reason": "because"}, follow_redirects=True))
    assert "Not revoked: choose a reason" in page
    web.post(f"/admin/certs/{serial}/revoke", data={"reason": "cessationOfOperation"})
    again = text(web.post(f"/admin/certs/{serial}/revoke", data={"reason": "keyCompromise"}, follow_redirects=True))
    assert "already revoked" in again
    assert crl_number(load_crl(ca_app)) == 1                            # no extra CRL for refused attempts
    with ca_app.app_context(), pytest.raises(ca_core.RevocationError, match="no certificate"):
        ca_core.revoke_certificate("0" * 32, "keyCompromise", "test")


def test_crl_routes_serve_pem_and_der_and_renew_an_old_crl(ca_app, web, issuing_ca, monkeypatch):
    first = web.get("/crl.pem")                                         # no CRL yet: an empty one is made
    assert first.status_code == 200 and first.mimetype == "application/x-pem-file"
    crl = x509.load_pem_x509_crl(first.data)
    assert crl_number(crl) == 1 and len(list(crl)) == 0 and crl.is_signature_valid(issuing_ca.cert.public_key())

    der = web.get("/crl.der")
    assert der.mimetype == "application/pkix-crl" and x509.load_der_x509_crl(der.data) == crl
    assert crl_number(x509.load_pem_x509_crl(web.get("/crl.pem").data)) == 1   # reused while still fresh

    later = ca_core.now_utc() + timedelta(days=8)                        # past nextUpdate
    monkeypatch.setattr(ca_core, "now_utc", lambda: later)
    assert crl_number(x509.load_pem_x509_crl(web.get("/crl.pem").data)) == 2


# ---------------------------------------------------------------- status API

def test_status_api_answers_good_revoked_expired_unknown(ca_app, web, keys):
    good = issue(ca_app, keys.rsa2048).serial_hex
    revoked = issue(ca_app, keys.rsa2048).serial_hex
    expired = issue(ca_app, keys.rsa2048).serial_hex
    web.post(f"/admin/certs/{revoked}/revoke", data={"reason": "keyCompromise"})
    set_not_after(ca_app, expired, ca_core.now_utc() - timedelta(days=1))

    answer = web.get(f"/api/status/{good}").get_json()
    assert answer["status"] == "good" and answer["revocation_time"] is None and answer["subject_cn"] == "Asha Rao"
    answer = web.get(f"/api/status/{revoked}").get_json()
    assert answer["status"] == "revoked" and answer["revocation_reason"] == "keyCompromise"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", answer["revocation_time"])
    assert web.get(f"/api/status/{expired}").get_json()["status"] == "expired"
    assert web.get("/api/status/" + "ab" * 16).get_json()["status"] == "unknown"
    assert web.get("/api/status/hello").get_json()["status"] == "unknown"

    openssl_style = ":".join(re.findall("..", good)).upper()
    assert web.get(f"/api/status/{openssl_style}").get_json()["status"] == "good"
    assert web.get(f"/api/status/0x{good.lstrip('0')}").get_json()["serial"] == good


# ---------------------------------------------------------------- audit log page and CSV

def test_audit_page_and_csv_export(ca_app, web, keys):
    serial = issue(ca_app, keys.rsa2048).serial_hex
    web.post(f"/admin/certs/{serial}/revoke", data={"reason": "superseded"})
    with ca_app.app_context():
        log_event("=HYPERLINK(\"http://evil\")", "TEST", None, "-2+3")    # spreadsheet formula injection attempt

    page = text(web.get("/admin/audit"))
    for action in ("CERT_ISSUED", "CERT_REVOKED", "CRL_PUBLISHED"):
        assert action in page
    assert "Export CSV" in page

    response = web.get("/admin/audit.csv")
    assert response.mimetype == "text/csv"
    assert "attachment; filename=audit_log.csv" in response.headers["Content-Disposition"]
    rows = list(csv.reader(io.StringIO(text(response))))
    assert rows[0] == ["id", "ts", "actor", "action", "target", "details"]
    assert [r[3] for r in rows[1:]] == ["CERT_ISSUED", "CERT_REVOKED", "CRL_PUBLISHED", "TEST"]
    assert rows[-1][2].startswith("'=") and rows[-1][5] == "'-2+3"           # made harmless


# ---------------------------------------------------------------- OCSP responder

def ask_ocsp(web, cert, issuer_cert, nonce=b"0123456789abcdef"):
    request = (ocsp.OCSPRequestBuilder().add_certificate(cert, issuer_cert, hashes.SHA1())
               .add_extension(x509.OCSPNonce(nonce), critical=False).build())
    response = web.post("/ocsp", data=request.public_bytes(serialization.Encoding.DER),
                        content_type="application/ocsp-request")
    assert response.mimetype == "application/ocsp-response"
    return ocsp.load_der_ocsp_response(response.data)


def test_ocsp_responder_says_good_then_revoked(ca_app, web, keys, issuing_ca):
    cert = issue(ca_app, keys.rsa2048).certificate

    answer = ask_ocsp(web, cert, issuing_ca.cert)
    assert answer.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
    assert answer.certificate_status == ocsp.OCSPCertStatus.GOOD
    assert answer.serial_number == cert.serial_number
    issuing_ca.cert.public_key().verify(answer.signature, answer.tbs_response_bytes,   # signed by the Issuing CA
                                        padding.PKCS1v15(), hashes.SHA256())
    nonce = answer.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
    assert nonce == b"0123456789abcdef"

    web.post(f"/admin/certs/{cert.serial_number:032x}/revoke", data={"reason": "keyCompromise"})
    answer = ask_ocsp(web, cert, issuing_ca.cert)
    assert answer.certificate_status == ocsp.OCSPCertStatus.REVOKED
    assert answer.revocation_reason == x509.ReasonFlags.key_compromise
    assert answer.revocation_time_utc is not None


def test_ocsp_responder_says_unknown_for_other_issuers_and_rejects_junk(ca_app, web, keys, demo_ca):
    cert = issue(ca_app, keys.rsa2048).certificate
    root = x509.load_pem_x509_certificate((demo_ca.ca_dir / "issuing" / "root-ca.crt").read_bytes())
    assert ask_ocsp(web, cert, root).certificate_status == ocsp.OCSPCertStatus.UNKNOWN   # wrong issuer named

    junk = web.post("/ocsp", data=b"not an ocsp request")
    assert ocsp.load_der_ocsp_response(junk.data).response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST


# ---------------------------------------------------------------- the applicant's view and the CLI

def test_request_status_page_shows_a_revoked_certificate(ca_app, web, keys):
    reply = web.post("/enroll?role=student", content_type="multipart/form-data", data={
        "role": "student", "template": "student_auth", "name": "Asha Rao", "email": "asha.rao@vit.ac.in",
        "reg_no": "21BCE0001",
        "csr_file": (io.BytesIO(make_csr(keys.rsa2048).public_bytes(serialization.Encoding.PEM)), "a.csr")})
    tracking_id = reply.headers["Location"].rsplit("/", 1)[1]
    web.post("/admin/requests/1/approve")
    with ca_app.app_context():
        serial = get_db().execute("SELECT serial_hex FROM certificates").fetchone()[0]
    web.post(f"/admin/certs/{serial}/revoke", data={"reason": "affiliationChanged"})

    page = text(web.get(f"/request/{tracking_id}"))
    assert "REVOKED" in page and "affiliationChanged" in page and "must not be trusted" in page


def test_cli_revoke(demo_ca, keys, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ISSUING_CA_PASS", demo_ca.issuing_pass.decode())
    csr_file = tmp_path / "x.csr"
    csr_file.write_bytes(make_csr(keys.rsa2048).public_bytes(serialization.Encoding.PEM))
    common = ["--ca-dir", str(tmp_path / "ca"), "--database", str(tmp_path / "cli.db")]
    shutil.copytree(demo_ca.ca_dir / "issuing", tmp_path / "ca" / "issuing")

    assert cli.main(["issue", *common, "--template", "student_auth", "--name", "Asha Rao",
                     "--email", "asha.rao@vit.ac.in", "--regno", "21BCE0001", "--csr", str(csr_file)]) == 0
    serial = re.search(r"serial\s+([0-9a-f]{32})", capsys.readouterr().out).group(1)

    assert cli.main(["revoke", *common, "--serial", serial.upper(), "--reason", "keyCompromise"]) == 0
    out = capsys.readouterr().out
    assert f"Certificate {serial} revoked (keyCompromise)" in out and "CRL #1 published: 1 revoked" in out
    crl = x509.load_pem_x509_crl((tmp_path / "ca" / "crl" / "crl.pem").read_bytes())
    assert crl.get_revoked_certificate_by_serial_number(int(serial, 16)) is not None

    assert cli.main(["revoke", *common, "--serial", serial, "--reason", "keyCompromise"]) == 1
    assert "already revoked" in capsys.readouterr().err
    assert cli.main(["revoke", *common, "--serial", "xyz", "--reason", "keyCompromise"]) == 1
