"""Phase 2 checks for app/ca_core.py.

What a certificate from each template must look like, what the CA must refuse,
and what a failure must never leave behind.
"""
import shutil
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app import ca_core
from app.ca_core import Identity, IssuanceError, IssuingCA, issue_certificate, load_csr
from app.db import get_db
from csr_factory import make_csr, tamper

GOOD = Identity("Asha Rao", "asha.rao@vit.ac.in", "21BCE0001")

IDENTITIES = {
    "student_auth": GOOD,
    "faculty_email": Identity("Dr. Meera Iyer", "meera.iyer@vit.ac.in", "FAC1001"),
    "server_tls": Identity("Lab Server", "labadmin@vit.ac.in", "SRV0001", ("lab1.vit.local", "www.lab1.vit.local")),
    "code_signing": Identity("Ravi Kumar", "ravi.kumar@vit.ac.in", "21BCE0002"),
}
KEY_FOR = {"student_auth": "rsa2048", "faculty_email": "rsa2048", "server_tls": "ec256", "code_signing": "rsa3072"}

# What the report (Section 5.2) says each template must produce.
EXPECTED = {
    "student_auth": dict(days=365, usage={"digital_signature"}, eku=ExtendedKeyUsageOID.CLIENT_AUTH, san=None,
                         key_type="RSA-2048"),
    "faculty_email": dict(days=730, usage={"digital_signature", "key_encipherment"},
                          eku=ExtendedKeyUsageOID.EMAIL_PROTECTION, san="email", key_type="RSA-2048"),
    "server_tls": dict(days=365, usage={"digital_signature"}, eku=ExtendedKeyUsageOID.SERVER_AUTH, san="dns",
                       key_type="EC-P256"),
    "code_signing": dict(days=730, usage={"digital_signature"}, eku=ExtendedKeyUsageOID.CODE_SIGNING, san=None,
                         key_type="RSA-3072"),
}


def key_usage_bits(cert):
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    bits = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
            "key_agreement", "key_cert_sign", "crl_sign")
    return {bit for bit in bits if getattr(usage, bit)}


def saved_so_far(ca_app):
    """(rows in the certificates table, certificate files in issued/): proves what a failure left behind."""
    with ca_app.app_context():
        rows = get_db().execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
    folder = Path(ca_app.config["ISSUED_DIR"])
    return rows, len(list(folder.glob("*.pem"))) if folder.exists() else 0


def make_test_ca(key, starts_in_days, ends_in_days):
    """A CA certificate (self-signed is enough here) valid from/until the given days from now."""
    now = ca_core.now_utc()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now + timedelta(days=starts_in_days)).not_valid_after(now + timedelta(days=ends_in_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return IssuingCA(cert, key)


# ---------------------------------------------------------------- what each template produces

@pytest.mark.parametrize("template_name", list(EXPECTED))
def test_each_template_produces_the_right_certificate(ca_app, keys, issuing_ca, template_name):
    want, identity = EXPECTED[template_name], IDENTITIES[template_name]
    applicant_key = getattr(keys, KEY_FOR[template_name])
    with ca_app.app_context():
        result = issue_certificate(make_csr(applicant_key), identity, template_name)
        row = get_db().execute("SELECT * FROM certificates").fetchone()
    cert = result.certificate

    # who the certificate is for, and who signed it
    assert cert.version == x509.Version.v3
    assert [(attr.oid, attr.value) for attr in cert.subject] == [
        (NameOID.COUNTRY_NAME, "IN"), (NameOID.ORGANIZATION_NAME, "VIT"), (NameOID.COMMON_NAME, identity.name),
        (NameOID.EMAIL_ADDRESS, identity.email), (NameOID.SERIAL_NUMBER, identity.reg_no)]
    assert cert.issuer == issuing_ca.cert.subject
    cert.verify_directly_issued_by(issuing_ca.cert)
    assert cert.public_key().public_numbers() == applicant_key.public_key().public_numbers()

    # serial number and lifetime
    assert 64 < cert.serial_number.bit_length() <= 128
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=want["days"])

    # extensions: exactly these, no others
    wanted_types = {x509.BasicConstraints, x509.KeyUsage, x509.ExtendedKeyUsage, x509.SubjectKeyIdentifier,
                    x509.AuthorityKeyIdentifier, x509.CRLDistributionPoints}
    if want["san"]:
        wanted_types.add(x509.SubjectAlternativeName)
    assert {type(ext.value) for ext in cert.extensions} == wanted_types

    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic.critical and basic.value.ca is False
    assert cert.extensions.get_extension_for_class(x509.KeyUsage).critical
    assert key_usage_bits(cert) == want["usage"]
    assert list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [want["eku"]]
    assert (cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            == x509.SubjectKeyIdentifier.from_public_key(applicant_key.public_key()))
    ca_ski = issuing_ca.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier == ca_ski.digest

    crl_points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    assert len(crl_points) == 1
    assert [uri.value for uri in crl_points[0].full_name] == ["http://localhost:5000/crl.pem"]

    if want["san"] == "email":
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert list(san) == [x509.RFC822Name(identity.email)]
    elif want["san"] == "dns":
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert list(san) == [x509.DNSName(host) for host in identity.dns_names]

    # saved as a file and as a database row
    assert x509.load_pem_x509_certificate(result.pem_path.read_bytes()) == cert
    assert result.pem_path == Path(ca_app.config["ISSUED_DIR"]) / f"{cert.serial_number:032x}.pem"
    assert (row["serial_hex"], row["template"], row["status"]) == (f"{cert.serial_number:032x}", template_name, "valid")
    assert (row["subject_cn"], row["email"], row["reg_no"]) == (identity.name, identity.email, identity.reg_no)
    assert row["subject_dn"] == ca_core.subject_text(cert.subject)
    assert row["key_type"] == want["key_type"]
    assert row["fingerprint_sha256"] == cert.fingerprint(hashes.SHA256()).hex(":").upper()
    assert row["pem_path"] == result.pem_path.name and row["request_id"] is None
    assert row["not_before"].endswith("Z") and row["not_after"].endswith("Z")


def test_csr_subject_and_requested_extensions_are_ignored(ca_app, keys):
    wants_everything = [
        (x509.BasicConstraints(ca=True, path_length=None), True),
        (x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                       data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                       encipher_only=False, decipher_only=False), True),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CODE_SIGNING]), False),
        (x509.SubjectAlternativeName([x509.DNSName("evil.example"), x509.RFC822Name("ceo@evil.example")]), False),
    ]
    csr = make_csr(keys.rsa2048, "Evil Admin", wants_everything)
    with ca_app.app_context():
        cert = issue_certificate(csr, GOOD, "student_auth").certificate

    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Asha Rao"
    assert "Evil" not in ca_core.subject_text(cert.subject)
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert key_usage_bits(cert) == {"digital_signature"}
    assert list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [
        ExtendedKeyUsageOID.CLIENT_AUTH]
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)


def test_serial_numbers_are_unique_and_random(ca_app, keys):
    with ca_app.app_context():
        serials = {issue_certificate(make_csr(keys.rsa2048), GOOD, "student_auth").certificate.serial_number
                   for _ in range(3)}
    assert len(serials) == 3


def test_request_id_is_recorded(ca_app, keys):
    with ca_app.app_context():
        db = get_db()
        db.execute("INSERT INTO requests (tracking_id, name, email, reg_no, role, template) "
                   "VALUES ('REQ-1', 'Asha Rao', 'asha.rao@vit.ac.in', '21BCE0001', 'student', 'student_auth')")
        db.commit()
        issue_certificate(make_csr(keys.rsa2048), GOOD, "student_auth", request_id=1)
        assert db.execute("SELECT request_id FROM certificates").fetchone()[0] == 1


# ---------------------------------------------------------------- key policy

def test_a_bigger_rsa_key_than_the_minimum_is_accepted(ca_app, keys):
    with ca_app.app_context():
        result = issue_certificate(make_csr(keys.rsa3072), GOOD, "student_auth")   # template minimum is 2048
        assert get_db().execute("SELECT key_type FROM certificates").fetchone()[0] == "RSA-3072"
    assert result.certificate.public_key().key_size == 3072


@pytest.mark.parametrize("template_name, key_name, message", [
    ("student_auth", "rsa1024", "too small"),
    ("faculty_email", "rsa1024", "too small"),
    ("code_signing", "rsa2048", "too small"),                 # code signing needs 3072
    ("server_tls", "rsa2048", "needs an EC P-256 key"),
    ("student_auth", "ec256", "needs an RSA key"),
    ("code_signing", "ec256", "needs an RSA key"),
    ("server_tls", "ec384", "P-256"),
    ("student_auth", "ed25519", "unsupported"),
])
def test_wrong_key_is_rejected_and_nothing_is_saved(ca_app, keys, template_name, key_name, message):
    identity = IDENTITIES[template_name]
    with ca_app.app_context(), pytest.raises(IssuanceError, match=message):
        issue_certificate(make_csr(getattr(keys, key_name)), identity, template_name)
    assert saved_so_far(ca_app) == (0, 0)


def test_bad_csr_signature_is_rejected_and_nothing_is_saved(ca_app, keys):
    good_csr = make_csr(keys.rsa2048)
    bad_csr = tamper(good_csr)
    assert good_csr.is_signature_valid and not bad_csr.is_signature_valid      # the tampering really breaks it
    with ca_app.app_context(), pytest.raises(IssuanceError, match="signature is invalid"):
        issue_certificate(bad_csr, GOOD, "student_auth")
    assert saved_so_far(ca_app) == (0, 0)


def test_unknown_template_is_rejected(ca_app, keys):
    with ca_app.app_context(), pytest.raises(IssuanceError, match="unknown template"):
        issue_certificate(make_csr(keys.rsa2048), GOOD, "root_ca")
    assert saved_so_far(ca_app) == (0, 0)


def test_bad_requests_are_rejected_before_the_ca_key_is_touched(app, keys):
    """`app` has no CA at all: validation must fail first, with its own message, not 'no Issuing CA found'."""
    with app.app_context():
        with pytest.raises(IssuanceError, match="signature is invalid"):
            issue_certificate(tamper(make_csr(keys.rsa2048)), GOOD, "student_auth")
        with pytest.raises(IssuanceError, match="too small"):
            issue_certificate(make_csr(keys.rsa1024), GOOD, "student_auth")


# ---------------------------------------------------------------- identity data

@pytest.mark.parametrize("identity, template_name, key_name, message", [
    (Identity("", "a@vit.ac.in", "21BCE0001"), "student_auth", "rsa2048", "name must be"),
    (Identity("A" * 65, "a@vit.ac.in", "21BCE0001"), "student_auth", "rsa2048", "name must be"),
    (Identity("Asha <b>Rao</b>", "a@vit.ac.in", "21BCE0001"), "student_auth", "rsa2048", "name must be"),
    (Identity("...", "a@vit.ac.in", "21BCE0001"), "student_auth", "rsa2048", "name must be"),
    (Identity("Asha Rao", "not-an-email", "21BCE0001"), "student_auth", "rsa2048", "not a valid e-mail"),
    (Identity("Asha Rao", "a@vit.ac.in", "bad_reg@no"), "student_auth", "rsa2048", "registration number"),
    (Identity("Asha Rao", "a@vit.ac.in", ""), "student_auth", "rsa2048", "registration number"),
    (Identity("Lab Server", "a@vit.ac.in", "S1"), "server_tls", "ec256", "at least one DNS name"),
    (Identity("Lab Server", "a@vit.ac.in", "S1", ("not a host",)), "server_tls", "ec256", "not a valid DNS name"),
    (Identity("Lab Server", "a@vit.ac.in", "S1", ("*.vit.local",)), "server_tls", "ec256", "not a valid DNS name"),
    (Identity("Asha Rao", "a@vit.ac.in", "21BCE0001", ("x.vit.local",)), "student_auth", "rsa2048",
     "only used by the server_tls"),
])
def test_bad_identity_data_is_rejected(ca_app, keys, identity, template_name, key_name, message):
    with ca_app.app_context(), pytest.raises(IssuanceError, match=message):
        issue_certificate(make_csr(getattr(keys, key_name)), identity, template_name)
    assert saved_so_far(ca_app) == (0, 0)


def test_identity_data_is_cleaned_before_it_goes_into_the_certificate(ca_app, keys):
    messy = Identity("  Ananya   Śarma ", " ananya@vit.ac.in ", " 21BCE0777 ")
    with ca_app.app_context():
        cert = issue_certificate(make_csr(keys.rsa2048), messy, "student_auth").certificate
    assert [attr.value for attr in cert.subject][2:] == ["Ananya Śarma", "ananya@vit.ac.in", "21BCE0777"]

    hosts = Identity("Lab Server", "a@vit.ac.in", "S1", ("LAB1.vit.local", "lab1.vit.local", " www.vit.local "))
    with ca_app.app_context():
        cert = issue_certificate(make_csr(keys.ec256), hosts, "server_tls").certificate
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["lab1.vit.local", "www.vit.local"]


# ---------------------------------------------------------------- the CA's own validity

def test_certificate_never_outlives_the_ca(ca_app, keys):
    short_ca = make_test_ca(keys.ec256, starts_in_days=-1, ends_in_days=100)
    ca_app.extensions["issuing_ca"] = short_ca
    with ca_app.app_context():
        cert = issue_certificate(make_csr(keys.rsa2048), GOOD, "student_auth").certificate   # asks for 365 days
    assert cert.not_valid_after_utc == short_ca.cert.not_valid_after_utc


@pytest.mark.parametrize("starts, ends", [(-10, -1), (1, 100)], ids=["expired", "not yet valid"])
def test_a_ca_that_is_not_valid_now_cannot_issue(ca_app, keys, starts, ends):
    ca_app.extensions["issuing_ca"] = make_test_ca(keys.ec256, starts, ends)
    with ca_app.app_context(), pytest.raises(IssuanceError, match="not valid right now"):
        issue_certificate(make_csr(keys.rsa2048), GOOD, "student_auth")
    assert saved_so_far(ca_app) == (0, 0)


# ---------------------------------------------------------------- failures must not leave a mess

def test_duplicate_serial_is_refused_before_any_file_is_written(ca_app, keys, monkeypatch):
    monkeypatch.setattr(ca_core, "random_serial", lambda: 0x1234)
    with ca_app.app_context():
        first = issue_certificate(make_csr(keys.rsa2048), GOOD, "student_auth")
        original = first.pem_path.read_bytes()
        with pytest.raises(sqlite3.IntegrityError):
            issue_certificate(make_csr(keys.rsa2048), GOOD, "student_auth")
    assert first.pem_path.read_bytes() == original            # the first certificate file is untouched
    assert saved_so_far(ca_app) == (1, 1)


def test_a_file_that_cannot_be_written_rolls_back_the_database_row(ca_app, keys, monkeypatch):
    monkeypatch.setattr(ca_core, "random_serial", lambda: 0x1234)
    issued = Path(ca_app.config["ISSUED_DIR"])
    issued.mkdir(parents=True)
    in_the_way = issued / f"{0x1234:032x}.pem"
    in_the_way.write_text("someone else's file")
    with ca_app.app_context():
        with pytest.raises(FileExistsError):
            issue_certificate(make_csr(keys.rsa2048), GOOD, "student_auth")
        # A caller that carries on after the error (e.g. to log it) will commit on this same connection:
        # the half-finished row must not slip in with that commit.
        db = get_db()
        db.commit()
        assert db.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 0
    assert in_the_way.read_text() == "someone else's file"    # never overwritten, never deleted
    assert saved_so_far(ca_app) == (0, 1)                     # no database row for it


# ---------------------------------------------------------------- reading CSRs

def test_load_csr_reads_pem_and_der_and_rejects_everything_else(keys):
    csr = make_csr(keys.rsa2048)
    assert load_csr(csr.public_bytes(serialization.Encoding.PEM)) == csr
    assert load_csr(csr.public_bytes(serialization.Encoding.DER)) == csr
    for junk in (b"", b"hello", b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"):
        with pytest.raises(IssuanceError, match="not a readable certificate request"):
            load_csr(junk)


# ---------------------------------------------------------------- the Issuing CA itself

def test_load_issuing_ca_reads_the_passphrase_from_the_environment(demo_ca, monkeypatch):
    monkeypatch.setenv("ISSUING_CA_PASS", demo_ca.issuing_pass.decode())
    ca = ca_core.load_issuing_ca(demo_ca.ca_dir / "issuing")
    assert ca.cert.subject.rfc4514_string() == "CN=VIT Issuing CA,O=VIT-PKI,C=IN"


def test_load_issuing_ca_problems_are_explained(demo_ca, tmp_path, monkeypatch):
    issuing = demo_ca.ca_dir / "issuing"
    monkeypatch.delenv("ISSUING_CA_PASS", raising=False)
    with pytest.raises(IssuanceError, match="ISSUING_CA_PASS"):
        ca_core.load_issuing_ca(issuing)
    monkeypatch.setenv("ISSUING_CA_PASS", "not the passphrase")
    with pytest.raises(IssuanceError, match="does not unlock"):
        ca_core.load_issuing_ca(issuing)
    with pytest.raises(IssuanceError, match="bootstrap_ca.py"):
        ca_core.load_issuing_ca(tmp_path / "no such folder")


def test_load_issuing_ca_rejects_a_key_that_does_not_match_the_certificate(demo_ca, tmp_path):
    folder = tmp_path / "issuing"
    shutil.copytree(demo_ca.ca_dir / "issuing", folder)
    shutil.copy(folder / "root-ca.crt", folder / "issuing-ca.crt")      # a certificate for some other key
    with pytest.raises(IssuanceError, match="does not belong"):
        ca_core.load_issuing_ca(folder, demo_ca.issuing_pass)


def test_the_issuing_ca_is_loaded_once_and_then_kept(app, issuing_ca, monkeypatch):
    calls = []

    def fake_load(issuing_dir):
        calls.append(issuing_dir)
        return issuing_ca

    monkeypatch.setattr(ca_core, "load_issuing_ca", fake_load)
    with app.app_context():
        assert ca_core.get_issuing_ca() is issuing_ca
        assert ca_core.get_issuing_ca() is issuing_ca
    assert calls == [app.config["ISSUING_DIR"]]
