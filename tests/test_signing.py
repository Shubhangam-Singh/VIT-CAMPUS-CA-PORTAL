"""Phase 5 checks: signing files with a code_signing certificate and the five verification checks.

Besides the three checkpoint cases (all PASS / one byte changed / signer revoked) this tries the
attacks a signature scheme must survive: a rewritten hash, a forged CA chain with look-alike names,
a back- or forward-dated signed_at, a missing, stale or forged CRL, and non-code-signing certificates.
"""
import base64
import hashlib
import io
import json
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app import ca_core, signing
from app.ca_core import Identity, IssuingCA, build_certificate, build_pkcs12, issue_certificate
from app.db import get_db
from app.signing import SigningError, parse_signature_file, sign_bytes, sign_with_p12, to_json, verify_signature
from app.templates_def import TEMPLATES
from csr_factory import make_csr
from scripts import bootstrap_ca
from tools import sign_file, verify_file

RAVI = Identity("Ravi Kumar", "ravi.kumar@vit.ac.in", "21BCE0002")
DATA = b"%PDF-1.4\nVIT BCSE330L project report\n" * 50
P12_PASSWORD = "p12-test-password"


@pytest.fixture
def signer(ca_app, keys, issuing_ca, demo_ca):
    """A code-signing key + certificate from the demo CA, with everything needed to verify."""
    with ca_app.app_context():
        cert = issue_certificate(make_csr(keys.rsa3072), RAVI, "code_signing", actor="test").certificate
    root = x509.load_pem_x509_certificate((demo_ca.ca_dir / "issuing" / "root-ca.crt").read_bytes())
    return type("Signer", (), {"key": keys.rsa3072, "cert": cert, "chain": [issuing_ca.cert, root], "root": root})


def fresh_crl(ca_app):
    with ca_app.app_context():
        return ca_core.current_crl()


def verdicts(result):
    return [check.passed for check in result.checks]


# ---------------------------------------------------------------- the three checkpoint cases

def test_sign_then_verify_passes_all_five_checks(ca_app, signer):
    document = sign_bytes(DATA, "report.pdf", signer.key, signer.cert, signer.chain)
    assert set(document) == {"filename", "sha256", "algorithm", "signature", "signer_certificate", "chain", "signed_at"}
    assert document["algorithm"] == "RSASSA-PSS with SHA-256 (MGF1-SHA256, salt length 32)"
    assert len(document["chain"]) == 2

    result = verify_signature(DATA, parse_signature_file(to_json(document)), signer.root, fresh_crl(ca_app))
    assert verdicts(result) == [True] * 5 and result.passed
    assert result.signer["name"] == "Ravi Kumar" and result.signer["reg_no"] == "21BCE0002"
    assert result.signer["email"] == "ravi.kumar@vit.ac.in"
    assert result.signer["certificate_serial"] == f"{signer.cert.serial_number:032x}"


def test_changing_one_byte_fails_the_hash_check(ca_app, signer):
    document = sign_bytes(DATA, "report.pdf", signer.key, signer.cert, signer.chain)
    tampered = bytearray(DATA)
    tampered[100] ^= 0x01
    result = verify_signature(bytes(tampered), document, signer.root, fresh_crl(ca_app))
    assert verdicts(result) == [False, True, True, True, True]     # the signature still matches the SIGNED hash
    assert not result.passed and result.signer is None
    assert "the signature file says" in result.checks[0].detail


def test_revoking_the_signer_fails_the_revocation_check(ca_app, signer):
    document = sign_bytes(DATA, "report.pdf", signer.key, signer.cert, signer.chain)
    with ca_app.app_context():
        crl = ca_core.revoke_certificate(f"{signer.cert.serial_number:032x}", "keyCompromise", "test")
    result = verify_signature(DATA, document, signer.root, crl)
    assert verdicts(result) == [True, True, True, True, False]
    detail = result.checks[4].detail
    assert "REVOKED at" in detail and "keyCompromise" in detail and "signed_at" in detail and "never accepted" in detail


def test_signature_uses_exactly_the_published_parameters(signer):
    """Checked with an independent verifier, not the module's own constant: the documented
    `openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32` depends on these."""
    document = sign_bytes(DATA, "report.pdf", signer.key, signer.cert, signer.chain)
    published = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    signer.cert.public_key().verify(base64.b64decode(document["signature"]), DATA, published, hashes.SHA256())
    assert document["sha256"] == hashlib.sha256(DATA).hexdigest()


def test_a_signer_certificate_that_has_expired_since_fails_the_chain_check(ca_app, signer):
    document = sign_bytes(DATA, "report.pdf", signer.key, signer.cert, signer.chain)
    after_expiry = signer.cert.not_valid_after_utc + timedelta(days=1)
    result = verify_signature(DATA, document, signer.root, fresh_crl(ca_app), now=after_expiry)
    assert not result.checks[2].passed and "'Ravi Kumar' is not valid now" in result.checks[2].detail


# ---------------------------------------------------------------- attacks on the signature file

def test_rewriting_the_hash_to_match_a_changed_file_breaks_the_signature(ca_app, signer):
    document = sign_bytes(DATA, "report.pdf", signer.key, signer.cert, signer.chain)
    forged = DATA + b"one more line"
    document["sha256"] = hashlib.sha256(forged).hexdigest()
    result = verify_signature(forged, document, signer.root, fresh_crl(ca_app))
    assert verdicts(result)[:2] == [True, False] and not result.passed


def test_a_garbled_signature_value_fails(ca_app, signer):
    document = sign_bytes(DATA, "report.pdf", signer.key, signer.cert, signer.chain)
    document["signature"] = "not base64!!"
    assert verdicts(verify_signature(DATA, document, signer.root, fresh_crl(ca_app)))[1] is False


def test_a_forged_ca_with_look_alike_names_is_not_trusted(ca_app, keys, signer, monkeypatch):
    """An attacker builds their own "VIT Root CA" -> "VIT Issuing CA" and a code-signing cert for Ravi."""
    monkeypatch.setattr(bootstrap_ca, "KEY_BITS", 2048)
    fake = bootstrap_ca.generate_ca()
    fake_cert = build_certificate(IssuingCA(fake.issuing_cert, fake.issuing_key), keys.rsa3072.public_key(), RAVI,
                                  TEMPLATES["code_signing"], "http://localhost:5000/crl.pem")
    assert fake_cert.issuer == signer.cert.issuer                       # same names as the real CA...
    document = sign_bytes(DATA, "report.pdf", keys.rsa3072, fake_cert, [fake.issuing_cert, fake.root_cert])

    result = verify_signature(DATA, document, signer.root, fresh_crl(ca_app))
    assert verdicts(result)[:4] == [True, True, False, True]           # ...but no path to OUR root key
    assert "self-signed 'VIT Root CA' that is NOT our trusted" in result.checks[2].detail
    assert not result.checks[4].passed and "chain did not verify" in result.checks[4].detail


def test_a_different_trust_anchor_rejects_our_signatures(ca_app, keys, signer):
    other_root = bootstrap_ca.make_root_cert(keys.rsa2048)              # same name, different key
    document = sign_bytes(DATA, "report.pdf", signer.key, signer.cert, signer.chain)
    assert verdicts(verify_signature(DATA, document, other_root, fresh_crl(ca_app)))[2] is False


def test_a_chain_without_the_issuing_ca_cannot_be_built(ca_app, signer):
    document = sign_bytes(DATA, "report.pdf", signer.key, signer.cert, [signer.root])
    assert verdicts(verify_signature(DATA, document, signer.root, fresh_crl(ca_app)))[2] is False


def rogue_certificate(issuing_ca, key, common_name, ca, eku=None):
    """A certificate signed with the REAL Issuing CA key, but breaking the rules (made outside the CA code)."""
    now = ca_core.now_utc()
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
               .issuer_name(issuing_ca.cert.subject).public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now).not_valid_after(now + timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    return builder.sign(issuing_ca.key, hashes.SHA256())


def test_pathlen_0_stops_a_sub_ca_below_the_issuing_ca(ca_app, keys, signer, issuing_ca):
    """Even with the Issuing CA's key, nobody can create a working sub-CA: its pathlen is 0."""
    sub_ca = rogue_certificate(issuing_ca, keys.ec256, "Rogue Sub CA", ca=True)
    leaf = build_certificate(IssuingCA(sub_ca, keys.ec256), keys.rsa3072.public_key(), RAVI,
                             TEMPLATES["code_signing"], "http://localhost:5000/crl.pem")
    document = sign_bytes(DATA, "report.pdf", keys.rsa3072, leaf, [sub_ca] + signer.chain)
    result = verify_signature(DATA, document, signer.root, fresh_crl(ca_app))
    assert not result.checks[2].passed
    assert "'VIT Issuing CA' has pathlen 0, but the chain goes deeper" in result.checks[2].detail


def test_a_ca_certificate_cannot_be_the_signer(ca_app, keys, signer, issuing_ca):
    ca_signer = rogue_certificate(issuing_ca, keys.rsa3072, "Ravi Kumar", ca=True, eku=ExtendedKeyUsageOID.CODE_SIGNING)
    document = sign_bytes(DATA, "report.pdf", keys.rsa3072, ca_signer, signer.chain)
    result = verify_signature(DATA, document, signer.root, fresh_crl(ca_app))
    assert not result.checks[2].passed and "is a CA certificate" in result.checks[2].detail


def test_a_certificate_without_code_signing_fails_check_4(ca_app, keys, signer):
    with ca_app.app_context():
        student = issue_certificate(make_csr(keys.rsa2048), RAVI, "student_auth", actor="test").certificate
    document = sign_bytes(DATA, "report.pdf", keys.rsa2048, student, signer.chain)
    result = verify_signature(DATA, document, signer.root, fresh_crl(ca_app))
    assert verdicts(result) == [True, True, True, False, True]
    assert "no codeSigning" in result.checks[3].detail


@pytest.mark.parametrize("signed_at, message", [
    ("2000-01-01T00:00:00Z", "outside the certificate's validity"),
    ("2999-01-01T00:00:00Z", "in the future"),
    ("yesterday", "is not a time"),
])
def test_signed_at_must_be_a_sensible_time_inside_the_validity(ca_app, signer, signed_at, message):
    document = sign_bytes(DATA, "report.pdf", signer.key, signer.cert, signer.chain)
    document["signed_at"] = signed_at
    result = verify_signature(DATA, document, signer.root, fresh_crl(ca_app))
    assert not result.checks[3].passed and message in result.checks[3].detail


def test_revocation_check_fails_closed(ca_app, keys, signer, monkeypatch):
    document = sign_bytes(DATA, "report.pdf", signer.key, signer.cert, signer.chain)
    crl = fresh_crl(ca_app)

    no_crl = verify_signature(DATA, document, signer.root, None)
    assert not no_crl.checks[4].passed and "no CRL" in no_crl.checks[4].detail

    much_later = ca_core.now_utc() + timedelta(days=8)                  # CRL nextUpdate has passed
    stale = verify_signature(DATA, document, signer.root, crl, now=much_later)
    assert not stale.checks[4].passed and "out of date" in stale.checks[4].detail

    forged_crl = (x509.CertificateRevocationListBuilder().issuer_name(signer.chain[0].subject)
                  .last_update(ca_core.now_utc()).next_update(ca_core.now_utc() + timedelta(days=7))
                  .sign(keys.rsa2048, hashes.SHA256()))                 # right name, wrong key
    forged = verify_signature(DATA, document, signer.root, forged_crl)
    assert not forged.checks[4].passed and "not signed by the signer's CA" in forged.checks[4].detail


def test_revocation_detail_compares_revocation_time_with_signed_at(signer, ca_app):
    with ca_app.app_context():
        crl = ca_core.revoke_certificate(f"{signer.cert.serial_number:032x}", "superseded", "test")
    entry_time = crl.get_revoked_certificate_by_serial_number(signer.cert.serial_number).revocation_date_utc
    before = signing.check_revocation(signer.cert, signer.chain[0], crl, entry_time - timedelta(hours=1),
                                      entry_time)
    after = signing.check_revocation(signer.cert, signer.chain[0], crl, entry_time + timedelta(hours=1),
                                     entry_time + timedelta(hours=1))
    assert before[0] is False and "is before the revocation" in before[1]
    assert after[0] is False and "is after the revocation" in after[1]


def test_unreadable_certificates_fail_every_check_after_the_hash(ca_app, signer):
    document = sign_bytes(DATA, "report.pdf", signer.key, signer.cert, signer.chain)
    document["signer_certificate"] = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    assert verdicts(verify_signature(DATA, document, signer.root, fresh_crl(ca_app))) == [True] + [False] * 4


@pytest.mark.parametrize("text, message", [
    ("not json", "not valid JSON"),
    ("[1, 2]", "not a signature document"),
    ('{"filename": "x"}', "missing"),
    (json.dumps({"filename": "x", "sha256": "a", "algorithm": "a", "signature": "a", "signer_certificate": "a",
                 "chain": "not a list", "signed_at": "a"}), "chain must be a list"),
])
def test_bad_signature_files_are_refused(text, message):
    with pytest.raises(SigningError, match=message):
        parse_signature_file(text)


# ---------------------------------------------------------------- signing rules

def test_only_rsa_keys_that_match_the_certificate_can_sign(signer, keys):
    with pytest.raises(SigningError, match="needs an RSA key"):
        sign_bytes(DATA, "x", keys.ec256, signer.cert, [])
    with pytest.raises(SigningError, match="does not belong"):
        sign_bytes(DATA, "x", keys.rsa2048, signer.cert, [])


def test_sign_with_p12(ca_app, keys, signer):
    p12 = build_pkcs12(signer.key, signer.cert, signer.chain, P12_PASSWORD.encode(), "Ravi Kumar")
    document = sign_with_p12(DATA, "report.pdf", p12, P12_PASSWORD)
    assert len(document["chain"]) == 2                                  # the chain came out of the .p12
    assert verify_signature(DATA, document, signer.root, fresh_crl(ca_app)).passed

    bare = build_pkcs12(signer.key, signer.cert, [], P12_PASSWORD.encode(), "Ravi Kumar")
    assert sign_with_p12(DATA, "r", bare, P12_PASSWORD, signer.chain)["chain"]   # fallback chain used

    with pytest.raises(SigningError, match="wrong password"):
        sign_with_p12(DATA, "r", p12, "wrong")
    with ca_app.app_context():
        student = issue_certificate(make_csr(keys.rsa2048), RAVI, "student_auth", actor="test").certificate
    student_p12 = build_pkcs12(keys.rsa2048, student, signer.chain, P12_PASSWORD.encode(), "Ravi Kumar")
    with pytest.raises(SigningError, match="not a code-signing certificate"):
        sign_with_p12(DATA, "r", student_p12, P12_PASSWORD)


# ---------------------------------------------------------------- the command-line tools

def test_tools_sign_and_verify(ca_app, signer, tmp_path, monkeypatch, capsys):
    report = tmp_path / "report.pdf"
    report.write_bytes(DATA)
    p12 = tmp_path / "ravi.p12"
    p12.write_bytes(build_pkcs12(signer.key, signer.cert, signer.chain, P12_PASSWORD.encode(), "Ravi Kumar"))
    root_file = tmp_path / "root-ca.crt"
    root_file.write_bytes(signer.root.public_bytes(serialization.Encoding.PEM))
    crl_file = tmp_path / "crl.pem"
    crl_file.write_bytes(fresh_crl(ca_app).public_bytes(serialization.Encoding.PEM))
    verify_args = ["--file", str(report), "--root", str(root_file), "--crl", str(crl_file)]

    monkeypatch.setenv("P12_PASSWORD", P12_PASSWORD)
    assert sign_file.main(["--p12", str(p12), "--file", str(report)]) == 0
    out = capsys.readouterr().out
    assert (tmp_path / "report.pdf.sig.json").is_file() and "Signed report.pdf" in out
    assert "signer     Ravi Kumar (reg no 21BCE0002, ravi.kumar@vit.ac.in)" in out

    assert verify_file.main(verify_args) == 0
    out = capsys.readouterr().out
    assert out.count("PASS  ") == 5 and "RESULT: VALID - signed by Ravi Kumar (reg no 21BCE0002" in out

    report.write_bytes(DATA.replace(b"report", b"rep0rt", 1))         # change the file
    assert verify_file.main(verify_args) == 1
    out = capsys.readouterr().out
    assert "FAIL  1. File hash matches" in out and "RESULT: NOT VALID - failed check(s) 1" in out

    report.write_bytes(DATA)
    assert verify_file.main(["--file", str(report), "--root", str(root_file), "--crl", str(tmp_path / "none.pem")]) == 1
    assert "FAIL  5. Not revoked" in capsys.readouterr().out          # no CRL: never assume "not revoked"

    monkeypatch.setenv("P12_PASSWORD", "wrong")
    assert sign_file.main(["--p12", str(p12), "--file", str(report)]) == 1
    assert "wrong password" in capsys.readouterr().err


# ---------------------------------------------------------------- the web pages

def upload(web, url, files, **fields):
    """POST a form with file uploads. files = {field name: (bytes, file name)}."""
    data = dict(fields)
    for name, (content, filename) in files.items():
        data[name] = (io.BytesIO(content), filename)
    return web.post(url, data=data, content_type="multipart/form-data")


def test_sign_page_returns_a_signature_and_verify_page_shows_the_checks(ca_app, signer):
    web = ca_app.test_client()
    assert "DEMO ONLY" in web.get("/sign").get_data(as_text=True)
    p12 = build_pkcs12(signer.key, signer.cert, signer.chain, P12_PASSWORD.encode(), "Ravi Kumar")

    signed = upload(web, "/sign", {"p12_file": (p12, "ravi.p12"), "file": (DATA, "report.pdf")},
                    password=P12_PASSWORD)
    assert signed.status_code == 200 and signed.mimetype == "application/json"
    assert 'filename="report.pdf.sig.json"' in signed.headers["Content-Disposition"]
    sig = (signed.data, "report.pdf.sig.json")

    good = upload(web, "/verify", {"file": (DATA, "report.pdf"), "sig_file": sig})
    page = good.get_data(as_text=True)
    assert "VALID SIGNATURE" in page and page.count(">PASS<") == 5
    assert "Ravi Kumar" in page and "21BCE0002" in page and "ravi.kumar@vit.ac.in" in page

    bad = upload(web, "/verify", {"file": (DATA + b"!", "report.pdf"), "sig_file": sig})
    page = bad.get_data(as_text=True)
    assert "NOT VALID" in page and page.count(">FAIL<") == 1

    web.post(f"/admin/certs/{signer.cert.serial_number:032x}/revoke", data={"reason": "keyCompromise"})
    revoked = upload(web, "/verify", {"file": (DATA, "report.pdf"), "sig_file": sig})
    page = revoked.get_data(as_text=True)
    assert "NOT VALID" in page and "REVOKED at" in page

    refused = upload(web, "/sign", {"p12_file": (p12, "ravi.p12"), "file": (DATA, "report.pdf")},
                     password=P12_PASSWORD)
    assert refused.status_code == 400 and "this certificate was revoked" in refused.get_data(as_text=True)

    with ca_app.app_context():
        actions = [r[0] for r in get_db().execute("SELECT action FROM audit_log ORDER BY id")]
    assert "FILE_SIGNED" in actions and actions.count("FILE_VERIFIED") == 3


def test_sign_and_verify_pages_explain_problems(ca_app, signer):
    web = ca_app.test_client()
    p12 = build_pkcs12(signer.key, signer.cert, signer.chain, P12_PASSWORD.encode(), "Ravi Kumar")
    wrong = upload(web, "/sign", {"p12_file": (p12, "ravi.p12"), "file": (DATA, "report.pdf")}, password="nope")
    assert wrong.status_code == 400 and "wrong password" in wrong.get_data(as_text=True)
    missing = upload(web, "/sign", {"file": (DATA, "report.pdf")}, password=P12_PASSWORD)
    assert missing.status_code == 400
    junk = upload(web, "/verify", {"file": (DATA, "report.pdf"), "sig_file": (b"not json", "x.sig.json")})
    assert junk.status_code == 400 and "not valid JSON" in junk.get_data(as_text=True)
