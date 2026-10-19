"""Core CA logic: load the Issuing CA and issue end-entity certificates.

issue_certificate() is the only place where a certificate is created. The command line
(app/cli.py) uses it, and from Phase 3 so does the RA's "Approve" button.

What the CA takes from the applicant, and what it does not:
  * from the CSR it uses ONLY the public key, and it checks the CSR's signature (proof that the
    applicant really holds the private key). The subject and any extensions the CSR asks for
    are ignored.
  * the subject comes from the identity data the RA verified;
  * every extension, and the lifetime, come from the template (app/templates_def.py).
"""
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from flask import current_app

from .audit import log_event
from .db import get_db
from .templates_def import TEMPLATES

SUBJECT_COUNTRY = "IN"
SUBJECT_ORG = "VIT"

# The names of the bits of the KeyUsage extension (the template lists the ones that are on).
KEY_USAGE_BITS = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
                  "key_agreement", "key_cert_sign", "crl_sign")

# What the RA-verified identity data may contain. Strict on purpose: these values end up inside a
# certificate, and the ASN.1 string types used for them only allow some characters.
NAME_RE = re.compile(r"[\w .'-]{1,64}")                       # letters of any language, digits, space . ' -
REG_NO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ./-]{0,31}")   # characters a PrintableString allows
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")
_DNS_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
DNS_RE = re.compile(rf"{_DNS_LABEL}(\.{_DNS_LABEL})*")

DN_LABELS = {NameOID.COUNTRY_NAME: "C", NameOID.ORGANIZATION_NAME: "O", NameOID.COMMON_NAME: "CN",
             NameOID.EMAIL_ADDRESS: "emailAddress", NameOID.SERIAL_NUMBER: "serialNumber"}


class IssuanceError(Exception):
    """The request cannot be turned into a certificate. The message is safe to show to the RA."""


@dataclass(frozen=True)
class Identity:
    """RA-verified facts about the applicant. These, not the CSR, go into the certificate."""
    name: str
    email: str
    reg_no: str
    dns_names: tuple = ()      # only for the server_tls template


@dataclass
class IssuingCA:
    """The online Issuing CA: its certificate and its (decrypted) private key."""
    cert: x509.Certificate
    key: Any


@dataclass
class IssuedCertificate:
    certificate: x509.Certificate
    serial_hex: str
    pem_path: Path
    db_id: int


# --------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------

def random_serial():
    """Random 128-bit serial number (never 0)."""
    return secrets.randbits(128) or 1


def now_utc():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(moment):
    """A time as text for the database, e.g. 2026-10-19T09:30:00Z."""
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def subject_text(name):
    """A subject in the order it is stored: C=IN, O=VIT, CN=..., emailAddress=..., serialNumber=..."""
    return ", ".join(f"{DN_LABELS.get(attr.oid, attr.oid.dotted_string)}={attr.value}" for attr in name)


def key_label(public_key):
    """Short description of a public key, such as RSA-2048 or EC-P256."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA-{public_key.key_size}"
    return "EC-" + {"secp256r1": "P256"}.get(public_key.curve.name, public_key.curve.name)


# --------------------------------------------------------------------------------------
# The Issuing CA
# --------------------------------------------------------------------------------------

def load_issuing_ca(issuing_dir, passphrase=None):
    """Read the Issuing CA certificate and key from issuing_dir.

    The passphrase comes from the ISSUING_CA_PASS environment variable (it is deliberately not kept
    in app.config). Reading an RSA-4096 key takes about a second, so callers load it once.
    """
    issuing_dir = Path(issuing_dir)
    cert_path, key_path = issuing_dir / "issuing-ca.crt", issuing_dir / "issuing-ca.key"
    if not cert_path.is_file() or not key_path.is_file():
        raise IssuanceError(f"no Issuing CA found in {issuing_dir}: run scripts/bootstrap_ca.py first")

    if passphrase is None:
        value = os.environ.get("ISSUING_CA_PASS")
        if not value:
            raise IssuanceError(
                "the Issuing CA key is locked: set the ISSUING_CA_PASS environment variable first\n"
                "  PowerShell:  $env:ISSUING_CA_PASS = '...'\n"
                "  Git Bash:    export ISSUING_CA_PASS='...'")
        passphrase = value.encode("utf-8")

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=passphrase)
    except (ValueError, TypeError):
        raise IssuanceError("ISSUING_CA_PASS does not unlock issuing-ca.key (wrong passphrase?)") from None
    if key.public_key().public_numbers() != cert.public_key().public_numbers():
        raise IssuanceError("issuing-ca.key does not belong to issuing-ca.crt")
    return IssuingCA(cert, key)


def get_issuing_ca():
    """The Issuing CA of this app: loaded on first use, then kept in memory."""
    ca = current_app.extensions.get("issuing_ca")
    if ca is None:
        ca = load_issuing_ca(current_app.config["ISSUING_DIR"])
        current_app.extensions["issuing_ca"] = ca
    return ca


# --------------------------------------------------------------------------------------
# Checking what the applicant sent
# --------------------------------------------------------------------------------------

def load_csr(data):
    """Read a certificate request given as PEM text or DER bytes."""
    try:
        return x509.load_pem_x509_csr(data)
    except ValueError:
        pass
    try:
        return x509.load_der_x509_csr(data)
    except ValueError:
        raise IssuanceError("that is not a readable certificate request (CSR) in PEM or DER format") from None


def check_csr(csr, template):
    """Proof of possession and key policy. Returns the key description, or raises IssuanceError."""
    try:
        signature_ok = csr.is_signature_valid
        key = csr.public_key()
    except (ValueError, UnsupportedAlgorithm):
        raise IssuanceError("unsupported CSR (only RSA and EC P-256 keys are accepted)") from None
    if not signature_ok:
        raise IssuanceError("the CSR signature is invalid: the applicant did not prove possession of the private key")

    if isinstance(key, rsa.RSAPublicKey):
        if template.key_type != "RSA":
            raise IssuanceError(f"template {template.name} needs an EC P-256 key, but the CSR has an RSA key")
        if key.key_size < template.rsa_bits:
            raise IssuanceError(f"RSA key too small: the CSR has {key.key_size} bits, "
                                f"template {template.name} needs at least {template.rsa_bits}")
    elif isinstance(key, ec.EllipticCurvePublicKey):
        if template.key_type != "EC":
            raise IssuanceError(f"template {template.name} needs an RSA key (at least {template.rsa_bits} bits), "
                                "but the CSR has an EC key")
        if key.curve.name != "secp256r1":
            raise IssuanceError(f"the EC key must use curve P-256 (secp256r1), the CSR uses {key.curve.name}")
    else:
        raise IssuanceError("unsupported public key type (only RSA and EC P-256 keys are accepted)")
    return key_label(key)


def check_identity(identity, template):
    """Validate the RA-verified identity data. Returns a cleaned copy, or raises IssuanceError."""
    name = " ".join(identity.name.split())            # trim and collapse white space
    email = identity.email.strip()
    reg_no = identity.reg_no.strip()
    if not NAME_RE.fullmatch(name) or not any(ch.isalpha() for ch in name):
        raise IssuanceError("the name must be 1-64 characters: letters, digits, spaces and . ' -")
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        raise IssuanceError(f"{email!r} is not a valid e-mail address")
    if not REG_NO_RE.fullmatch(reg_no):
        raise IssuanceError("the registration number must be 1-32 characters: letters, digits, space and . / -")

    dns_names = tuple(dict.fromkeys(host.strip().lower() for host in identity.dns_names))
    if template.san_dns:
        if not dns_names:
            raise IssuanceError(f"template {template.name} needs at least one DNS name (SAN dNSName)")
        for host in dns_names:
            if len(host) > 253 or not DNS_RE.fullmatch(host):
                raise IssuanceError(f"{host!r} is not a valid DNS name")
    elif dns_names:
        raise IssuanceError(f"DNS names are only used by the server_tls template, not {template.name}")
    return Identity(name, email, reg_no, dns_names)


# --------------------------------------------------------------------------------------
# Building the certificate
# --------------------------------------------------------------------------------------

def build_subject(identity):
    """C=IN, O=VIT, CN=<name>, emailAddress=<email>, serialNumber=<reg no> (in this order)."""
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, SUBJECT_COUNTRY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, SUBJECT_ORG),
        x509.NameAttribute(NameOID.COMMON_NAME, identity.name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, identity.email),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, identity.reg_no),
    ])


def authority_key_identifier(ca_cert):
    """AKI = the Issuing CA's Subject Key Identifier (worked out from its key if the CA has none)."""
    try:
        ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)


def build_certificate(ca, public_key, identity, template, crl_url):
    """Make and sign the certificate. Everything here comes from the template and the identity."""
    now = now_utc()
    if not ca.cert.not_valid_before_utc <= now <= ca.cert.not_valid_after_utc:
        raise IssuanceError("the Issuing CA certificate is not valid right now, so it cannot issue")
    # A certificate must not outlive the CA that signed it.
    not_after = min(now + timedelta(days=template.days), ca.cert.not_valid_after_utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(build_subject(identity))
        .issuer_name(ca.cert.subject)
        .public_key(public_key)
        .serial_number(random_serial())
        .not_valid_before(now)
        .not_valid_after(not_after)
        # CA:FALSE, critical: this certificate can never be used to sign other certificates.
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(**{bit: bit in template.key_usage for bit in KEY_USAGE_BITS},
                          encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(x509.ExtendedKeyUsage([template.eku]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(authority_key_identifier(ca.cert), critical=False)
        .add_extension(
            x509.CRLDistributionPoints([x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl_url)],
                relative_name=None, reasons=None, crl_issuer=None)]),
            critical=False)
    )

    alt_names = []
    if template.san_email:
        alt_names.append(x509.RFC822Name(identity.email))
    if template.san_dns:
        alt_names.extend(x509.DNSName(host) for host in identity.dns_names)
    if alt_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(alt_names), critical=False)

    return builder.sign(ca.key, hashes.SHA256())


# --------------------------------------------------------------------------------------
# Saving and the public entry point
# --------------------------------------------------------------------------------------

def save_certificate(cert, template, identity, key_description, request_id):
    """Write the PEM under ISSUED_DIR and record the certificate in the database - both or neither."""
    serial_hex = f"{cert.serial_number:032x}"
    issued_dir = Path(current_app.config["ISSUED_DIR"])
    pem_path = issued_dir / f"{serial_hex}.pem"
    db = get_db()
    created_file = False
    try:
        # The database row goes first: a duplicate serial fails here, before any file is touched.
        cursor = db.execute(
            "INSERT INTO certificates (serial_hex, request_id, template, subject_cn, subject_dn, email, reg_no,"
            " key_type, fingerprint_sha256, not_before, not_after, pem_path) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (serial_hex, request_id, template.name, identity.name, subject_text(cert.subject), identity.email,
             identity.reg_no, key_description, cert.fingerprint(hashes.SHA256()).hex(":").upper(),
             iso(cert.not_valid_before_utc), iso(cert.not_valid_after_utc), pem_path.name))
        issued_dir.mkdir(parents=True, exist_ok=True)
        with open(pem_path, "xb") as pem_file:       # "x": never overwrite an existing certificate file
            created_file = True
            pem_file.write(cert.public_bytes(serialization.Encoding.PEM))
        db.commit()
    except Exception:
        db.rollback()
        if created_file:
            pem_path.unlink(missing_ok=True)
        raise
    return IssuedCertificate(cert, serial_hex, pem_path, cursor.lastrowid)


def issue_certificate(csr, identity, template_name, request_id=None, actor="system"):
    """Issue one certificate: check, build, sign, save, log. Returns an IssuedCertificate.

    csr           the applicant's x509 certificate request (only its public key is used)
    identity      the RA-verified Identity (this becomes the subject)
    template_name one of TEMPLATES
    request_id    id of the request row in the database, when the certificate comes from the web workflow
    actor         who asked for it, for the audit log ('ra-admin', 'cli', ...)

    Raises IssuanceError when anything is wrong; nothing is saved in that case.
    """
    template = TEMPLATES.get(template_name)
    if template is None:
        raise IssuanceError(f"unknown template {template_name!r} (choose one of: {', '.join(TEMPLATES)})")
    identity = check_identity(identity, template)
    key_description = check_csr(csr, template)
    cert = build_certificate(get_issuing_ca(), csr.public_key(), identity, template, current_app.config["CRL_URL"])
    result = save_certificate(cert, template, identity, key_description, request_id)
    log_event(actor, "CERT_ISSUED", result.serial_hex, f"template={template.name}; subject={subject_text(cert.subject)}")
    return result


# --------------------------------------------------------------------------------------
# Demo mode ONLY: the server makes the applicant's key pair
# In a real PKI the private key is generated by the applicant and never leaves them;
# the CA only ever sees the CSR. These helpers exist so the demo works without OpenSSL.
# --------------------------------------------------------------------------------------

def generate_demo_key(template):
    """A key pair of the kind the template needs (RSA of the minimum size, or EC P-256)."""
    if template.key_type == "EC":
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=template.rsa_bits)


def demo_csr(key):
    """A CSR for a demo key. Its subject does not matter: the CA ignores it anyway."""
    return (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo mode")]))
            .sign(key, hashes.SHA256()))


def build_pkcs12(key, cert, chain, password, friendly_name):
    """A password-protected PKCS#12 (.p12) holding the private key, the certificate and the CA chain."""
    return pkcs12.serialize_key_and_certificates(
        friendly_name.encode("utf-8"), key, cert, chain, serialization.BestAvailableEncryption(password))


# --------------------------------------------------------------------------------------
# Certificate lifecycle: status, revocation and the CRL (Phase 4)
# --------------------------------------------------------------------------------------

# The revocation reasons the RA may choose (names as in RFC 5280), and their CRL codes.
REVOCATION_REASONS = {
    "keyCompromise": x509.ReasonFlags.key_compromise,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
    "affiliationChanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
}
CRL_VALID_DAYS = 7          # nextUpdate: relying parties must fetch a fresh CRL after this


class RevocationError(Exception):
    """The certificate cannot be revoked (unknown serial, bad reason, already revoked)."""


def parse_iso(text):
    """The opposite of iso(): '2026-10-19T09:30:00Z' -> a UTC datetime."""
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def normalize_serial(text):
    """Accept a serial the way people type it ('7A:4D:..', '0x7a4d..', with leading zeros or not)
    and return the 32-digit lowercase hex used in the database, or None if it is not a serial."""
    cleaned = text.strip().lower().replace(":", "").replace(" ", "")
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not re.fullmatch(r"[0-9a-f]{1,40}", cleaned):
        return None
    return f"{int(cleaned, 16):032x}"


def find_certificate(serial_hex):
    return get_db().execute("SELECT * FROM certificates WHERE serial_hex = ?", (serial_hex,)).fetchone()


def certificate_status(row, now=None):
    """'revoked', 'expired' or 'valid'. "Expired" is never stored: it follows from not_after and the clock."""
    if row["status"] == "revoked":
        return "revoked"
    if parse_iso(row["not_after"]) < (now or now_utc()):
        return "expired"
    return "valid"


def lookup_status(serial_text):
    """The OCSP-like answer for /api/status: good, revoked, expired or unknown."""
    serial_hex = normalize_serial(serial_text)
    row = find_certificate(serial_hex) if serial_hex else None
    if row is None:
        return {"serial": serial_text, "status": "unknown"}
    status = certificate_status(row)
    return {"serial": serial_hex, "status": "good" if status == "valid" else status,
            "revocation_time": row["revoked_at"], "revocation_reason": row["revocation_reason"],
            "not_after": row["not_after"], "subject_cn": row["subject_cn"]}


def revoke_certificate(serial_hex, reason, actor):
    """Mark a certificate revoked and publish a new CRL. Returns the new CRL."""
    if reason not in REVOCATION_REASONS:
        raise RevocationError(f"choose a reason: {', '.join(REVOCATION_REASONS)}")
    row = find_certificate(serial_hex)
    if row is None:
        raise RevocationError(f"no certificate with serial {serial_hex}")
    if row["status"] == "revoked":
        raise RevocationError(f"certificate {serial_hex} is already revoked")

    get_issuing_ca()        # unlock the CA key FIRST: if that fails, nothing has been changed yet
    db = get_db()
    db.execute("UPDATE certificates SET status = 'revoked', revoked_at = ?, revocation_reason = ? WHERE id = ?",
               (iso(now_utc()), reason, row["id"]))
    db.commit()
    log_event(actor, "CERT_REVOKED", serial_hex, reason)
    return publish_crl(actor)


def publish_crl(actor="system"):
    """Build, sign and save a fresh CRL that lists every revoked certificate. Returns it.

    Each CRL gets the next CRL number (kept in crl_number.txt) and is valid for CRL_VALID_DAYS.
    It is saved twice: crl.pem (text) and crl.der (binary, the usual format on the web).
    """
    ca = get_issuing_ca()
    crl_dir = Path(current_app.config["CRL_DIR"])
    crl_dir.mkdir(parents=True, exist_ok=True)
    number_file = crl_dir / "crl_number.txt"
    number = int(number_file.read_text()) + 1 if number_file.exists() else 1

    now = now_utc()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=CRL_VALID_DAYS))
        .add_extension(x509.CRLNumber(number), critical=False)
        .add_extension(authority_key_identifier(ca.cert), critical=False)
    )
    revoked = get_db().execute("SELECT serial_hex, revoked_at, revocation_reason FROM certificates"
                               " WHERE status = 'revoked' ORDER BY id").fetchall()
    for row in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(int(row["serial_hex"], 16))
            .revocation_date(parse_iso(row["revoked_at"]))
            .add_extension(x509.CRLReason(REVOCATION_REASONS[row["revocation_reason"]]), critical=False)
            .build())
    crl = builder.sign(ca.key, hashes.SHA256())

    (crl_dir / "crl.pem").write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    (crl_dir / "crl.der").write_bytes(crl.public_bytes(serialization.Encoding.DER))
    number_file.write_text(str(number))
    log_event(actor, "CRL_PUBLISHED", f"CRL #{number}",
              f"{len(revoked)} revoked certificate(s); next update {iso(now + timedelta(days=CRL_VALID_DAYS))}")
    return crl


def current_crl():
    """The published CRL. A new one is made if there is none yet, or the old one is past its nextUpdate."""
    path = Path(current_app.config["CRL_DIR"]) / "crl.pem"
    if path.exists():
        crl = x509.load_pem_x509_crl(path.read_bytes())
        if crl.next_update_utc > now_utc():
            return crl
    return publish_crl("system")


# --------------------------------------------------------------------------------------
# OCSP responder (stretch goal): the online, per-certificate version of the CRL
# --------------------------------------------------------------------------------------

def build_ocsp_response(request_der):
    """Answer a DER-encoded OCSP request with a response signed by the Issuing CA."""
    try:
        req = ocsp.load_der_ocsp_request(request_der)
    except ValueError:
        return ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

    ca = get_issuing_ca()
    now = now_utc()

    # Is the question about OUR CA? The request names the issuer by a hash of its name and key.
    name_hash = hashes.Hash(req.hash_algorithm)
    name_hash.update(ca.cert.subject.public_bytes())
    ca_key = ca.cert.public_key()
    key_bits = (ca_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
                if isinstance(ca_key, rsa.RSAPublicKey)
                else ca_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
    key_hash = hashes.Hash(req.hash_algorithm)
    key_hash.update(key_bits)
    ours = req.issuer_name_hash == name_hash.finalize() and req.issuer_key_hash == key_hash.finalize()

    row = find_certificate(f"{req.serial_number:032x}") if ours else None
    revocation_time = revocation_reason = None
    if row is None:
        cert_status = ocsp.OCSPCertStatus.UNKNOWN
    elif row["status"] == "revoked":
        cert_status = ocsp.OCSPCertStatus.REVOKED
        revocation_time = parse_iso(row["revoked_at"])
        revocation_reason = REVOCATION_REASONS[row["revocation_reason"]]
    else:
        cert_status = ocsp.OCSPCertStatus.GOOD

    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response_by_hash(
            issuer_name_hash=req.issuer_name_hash, issuer_key_hash=req.issuer_key_hash,
            serial_number=req.serial_number, algorithm=req.hash_algorithm, cert_status=cert_status,
            this_update=now, next_update=now + timedelta(days=1),
            revocation_time=revocation_time, revocation_reason=revocation_reason)
        .responder_id(ocsp.OCSPResponderEncoding.HASH, ca.cert)
    )
    for extension in req.extensions:                 # echo the nonce: proves the answer is fresh
        if isinstance(extension.value, x509.OCSPNonce):
            builder = builder.add_extension(extension.value, critical=False)
    return builder.sign(ca.key, hashes.SHA256())


# --------------------------------------------------------------------------------------
# Showing a certificate to people
# --------------------------------------------------------------------------------------

KEY_USAGE_NAMES = {"digital_signature": "Digital Signature", "content_commitment": "Non Repudiation",
                   "key_encipherment": "Key Encipherment", "data_encipherment": "Data Encipherment",
                   "key_agreement": "Key Agreement", "key_cert_sign": "Certificate Sign", "crl_sign": "CRL Sign"}
EKU_NAMES = {ExtendedKeyUsageOID.CLIENT_AUTH: "TLS client authentication (clientAuth)",
             ExtendedKeyUsageOID.SERVER_AUTH: "TLS server authentication (serverAuth)",
             ExtendedKeyUsageOID.EMAIL_PROTECTION: "E-mail protection (emailProtection)",
             ExtendedKeyUsageOID.CODE_SIGNING: "Code signing (codeSigning)"}


def describe_certificate(cert):
    """The fields of a certificate as readable text, for the detail page."""
    def ext(cls):
        try:
            return cert.extensions.get_extension_for_class(cls)
        except x509.ExtensionNotFound:
            return None

    basic, usage, eku, san, crl_points = (ext(x509.BasicConstraints), ext(x509.KeyUsage),
                                          ext(x509.ExtendedKeyUsage), ext(x509.SubjectAlternativeName),
                                          ext(x509.CRLDistributionPoints))
    alt_names = []
    if san:
        alt_names = ([f"email: {v}" for v in san.value.get_values_for_type(x509.RFC822Name)]
                     + [f"DNS: {v}" for v in san.value.get_values_for_type(x509.DNSName)])
    return {
        "Subject": subject_text(cert.subject),
        "Issuer": subject_text(cert.issuer),
        "Serial number": f"{cert.serial_number:032x}",
        "Valid from": iso(cert.not_valid_before_utc),
        "Valid until": iso(cert.not_valid_after_utc),
        "Public key": key_label(cert.public_key()),
        "Signature": f"{cert.signature_hash_algorithm.name.upper()} with the Issuing CA's key",
        "Basic constraints": (f"CA:{'TRUE' if basic.value.ca else 'FALSE'}"
                              + (" (critical)" if basic.critical else "")) if basic else "-",
        "Key usage": ", ".join(name for bit, name in KEY_USAGE_NAMES.items() if getattr(usage.value, bit))
                     + (" (critical)" if usage.critical else "") if usage else "-",
        "Extended key usage": ", ".join(EKU_NAMES.get(oid, oid.dotted_string) for oid in eku.value) if eku else "-",
        "Subject alternative names": ", ".join(alt_names) or "-",
        "CRL distribution point": ", ".join(uri.value for point in crl_points.value for uri in point.full_name)
                                  if crl_points else "-",
        "SHA-256 fingerprint": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
    }
