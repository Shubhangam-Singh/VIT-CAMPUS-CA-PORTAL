"""Sign files with a code_signing certificate and verify the signatures (non-repudiation).

A signature is saved as <file>.sig.json:
    filename            name of the signed file
    sha256              SHA-256 of the file (hex)
    algorithm           how it was signed (see ALGORITHM)
    signature           the RSA-PSS signature (base64)
    signer_certificate  the signer's certificate (PEM)
    chain               the CA certificates above it (PEM list, untrusted: only used to build the path)
    signed_at           when the signer says they signed (UTC)

Signing = RSA-PSS over SHA-256(file). That is exactly what
    openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sign key.pem file
produces, so anyone can check our signatures with OpenSSL (see docs/VERIFY_WITH_OPENSSL.md).

Verifying = five independent checks, each PASS or FAIL (see verify_signature). The only thing we
trust is the VIT Root CA certificate; everything inside the .sig.json is treated as a claim.

This module has no Flask code, so tools/sign_file.py and tools/verify_file.py use it too.
"""
import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ALGORITHM = "RSASSA-PSS with SHA-256 (MGF1-SHA256, salt length 32)"
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
SIGNATURE_FIELDS = ("filename", "sha256", "algorithm", "signature", "signer_certificate", "chain", "signed_at")
CLOCK_SKEW = timedelta(minutes=5)     # tolerance for a signer's clock that is slightly ahead

CHECK_NAMES = (
    "1. File hash matches",
    "2. Signature is valid",
    "3. Certificate chains to the VIT Root CA",
    "4. Code-signing certificate, valid when signed",
    "5. Not revoked (current CRL)",
)


class SigningError(Exception):
    """Cannot sign, or the signature file is unreadable. The message is safe to show."""


def now_utc():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def common_name(cert_or_name):
    name = cert_or_name.subject if isinstance(cert_or_name, x509.Certificate) else cert_or_name
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[0].value if values else name.rfc4514_string()


def has_code_signing(cert):
    try:
        return ExtendedKeyUsageOID.CODE_SIGNING in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False


# --------------------------------------------------------------------------------------
# Signing
# --------------------------------------------------------------------------------------

def load_p12(p12_bytes, password):
    """Open a PKCS#12 file. Returns (private key, certificate, CA certificates inside it)."""
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(p12_bytes, password.encode("utf-8"))
    except ValueError:
        raise SigningError("could not open the .p12 file: wrong password, or not a PKCS#12 file") from None
    if key is None or cert is None:
        raise SigningError("the .p12 file must contain a private key and its certificate")
    return key, cert, list(extra or [])


def sign_bytes(data, filename, key, cert, chain, signed_at=None):
    """Sign `data` and return the signature document (a dict, saved as <file>.sig.json)."""
    if not isinstance(key, rsa.RSAPrivateKey):
        raise SigningError("RSA-PSS needs an RSA key (the code_signing template uses RSA-3072)")
    if key.public_key().public_numbers() != cert.public_key().public_numbers():
        raise SigningError("the private key does not belong to the certificate")

    digest = hashlib.sha256(data).digest()
    # Prehashed: we hand over SHA-256(file) instead of the file; the result is the same signature.
    signature = key.sign(digest, PSS, utils.Prehashed(hashes.SHA256()))
    return {
        "filename": filename,
        "sha256": digest.hex(),
        "algorithm": ALGORITHM,
        "signature": base64.b64encode(signature).decode("ascii"),
        "signer_certificate": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "chain": [c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in chain],
        "signed_at": iso(signed_at or now_utc()),
    }


def sign_with_p12(data, filename, p12_bytes, password, fallback_chain=()):
    """What the /sign page and tools/sign_file.py do: only code-signing certificates may sign.

    The CA chain normally comes from inside the .p12; fallback_chain is used when it has none.
    """
    key, cert, p12_chain = load_p12(p12_bytes, password)
    if not has_code_signing(cert):
        raise SigningError(f"the certificate of {common_name(cert)} is not a code-signing certificate "
                           "(its Extended Key Usage has no codeSigning)")
    return sign_bytes(data, filename, key, cert, p12_chain or list(fallback_chain))


def load_crl(data):
    """A CRL given as PEM or DER."""
    try:
        return x509.load_pem_x509_crl(data)
    except ValueError:
        return x509.load_der_x509_crl(data)


def to_json(document):
    return json.dumps(document, indent=2) + "\n"


def parse_signature_file(text):
    """Read a .sig.json file. Raises SigningError if it is not one of ours."""
    try:
        document = json.loads(text)
    except (ValueError, UnicodeDecodeError):
        raise SigningError("the signature file is not valid JSON") from None
    if not isinstance(document, dict):
        raise SigningError("the signature file is not a signature document")
    missing = [name for name in SIGNATURE_FIELDS if name not in document]
    if missing:
        raise SigningError(f"the signature file is missing: {', '.join(missing)}")
    if not isinstance(document["chain"], list) or not all(isinstance(c, str) for c in document["chain"]):
        raise SigningError("the signature file's chain must be a list of PEM certificates")
    if not all(isinstance(document[name], str) for name in SIGNATURE_FIELDS if name != "chain"):
        raise SigningError("the signature file has a field of the wrong type")
    return document


# --------------------------------------------------------------------------------------
# Verifying
# --------------------------------------------------------------------------------------

@dataclass
class Check:
    name: str
    passed: bool
    detail: str


@dataclass
class Verification:
    checks: list = field(default_factory=list)
    signer: dict = None              # who signed (only filled in when every check passed)

    @property
    def passed(self):
        return len(self.checks) == len(CHECK_NAMES) and all(check.passed for check in self.checks)


def issued_by(child, parent):
    """True if `parent` signed `child` (names match and the signature checks out)."""
    try:
        child.verify_directly_issued_by(parent)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def get_ext(cert, cls):
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def check_chain(leaf, untrusted, anchor, now):
    """Build and check the path leaf -> ... -> anchor by hand (RFC 5280 basics).

    Returns (issuer of the leaf or None, passed, detail). The certificates in the signature file are
    only used to FIND the path; trust comes from the anchor (our root-ca.crt) alone.
    """
    path, current = [leaf], leaf
    for _ in range(4):                                       # a real path here is 3 certificates long
        if issued_by(current, anchor):
            path.append(anchor)
            break
        if current is not leaf and issued_by(current, current):
            # A self-signed root that is not ours, typically a look-alike made by an attacker.
            return None, False, (f"the chain ends at a self-signed '{common_name(current)}' that is NOT our trusted "
                                 "VIT Root CA (same name, different key): no certificate signed by the VIT Root CA "
                                 "leads to the signer")
        parent = next((c for c in untrusted
                       if c is not current and c.subject == current.issuer and issued_by(current, c)), None)
        if parent is None:
            return None, False, (f"no certificate signed by the VIT Root CA leads to '{common_name(current)}'"
                                 f" (it claims issuer '{common_name(current.issuer)}')")
        path.append(parent)
        current = parent
    else:
        return None, False, "the chain is too long"

    for depth, cert in enumerate(path):
        name = common_name(cert)
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            return None, False, f"'{name}' is not valid now ({iso(cert.not_valid_before_utc)} to {iso(cert.not_valid_after_utc)})"
        basic = get_ext(cert, x509.BasicConstraints)
        if depth == 0:
            if basic is not None and basic.ca:
                return None, False, "the signer's certificate is a CA certificate, not an end-entity one"
            continue
        usage = get_ext(cert, x509.KeyUsage)
        if basic is None or not basic.ca or (usage is not None and not usage.key_cert_sign):
            return None, False, f"'{name}' is not allowed to sign certificates"
        if basic.path_length is not None and depth - 1 > basic.path_length:   # CAs below it vs its pathlen
            return None, False, f"'{name}' has pathlen {basic.path_length}, but the chain goes deeper"
    return path[1], True, " -> ".join(f"'{common_name(cert)}'" for cert in path) + " (trust anchor: root-ca.crt)"


def check_revocation(signer, issuer, crl, signed_at, now):
    """Is the signer's certificate on the issuer's current CRL? Returns (passed, detail)."""
    if issuer is None:
        return False, "cannot check: the chain did not verify, so it is unknown which CRL applies"
    if crl is None:
        return False, "no CRL available, so revocation cannot be ruled out"
    if crl.issuer != issuer.subject or not crl.is_signature_valid(issuer.public_key()):
        return False, "the CRL was not signed by the signer's CA"
    if crl.next_update_utc < now:
        return False, f"the CRL is out of date (its nextUpdate was {iso(crl.next_update_utc)})"
    number = get_ext(crl, x509.CRLNumber)
    label = f"CRL #{number.crl_number}" if number else "the CRL"
    entry = crl.get_revoked_certificate_by_serial_number(signer.serial_number)
    if entry is None:
        return True, f"not on {label} (published {iso(crl.last_update_utc)})"

    reason = get_ext(entry, x509.CRLReason)
    revoked_at = entry.revocation_date_utc
    when = "before" if signed_at and signed_at < revoked_at else "after"
    signed_text = iso(signed_at) if signed_at else "unknown"
    return False, (f"REVOKED at {iso(revoked_at)} (reason: {reason.reason.value if reason else 'unspecified'}). "
                   f"signed_at {signed_text} is {when} the revocation, but signed_at is only the signer's "
                   "own claim (there is no trusted timestamp), so a revoked certificate is never accepted")


def verify_signature(data, document, root_cert, crl, now=None):
    """Run the five checks on `data` against a parsed signature document."""
    now = now or now_utc()
    result = Verification()

    def add(passed, detail):
        """Record the next check (they are added in the order of CHECK_NAMES)."""
        result.checks.append(Check(CHECK_NAMES[len(result.checks)], passed, detail))

    # 1. The file is the one that was signed.
    actual = hashlib.sha256(data).hexdigest()
    claimed = document["sha256"].strip().lower()
    add(actual == claimed, f"SHA-256 of the file: {actual}" + ("" if actual == claimed
                                                              else f"; the signature file says: {claimed}"))

    try:
        signer = x509.load_pem_x509_certificate(document["signer_certificate"].encode("ascii"))
        untrusted = [x509.load_pem_x509_certificate(pem.encode("ascii")) for pem in document["chain"]]
    except (ValueError, UnicodeEncodeError):
        for _ in CHECK_NAMES[1:]:
            add(False, "the signer certificate or the chain in the signature file cannot be read")
        return result

    # 2. The signature was made over that hash by the private key of the certificate in the file.
    try:
        public_key = signer.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError("not an RSA key")
        public_key.verify(base64.b64decode(document["signature"], validate=True), bytes.fromhex(claimed),
                          PSS, utils.Prehashed(hashes.SHA256()))
        add(True, f"{ALGORITHM}, made with the key of '{common_name(signer)}'")
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        add(False, "the signature does not match the signer's public key and the stated SHA-256")

    # 3. That certificate really comes from our CA.
    issuer, chain_ok, chain_detail = check_chain(signer, untrusted, root_cert, now)
    add(chain_ok, chain_detail)

    # 4. It is a code-signing certificate, and it was valid at the time the signer says they signed.
    try:
        signed_at = datetime.strptime(document["signed_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        signed_at = None
    if not has_code_signing(signer):
        add(False, "the certificate's Extended Key Usage has no codeSigning")
    elif signed_at is None:
        add(False, f"signed_at {document['signed_at']!r} is not a time like 2026-10-19T09:30:00Z")
    elif signed_at > now + CLOCK_SKEW:
        add(False, f"signed_at {iso(signed_at)} is in the future")
    elif not signer.not_valid_before_utc <= signed_at <= signer.not_valid_after_utc:
        add(False, f"signed_at {iso(signed_at)} is outside the certificate's validity "
                   f"({iso(signer.not_valid_before_utc)} to {iso(signer.not_valid_after_utc)})")
    else:
        add(True, f"EKU includes codeSigning; signed_at {iso(signed_at)} is within "
                  f"{iso(signer.not_valid_before_utc)} to {iso(signer.not_valid_after_utc)}")

    # 5. It has not been revoked.
    add(*check_revocation(signer, issuer, crl, signed_at, now))

    if result.passed:
        result.signer = {
            "name": subject_value(signer, NameOID.COMMON_NAME),
            "reg_no": subject_value(signer, NameOID.SERIAL_NUMBER),
            "email": subject_value(signer, NameOID.EMAIL_ADDRESS),
            "certificate_serial": f"{signer.serial_number:032x}",
            "signed_at": iso(signed_at),
        }
    return result


def subject_value(cert, oid):
    """One field of the certificate's subject, e.g. the CN or the registration number ('-' if absent)."""
    values = cert.subject.get_attributes_for_oid(oid)
    return values[0].value if values else "-"
