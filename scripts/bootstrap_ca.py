"""Create the demo CA hierarchy: offline Root CA -> online Issuing CA.

    python scripts/bootstrap_ca.py

Passphrases come from environment variables, never from files or command-line arguments:
    ROOT_CA_PASS      encrypts the Root CA private key      (not needed when importing)
    ISSUING_CA_PASS   encrypts the Issuing CA private key

Two modes:
  generate (default)  make a brand-new Root CA and Issuing CA.
  import              if existing_ca/ holds root-ca.crt, issuing-ca.crt and issuing-ca.key,
                      use that CA instead. The Issuing CA key is saved again, encrypted with
                      ISSUING_CA_PASS. No Root CA key is needed: it stays wherever you keep it offline.

Layout created under ca/ (the whole folder is git-ignored):
    root_offline/   Root CA key + certificate   <- move this folder offline after setup
    issuing/        Issuing CA key, CSR, certificate, public copy of the Root certificate, chain.pem
    issued/         end-entity certificates (filled in Phase 2)
    crl/            certificate revocation list (filled in Phase 4)

The script is standalone on purpose: it plays the part of the offline "root key ceremony",
so it does not import the web application.
"""
import argparse
import os
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PROJECT_ROOT = Path(__file__).resolve().parent.parent

KEY_BITS = 4096
ROOT_DAYS = 7300      # about 20 years
ISSUING_DAYS = 3650   # about 10 years
COUNTRY = "IN"
ORG = "VIT-PKI"
ROOT_CN = "VIT Root CA"
ISSUING_CN = "VIT Issuing CA"

# If all three of these are in existing_ca/, the script imports that CA instead of generating one.
EXISTING_FILES = ("root-ca.crt", "issuing-ca.crt", "issuing-ca.key")

# Files this script creates (relative to the CA folder). If any already exists we refuse to run.
OUTPUT_FILES = (
    "root_offline/root-ca.key", "root_offline/root-ca.crt",
    "issuing/issuing-ca.key", "issuing/issuing-ca.csr", "issuing/issuing-ca.crt",
    "issuing/root-ca.crt", "issuing/chain.pem",
)


class BootstrapError(Exception):
    """A problem the user can fix: a missing passphrase, bad files in existing_ca/, ..."""


@dataclass
class CAMaterial:
    """The keys and certificates that get written out."""
    root_cert: x509.Certificate
    issuing_cert: x509.Certificate
    issuing_key: Any
    root_key: Any = None      # only when generated: an imported CA brings no Root key
    issuing_csr: Any = None   # only when generated


# --------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------

def ca_name(common_name):
    """Distinguished name of a CA: C=IN, O=VIT-PKI, CN=<common_name>."""
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def random_serial():
    """Random 128-bit certificate serial number (never 0)."""
    return secrets.randbits(128) or 1


def now_utc():
    return datetime.now(timezone.utc).replace(microsecond=0)


def ca_key_usage():
    """KeyUsage of a CA: it may sign certificates (keyCertSign) and CRLs (cRLSign), nothing else."""
    return x509.KeyUsage(
        digital_signature=False, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
        encipher_only=False, decipher_only=False,
    )


def get_ext(cert, ext_class):
    """The certificate's extension of this type, or None if it does not have one."""
    try:
        return cert.extensions.get_extension_for_class(ext_class)
    except x509.ExtensionNotFound:
        return None


def public_key_bytes(public_key):
    """A public key in a fixed encoding, so two keys can be compared."""
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def key_pem(private_key, passphrase):
    """A private key as PEM, encrypted (PKCS#8) with the passphrase."""
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase),
    )


def cert_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()


def write_file(path, data, secret=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if secret:
        # Owner-only on Linux/macOS. On Windows chmod can only toggle the read-only flag, so there
        # the permissions of your user profile folder are what protect the file.
        os.chmod(path, 0o600)


def shown(path):
    """A path relative to the project folder when possible (shorter to read)."""
    try:
        return path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(path)


# --------------------------------------------------------------------------------------
# Generate mode: new Root CA, then an Issuing CA whose CSR the Root signs
# --------------------------------------------------------------------------------------

def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)


def make_root_cert(root_key):
    """The self-signed Root CA certificate (issuer == subject)."""
    now = now_utc()
    name = ca_name(ROOT_CN)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(root_key.public_key())
        .serial_number(random_serial())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=ROOT_DAYS))
        # CA:TRUE with no path length limit: the Root may have CAs below it.
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(ca_key_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )


def make_issuing_csr(issuing_key):
    """The Issuing CA's certificate request: its name and public key, signed with its own key.

    In a real ceremony this CSR file travels (e.g. on a USB stick) to the offline Root.
    """
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(ca_name(ISSUING_CN))
        .sign(issuing_key, hashes.SHA256())
    )


def sign_issuing_csr(csr, root_cert, root_key):
    """What the offline Root does: check the CSR, then issue the Issuing CA certificate.

    The Root decides every extension itself; the CSR only supplies the name and public key.
    """
    if not csr.is_signature_valid:
        raise BootstrapError("the Issuing CA certificate request (CSR) has an invalid signature")
    now = now_utc()
    root_ski = get_ext(root_cert, x509.SubjectKeyIdentifier).value
    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_cert.subject)
        .public_key(csr.public_key())
        .serial_number(random_serial())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=ISSUING_DAYS))
        # pathlen:0 = this CA may sign end-entity certificates but may NOT create further CAs.
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ca_key_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        # AKI = the Root's SKI: tells verifiers which key signed this certificate.
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski), critical=False)
        .sign(root_key, hashes.SHA256())
    )


def generate_ca():
    print("[1/4] Root CA: generating its RSA-4096 key ...", flush=True)
    root_key = new_key()
    print(f"[2/4] Root CA: creating the self-signed Root certificate ({ROOT_DAYS} days) ...", flush=True)
    root_cert = make_root_cert(root_key)
    print("[3/4] Issuing CA: generating its RSA-4096 key and certificate request (CSR) ...", flush=True)
    issuing_key = new_key()
    issuing_csr = make_issuing_csr(issuing_key)
    print(f"[4/4] Root CA: signing the Issuing CA's CSR ({ISSUING_DAYS} days, pathlen 0) ...", flush=True)
    issuing_cert = sign_issuing_csr(issuing_csr, root_cert, root_key)
    return CAMaterial(root_cert, issuing_cert, issuing_key, root_key=root_key, issuing_csr=issuing_csr)


# --------------------------------------------------------------------------------------
# Import mode: use the CA files found in existing_ca/
# --------------------------------------------------------------------------------------

def load_certificate(path):
    """Load a certificate file (PEM, or DER as a fallback)."""
    data = path.read_bytes()
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        pass
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        raise BootstrapError(f"{path.name} is not a readable PEM or DER certificate") from None


def load_private_key(path, passphrase):
    """Load a PEM private key whether or not it is encrypted. Returns (key, was_encrypted)."""
    data = path.read_bytes()
    try:
        return serialization.load_pem_private_key(data, password=None), False
    except TypeError:
        pass   # "Password was not given but private key is encrypted": try the passphrase below
    except ValueError as err:
        raise BootstrapError(f"{path.name} is not a readable PEM private key ({err})") from None
    try:
        return serialization.load_pem_private_key(data, password=passphrase), True
    except ValueError:
        raise BootstrapError(
            f"{path.name} is encrypted and ISSUING_CA_PASS does not decrypt it.\n"
            "  Set ISSUING_CA_PASS to that key's CURRENT passphrase (it is reused for the copy in ca/issuing/)."
        ) from None


def import_existing(existing_dir, issuing_pass):
    root_cert = load_certificate(existing_dir / "root-ca.crt")
    issuing_cert = load_certificate(existing_dir / "issuing-ca.crt")
    issuing_key, was_encrypted = load_private_key(existing_dir / "issuing-ca.key", issuing_pass)
    if not was_encrypted:
        print(f"Note: {shown(existing_dir)}/issuing-ca.key is NOT encrypted. The copy in ca/issuing/ will be\n"
              "      encrypted with ISSUING_CA_PASS; delete the original once the demo works.")
    return CAMaterial(root_cert, issuing_cert, issuing_key)


def check_chain(ca):
    """Sanity-check the CA, whether it was just generated or imported.

    Raises BootstrapError for anything that would break certificate issuing.
    Returns a list of warnings for things that are odd but not fatal.
    """
    root, issuing = ca.root_cert, ca.issuing_cert
    warnings = []

    # The Root must be self-signed, and the Issuing CA certificate must be signed by it.
    try:
        root.verify_directly_issued_by(root)
    except (ValueError, TypeError, InvalidSignature):
        raise BootstrapError("root-ca.crt is not a self-signed Root CA certificate") from None
    try:
        issuing.verify_directly_issued_by(root)
    except (ValueError, TypeError, InvalidSignature):
        raise BootstrapError("issuing-ca.crt was NOT signed by root-ca.crt") from None

    # The private key must be the one that belongs to the Issuing CA certificate.
    if public_key_bytes(ca.issuing_key.public_key()) != public_key_bytes(issuing.public_key()):
        raise BootstrapError("issuing-ca.key does not belong to issuing-ca.crt (the public keys differ)")

    now = now_utc()
    for label, cert in (("Root", root), ("Issuing", issuing)):
        basic = get_ext(cert, x509.BasicConstraints)
        if basic is None or not basic.value.ca:
            raise BootstrapError(f"the {label} CA certificate is not a CA (BasicConstraints CA:TRUE is missing)")
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise BootstrapError(
                f"the {label} CA certificate is not valid right now "
                f"({cert.not_valid_before_utc:%Y-%m-%d} to {cert.not_valid_after_utc:%Y-%m-%d})"
            )
        usage = get_ext(cert, x509.KeyUsage)
        if usage is not None and not usage.value.key_cert_sign:
            raise BootstrapError(f"the {label} CA certificate's KeyUsage lacks keyCertSign, so nothing it signs would verify")

    usage = get_ext(issuing, x509.KeyUsage)
    if usage is None:
        warnings.append("the Issuing CA certificate has no KeyUsage extension (works, but is non-standard)")
    elif not usage.value.crl_sign:
        warnings.append("the Issuing CA certificate's KeyUsage lacks cRLSign: its CRLs will fail "
                        "`openssl verify -crl_check` (Phase 4)")
    path_length = get_ext(issuing, x509.BasicConstraints).value.path_length
    if path_length != 0:
        shown_length = "no limit" if path_length is None else path_length
        warnings.append(f"the Issuing CA certificate has pathlen {shown_length} instead of 0 (it could create sub-CAs)")
    return warnings


# --------------------------------------------------------------------------------------
# Writing the files and talking to the user
# --------------------------------------------------------------------------------------

def write_ca_files(ca_dir, ca, issuing_pass, root_pass):
    """Write everything under ca_dir. Returns [(path, description), ...] for the summary."""
    root_dir, issuing_dir = ca_dir / "root_offline", ca_dir / "issuing"
    written = []

    def save(path, data, what, secret=False):
        write_file(path, data, secret)
        written.append((path, what))

    if ca.root_key is not None:   # generated: the Root key lives in the folder that goes offline
        save(root_dir / "root-ca.key", key_pem(ca.root_key, root_pass),
             "Root CA private key, encrypted with ROOT_CA_PASS", secret=True)
        save(root_dir / "root-ca.crt", cert_pem(ca.root_cert), "Root CA certificate")
    save(issuing_dir / "issuing-ca.key", key_pem(ca.issuing_key, issuing_pass),
         "Issuing CA private key, encrypted with ISSUING_CA_PASS", secret=True)
    if ca.issuing_csr is not None:
        save(issuing_dir / "issuing-ca.csr", ca.issuing_csr.public_bytes(serialization.Encoding.PEM),
             "Issuing CA certificate request (what the Root signed)")
    save(issuing_dir / "issuing-ca.crt", cert_pem(ca.issuing_cert), "Issuing CA certificate, signed by the Root")
    save(issuing_dir / "root-ca.crt", cert_pem(ca.root_cert),
         "public copy of the Root certificate (the web app's trust anchor)")
    save(issuing_dir / "chain.pem", cert_pem(ca.issuing_cert) + cert_pem(ca.root_cert),
         "chain file: issuing-ca.crt + root-ca.crt")

    (ca_dir / "issued").mkdir(exist_ok=True)   # end-entity certificates (Phase 2)
    (ca_dir / "crl").mkdir(exist_ok=True)      # the CRL (Phase 4)
    return written


def print_summary(ca_dir, ca, written):
    print(f"\nCA folder: {shown(ca_dir)}")
    print("Files written (relative to the CA folder):")
    for path, what in written:
        print(f"  {path.relative_to(ca_dir).as_posix():<28} {what}")
    print(f"  {'issued/, crl/':<28} (empty for now)")
    print("\nSubjects and SHA-256 fingerprints:")
    print(f"  Root CA     {ca.root_cert.subject.rfc4514_string()}")
    print(f"              {fingerprint(ca.root_cert)}")
    print(f"  Issuing CA  {ca.issuing_cert.subject.rfc4514_string()}")
    print(f"              {fingerprint(ca.issuing_cert)}")

    if ca.root_key is not None:
        print(f"""
==============================================================================
 REMINDER: this folder holds the ROOT CA PRIVATE KEY:
   {shown(ca_dir / 'root_offline')}
 A real Root CA is created on an air-gapped machine and kept offline (safe, HSM
 or USB stick). Before you go live: copy that folder to an offline place, then
 DELETE it from this computer. The web app has no setting that points to it and
 never loads it; the Issuing CA works on its own from now on.
==============================================================================""")
    else:
        print("\nNo Root CA key was imported or created here: the Root key stays wherever you keep it offline.")


def detect_mode(existing_dir):
    """'import' if all of existing_ca/'s three files are there, 'generate' if none are."""
    found = [name for name in EXISTING_FILES if (existing_dir / name).is_file()]
    if not found:
        return "generate"
    if len(found) == len(EXISTING_FILES):
        return "import"
    missing = [name for name in EXISTING_FILES if name not in found]
    raise BootstrapError(
        f"{shown(existing_dir)} contains only part of an existing CA (found: {', '.join(found)}).\n"
        f"  Missing: {', '.join(missing)}. Add the missing file(s), or empty the folder to generate a new CA."
    )


def refuse_if_ca_exists(ca_dir):
    """Never overwrite a CA: a new one would make every certificate issued so far untrusted."""
    if any((ca_dir / name).exists() for name in OUTPUT_FILES):
        raise BootstrapError(
            f"a CA already exists in {ca_dir}.\n"
            "  Running again would create a NEW CA, and every certificate issued so far would stop verifying.\n"
            "  To start over on purpose, delete that folder yourself first:\n"
            f"    PowerShell:  Remove-Item -Recurse \"{ca_dir}\"\n"
            f"    Git Bash:    rm -rf \"{ca_dir}\""
        )


def bootstrap(ca_dir, existing_dir, issuing_pass, root_pass=None):
    """Create (or import) the CA under ca_dir. Returns "generated" or "imported"."""
    mode = detect_mode(existing_dir)
    refuse_if_ca_exists(ca_dir)

    if mode == "generate":
        if root_pass is None:
            raise BootstrapError("a Root CA passphrase is needed to generate a new CA")
        print(f"Mode: GENERATE a new demo CA ({shown(existing_dir)} has no CA files)")
        ca = generate_ca()
    else:
        print(f"Mode: IMPORT the existing CA found in {shown(existing_dir)}")
        ca = import_existing(existing_dir, issuing_pass)

    for warning in check_chain(ca):
        print(f"WARNING: {warning}", file=sys.stderr)
    print("Self-check: the Issuing CA certificate verifies against the Root CA certificate ... OK")

    written = write_ca_files(ca_dir, ca, issuing_pass, root_pass)
    print_summary(ca_dir, ca, written)
    return "generated" if mode == "generate" else "imported"


# --------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------

def read_passphrases(*names):
    """Passphrases come from environment variables only. Returns {name: bytes}."""
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        raise BootstrapError(
            "set the passphrase environment variable(s) first: " + ", ".join(missing) + "\n"
            f"  PowerShell:  $env:{missing[0]} = 'a passphrase you choose'\n"
            f"  Git Bash:    export {missing[0]}='a passphrase you choose'"
        )
    for name in names:
        if len(os.environ[name]) < 8:
            print(f"WARNING: {name} has fewer than 8 characters (fine for a demo, weak for real use)",
                  file=sys.stderr)
    return {name: os.environ[name].encode("utf-8") for name in names}


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Create the demo Root CA and Issuing CA, or import an existing CA from existing_ca/.")
    parser.add_argument("--ca-dir", type=Path, default=PROJECT_ROOT / "ca",
                        help="where to create the CA (default: ca/ in the project)")
    parser.add_argument("--existing-dir", type=Path, default=None,
                        help="where to look for an existing CA to import (default: existing_ca/)")
    args = parser.parse_args(argv)
    args.existing_dir_given = args.existing_dir is not None
    args.ca_dir = args.ca_dir.resolve()
    args.existing_dir = (args.existing_dir or PROJECT_ROOT / "existing_ca").resolve()
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        # The default existing_ca/ may simply not exist. But a folder you named yourself that is
        # missing is a typo, and silently generating a brand-new CA instead would be a nasty surprise.
        if args.existing_dir_given and not args.existing_dir.is_dir():
            raise BootstrapError(f"--existing-dir {args.existing_dir} is not a folder")
        mode = detect_mode(args.existing_dir)
        refuse_if_ca_exists(args.ca_dir)   # fail before asking for anything
        names = ("ISSUING_CA_PASS",) if mode == "import" else ("ROOT_CA_PASS", "ISSUING_CA_PASS")
        passphrases = read_passphrases(*names)
        if len(set(passphrases.values())) < len(passphrases):
            print("WARNING: ROOT_CA_PASS and ISSUING_CA_PASS are the same; use different ones in real life",
                  file=sys.stderr)
        bootstrap(args.ca_dir, args.existing_dir, passphrases["ISSUING_CA_PASS"], passphrases.get("ROOT_CA_PASS"))
    except BootstrapError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
