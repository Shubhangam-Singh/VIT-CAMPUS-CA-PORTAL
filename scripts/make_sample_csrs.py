"""Make sample certificate requests (CSRs) to try the enrollment form with.

    python scripts/make_sample_csrs.py            (writes into demo_work/, which is git-ignored)

This plays the APPLICANT's side: each applicant makes their own key pair and sends only the CSR.
For every good sample the private key is saved next to it (in real life it would never leave the
applicant's computer), so you can later combine it with the issued certificate. The "bad_" samples show what the CA refuses.
"""
import argparse
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# file name -> (key to make, which template it fits)
GOOD = {
    "student_auth_rsa2048": ("rsa", 2048, "student_auth (students)"),
    "faculty_email_rsa2048": ("rsa", 2048, "faculty_email (faculty)"),
    "code_signing_rsa3072": ("rsa", 3072, "code_signing (students and faculty)"),
    "server_tls_ec_p256": ("ec", "P-256", "server_tls (faculty; also type a DNS name)"),
}


def make_key(kind, size):
    if kind == "ec":
        return ec.generate_private_key(ec.SECP384R1() if size == "P-384" else ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=size)


def make_csr(key, common_name):
    # The CA ignores this name on purpose: the certificate gets the RA-verified identity instead.
    return (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .sign(key, hashes.SHA256()))


def pem(csr):
    return csr.public_bytes(serialization.Encoding.PEM)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "demo_work", help="folder (default: demo_work/)")
    out = parser.parse_args().out
    out.mkdir(parents=True, exist_ok=True)

    print(f"Writing sample CSRs to {out}\n")
    for name, (kind, size, fits) in GOOD.items():
        key = make_key(kind, size)
        (out / f"{name}.key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (out / f"{name}.csr").write_bytes(pem(make_csr(key, "ignored by the CA")))
        print(f"  {name + '.csr':<30} fits {fits}")

    # Requests the CA must refuse.
    (out / "bad_rsa1024_too_small.csr").write_bytes(pem(make_csr(make_key("rsa", 1024), "too small")))
    (out / "bad_ec_p384_wrong_curve.csr").write_bytes(pem(make_csr(make_key("ec", "P-384"), "wrong curve")))
    der = bytearray(make_csr(make_key("rsa", 2048), "tampered").public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0x01                                   # flip one bit of the signature
    (out / "bad_signature_tampered.csr").write_bytes(pem(x509.load_der_x509_csr(bytes(der))))
    print("\n  bad_rsa1024_too_small.csr      refused: RSA key too small")
    print("  bad_ec_p384_wrong_curve.csr    refused: server_tls needs P-256")
    print("  bad_signature_tampered.csr     refused: CSR signature is invalid")
    print("\nThe .key files are the applicants' private keys: they never get uploaded.")


if __name__ == "__main__":
    main()
