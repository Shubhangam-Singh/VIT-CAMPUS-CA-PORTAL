"""Helpers that build certificate requests for the tests: the applicant's side of the story."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID


def make_csr(key, common_name="ignored by the CA", extensions=()):
    """A CSR for `key`. `extensions` is a list of (extension, critical) the applicant would like to get."""
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical)
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(key, algorithm)


def tamper(csr):
    """The same CSR with one bit of its signature flipped (the signature is the last thing in the file)."""
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0x01
    return x509.load_der_x509_csr(bytes(der))
