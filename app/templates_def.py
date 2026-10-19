"""The four certificate templates (report Section 5.2) and the role -> allowed templates matrix.

A template fixes everything about a certificate except WHO it is for: the key type and size,
the lifetime, KeyUsage, ExtendedKeyUsage and which SubjectAltName entries are added.
The CA applies the template; the applicant's CSR has no say in any of it.
"""
from dataclasses import dataclass

from cryptography.x509.oid import ExtendedKeyUsageOID


@dataclass(frozen=True)
class Template:
    name: str
    title: str                # shown to applicants on the enrollment form
    key_type: str             # "RSA" or "EC"
    rsa_bits: int             # minimum RSA key size (0 for the EC template, which requires P-256)
    days: int                 # validity period
    key_usage: tuple          # the KeyUsage bits that are switched on
    eku: object               # the one ExtendedKeyUsage purpose
    san_email: bool = False   # add SAN rfc822Name = the applicant's e-mail address
    san_dns: bool = False     # add SAN dNSName entries (and refuse to issue without any)


TEMPLATES = {t.name: t for t in (
    Template("student_auth", "Student login (TLS client authentication)",
             "RSA", 2048, 365, ("digital_signature",), ExtendedKeyUsageOID.CLIENT_AUTH),
    Template("faculty_email", "Faculty e-mail signing and encryption (S/MIME)",
             "RSA", 2048, 730, ("digital_signature", "key_encipherment"), ExtendedKeyUsageOID.EMAIL_PROTECTION,
             san_email=True),
    Template("server_tls", "TLS server certificate",
             "EC", 0, 365, ("digital_signature",), ExtendedKeyUsageOID.SERVER_AUTH,
             san_dns=True),
    Template("code_signing", "Code and document signing",
             "RSA", 3072, 730, ("digital_signature",), ExtendedKeyUsageOID.CODE_SIGNING),
)}

# Which templates each role may request.
ROLE_TEMPLATES = {
    "student": ("student_auth", "code_signing"),
    "faculty": ("faculty_email", "code_signing", "server_tls"),
}


def templates_for_role(role):
    """The templates this role may request, in display order."""
    return [TEMPLATES[name] for name in ROLE_TEMPLATES.get(role, ())]
