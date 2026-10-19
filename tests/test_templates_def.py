"""Phase 2 checks for app/templates_def.py: the table from the report, Section 5.2."""
from cryptography.x509.oid import ExtendedKeyUsageOID

from app.templates_def import ROLE_TEMPLATES, TEMPLATES, templates_for_role


def test_the_four_templates_match_the_report():
    assert list(TEMPLATES) == ["student_auth", "faculty_email", "server_tls", "code_signing"]

    student = TEMPLATES["student_auth"]
    assert (student.key_type, student.rsa_bits, student.days) == ("RSA", 2048, 365)
    assert student.key_usage == ("digital_signature",) and student.eku == ExtendedKeyUsageOID.CLIENT_AUTH
    assert not student.san_email and not student.san_dns

    faculty = TEMPLATES["faculty_email"]
    assert (faculty.key_type, faculty.rsa_bits, faculty.days) == ("RSA", 2048, 730)
    assert faculty.key_usage == ("digital_signature", "key_encipherment")
    assert faculty.eku == ExtendedKeyUsageOID.EMAIL_PROTECTION
    assert faculty.san_email and not faculty.san_dns

    server = TEMPLATES["server_tls"]
    assert (server.key_type, server.days) == ("EC", 365)
    assert server.key_usage == ("digital_signature",) and server.eku == ExtendedKeyUsageOID.SERVER_AUTH
    assert server.san_dns and not server.san_email

    code = TEMPLATES["code_signing"]
    assert (code.key_type, code.rsa_bits, code.days) == ("RSA", 3072, 730)
    assert code.key_usage == ("digital_signature",) and code.eku == ExtendedKeyUsageOID.CODE_SIGNING
    assert not code.san_email and not code.san_dns


def test_role_matrix():
    assert ROLE_TEMPLATES == {
        "student": ("student_auth", "code_signing"),
        "faculty": ("faculty_email", "code_signing", "server_tls"),
    }
    assert [t.name for t in templates_for_role("student")] == ["student_auth", "code_signing"]
    assert [t.name for t in templates_for_role("faculty")] == ["faculty_email", "code_signing", "server_tls"]
    assert templates_for_role("janitor") == []
    assert all(name in TEMPLATES for names in ROLE_TEMPLATES.values() for name in names)
