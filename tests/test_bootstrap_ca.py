"""Phase 1 checks for scripts/bootstrap_ca.py.

It must build a Root + Issuing CA with exactly the designed properties, import an existing CA
safely, refuse to overwrite a CA, and keep the Root key inside root_offline/.
"""
import hashlib
import subprocess
import sys
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from scripts import bootstrap_ca
from scripts.bootstrap_ca import BootstrapError

IMPORT_PASS = b"passphrase-for-the-import-tests"


def load_cert(path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def ext(cert, ext_class):
    return cert.extensions.get_extension_for_class(ext_class)


def key_usages(cert):
    """The KeyUsage bits that are switched on."""
    usage = ext(cert, x509.KeyUsage).value
    bits = ("digital_signature", "content_commitment", "key_encipherment",
            "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign")
    return {bit for bit in bits if getattr(usage, bit)}


def extension_types(cert):
    return {type(e.value) for e in cert.extensions}


@pytest.fixture
def root_cert(demo_ca):
    return load_cert(demo_ca.ca_dir / "root_offline" / "root-ca.crt")


@pytest.fixture
def issuing_cert(demo_ca):
    return load_cert(demo_ca.ca_dir / "issuing" / "issuing-ca.crt")


# ---------------------------------------------------------------- generate mode

def test_expected_files_exist(demo_ca):
    for name in ("root_offline/root-ca.key", "root_offline/root-ca.crt",
                 "issuing/issuing-ca.key", "issuing/issuing-ca.csr", "issuing/issuing-ca.crt",
                 "issuing/root-ca.crt", "issuing/chain.pem"):
        assert (demo_ca.ca_dir / name).is_file(), name
    assert (demo_ca.ca_dir / "issued").is_dir()
    assert (demo_ca.ca_dir / "crl").is_dir()


def test_root_certificate(root_cert):
    assert root_cert.version == x509.Version.v3
    assert root_cert.subject == root_cert.issuer                      # self-signed
    assert root_cert.subject.rfc4514_string() == "CN=VIT Root CA,O=VIT-PKI,C=IN"
    assert isinstance(root_cert.public_key(), rsa.RSAPublicKey)
    assert root_cert.public_key().key_size == 4096
    assert root_cert.signature_hash_algorithm.name == "sha256"
    assert root_cert.not_valid_after_utc - root_cert.not_valid_before_utc == timedelta(days=7300)

    basic = ext(root_cert, x509.BasicConstraints)
    assert basic.critical and basic.value.ca and basic.value.path_length is None
    assert ext(root_cert, x509.KeyUsage).critical
    assert key_usages(root_cert) == {"key_cert_sign", "crl_sign"}
    assert extension_types(root_cert) == {x509.BasicConstraints, x509.KeyUsage, x509.SubjectKeyIdentifier}
    root_cert.verify_directly_issued_by(root_cert)                     # signature checks out


def test_issuing_certificate(root_cert, issuing_cert):
    assert issuing_cert.version == x509.Version.v3
    assert issuing_cert.issuer == root_cert.subject
    assert issuing_cert.subject.rfc4514_string() == "CN=VIT Issuing CA,O=VIT-PKI,C=IN"
    assert isinstance(issuing_cert.public_key(), rsa.RSAPublicKey)
    assert issuing_cert.public_key().key_size == 4096
    assert issuing_cert.signature_hash_algorithm.name == "sha256"
    assert issuing_cert.not_valid_after_utc - issuing_cert.not_valid_before_utc == timedelta(days=3650)

    basic = ext(issuing_cert, x509.BasicConstraints)
    assert basic.critical and basic.value.ca and basic.value.path_length == 0   # pathlen:0
    assert ext(issuing_cert, x509.KeyUsage).critical
    assert key_usages(issuing_cert) == {"key_cert_sign", "crl_sign"}

    ski = ext(issuing_cert, x509.SubjectKeyIdentifier).value
    assert ski == x509.SubjectKeyIdentifier.from_public_key(issuing_cert.public_key())
    aki = ext(issuing_cert, x509.AuthorityKeyIdentifier).value
    assert aki.key_identifier == ext(root_cert, x509.SubjectKeyIdentifier).value.digest   # AKI = Root's SKI
    assert extension_types(issuing_cert) == {x509.BasicConstraints, x509.KeyUsage,
                                             x509.SubjectKeyIdentifier, x509.AuthorityKeyIdentifier}
    issuing_cert.verify_directly_issued_by(root_cert)                  # signed by the Root


def test_issuing_csr_matches_the_certificate(demo_ca, issuing_cert):
    csr = x509.load_pem_x509_csr((demo_ca.ca_dir / "issuing" / "issuing-ca.csr").read_bytes())
    assert csr.is_signature_valid
    assert csr.subject == issuing_cert.subject
    assert csr.public_key().public_numbers() == issuing_cert.public_key().public_numbers()


def test_serial_numbers_are_random_128_bit(root_cert, issuing_cert):
    for cert in (root_cert, issuing_cert):
        assert 64 < cert.serial_number.bit_length() <= 128
    assert root_cert.serial_number != issuing_cert.serial_number


def test_private_keys_are_encrypted_with_their_own_passphrases(demo_ca):
    load = serialization.load_pem_private_key
    for name, right, wrong in (("root_offline/root-ca.key", demo_ca.root_pass, demo_ca.issuing_pass),
                               ("issuing/issuing-ca.key", demo_ca.issuing_pass, demo_ca.root_pass)):
        data = (demo_ca.ca_dir / name).read_bytes()
        assert data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
        with pytest.raises(TypeError):        # no passphrase
            load(data, password=None)
        with pytest.raises(ValueError):       # the other CA's passphrase
            load(data, password=wrong)
        assert load(data, password=right).key_size == 4096


def test_root_key_exists_only_in_root_offline(demo_ca):
    keys = sorted(p.relative_to(demo_ca.ca_dir).as_posix() for p in demo_ca.ca_dir.rglob("*.key"))
    assert keys == ["issuing/issuing-ca.key", "root_offline/root-ca.key"]
    root_key_pem = (demo_ca.ca_dir / "root_offline" / "root-ca.key").read_bytes()
    for path in (demo_ca.ca_dir / "issuing").iterdir():
        assert root_key_pem not in path.read_bytes(), path.name


def test_chain_file_and_public_root_copy(demo_ca, root_cert, issuing_cert):
    chain = x509.load_pem_x509_certificates((demo_ca.ca_dir / "issuing" / "chain.pem").read_bytes())
    assert chain == [issuing_cert, root_cert]                          # issuing first, then root
    assert load_cert(demo_ca.ca_dir / "issuing" / "root-ca.crt") == root_cert


@pytest.fixture
def empty_existing_dir(tmp_path):
    """An existing_ca/ folder with nothing in it, so the script generates a new CA."""
    folder = tmp_path / "empty_existing_ca"
    folder.mkdir()
    return folder


def test_refuses_to_overwrite_an_existing_ca(demo_ca, empty_existing_dir, capsys):
    def snapshot():
        return {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in demo_ca.ca_dir.rglob("*") if p.is_file()}

    before = snapshot()
    with pytest.raises(BootstrapError, match="already exists"):
        bootstrap_ca.bootstrap(demo_ca.ca_dir, empty_existing_dir, demo_ca.issuing_pass, demo_ca.root_pass)
    assert bootstrap_ca.main(["--ca-dir", str(demo_ca.ca_dir), "--existing-dir", str(empty_existing_dir)]) == 1
    assert "already exists" in capsys.readouterr().err
    assert snapshot() == before                                         # nothing was touched


def test_main_needs_passphrases_and_creates_nothing_without_them(tmp_path, empty_existing_dir, monkeypatch, capsys):
    monkeypatch.delenv("ROOT_CA_PASS", raising=False)
    monkeypatch.delenv("ISSUING_CA_PASS", raising=False)
    ca_dir = tmp_path / "ca"
    assert bootstrap_ca.main(["--ca-dir", str(ca_dir), "--existing-dir", str(empty_existing_dir)]) == 1
    err = capsys.readouterr().err
    assert "ROOT_CA_PASS" in err and "ISSUING_CA_PASS" in err
    assert not ca_dir.exists()


def test_main_generates_a_ca_from_environment_variables(tmp_path, empty_existing_dir, monkeypatch):
    monkeypatch.setenv("ROOT_CA_PASS", "env-root-passphrase")
    monkeypatch.setenv("ISSUING_CA_PASS", "env-issuing-passphrase")
    ca_dir = tmp_path / "ca"
    assert bootstrap_ca.main(["--ca-dir", str(ca_dir), "--existing-dir", str(empty_existing_dir)]) == 0
    data = (ca_dir / "issuing" / "issuing-ca.key").read_bytes()
    assert serialization.load_pem_private_key(data, password=b"env-issuing-passphrase").key_size == 4096


def test_an_existing_dir_you_name_must_exist(tmp_path, monkeypatch, capsys):
    """A typo in --existing-dir must not silently turn into 'generate a brand-new CA'."""
    monkeypatch.setenv("ROOT_CA_PASS", "env-root-passphrase")
    monkeypatch.setenv("ISSUING_CA_PASS", "env-issuing-passphrase")
    ca_dir = tmp_path / "ca"
    assert bootstrap_ca.main(["--ca-dir", str(ca_dir), "--existing-dir", str(tmp_path / "typo")]) == 1
    assert "is not a folder" in capsys.readouterr().err
    assert not ca_dir.exists()


def test_script_runs_as_a_program():
    result = subprocess.run([sys.executable, bootstrap_ca.__file__, "--help"],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0
    assert "--ca-dir" in result.stdout and "--existing-dir" in result.stdout


# ---------------------------------------------------------------- import mode

@pytest.fixture
def fast_keys(monkeypatch):
    """2048-bit keys for tests that only exercise validation logic (4096-bit generation is slow and variable)."""
    monkeypatch.setattr(bootstrap_ca, "KEY_BITS", 2048)


def write_existing(folder, root_cert, issuing_cert, issuing_key_pem):
    folder.mkdir(exist_ok=True)
    (folder / "root-ca.crt").write_bytes(bootstrap_ca.cert_pem(root_cert))
    (folder / "issuing-ca.crt").write_bytes(bootstrap_ca.cert_pem(issuing_cert))
    (folder / "issuing-ca.key").write_bytes(issuing_key_pem)


@pytest.fixture
def existing_ca(demo_ca, tmp_path):
    """An existing_ca/ folder holding a copy of the generated CA (the key stays encrypted)."""
    folder = tmp_path / "existing_ca"
    folder.mkdir()
    for name in ("root-ca.crt", "issuing-ca.crt", "issuing-ca.key"):
        (folder / name).write_bytes((demo_ca.ca_dir / "issuing" / name).read_bytes())
    return folder


def load_issuing_key(ca_dir, passphrase):
    return serialization.load_pem_private_key((ca_dir / "issuing" / "issuing-ca.key").read_bytes(), passphrase)


def test_import_encrypted_key(demo_ca, existing_ca, tmp_path):
    ca_dir = tmp_path / "ca"
    assert bootstrap_ca.bootstrap(ca_dir, existing_ca, issuing_pass=demo_ca.issuing_pass) == "imported"

    assert not (ca_dir / "root_offline").exists()                       # no Root key is created or imported
    assert load_cert(ca_dir / "issuing" / "issuing-ca.crt") == load_cert(existing_ca / "issuing-ca.crt")
    assert load_cert(ca_dir / "issuing" / "root-ca.crt") == load_cert(existing_ca / "root-ca.crt")
    chain = x509.load_pem_x509_certificates((ca_dir / "issuing" / "chain.pem").read_bytes())
    assert chain == [load_cert(existing_ca / "issuing-ca.crt"), load_cert(existing_ca / "root-ca.crt")]
    assert load_issuing_key(ca_dir, demo_ca.issuing_pass).key_size == 4096
    assert (ca_dir / "issued").is_dir() and (ca_dir / "crl").is_dir()


def test_import_encrypts_an_unencrypted_key(demo_ca, existing_ca, tmp_path, capsys):
    key = serialization.load_pem_private_key((existing_ca / "issuing-ca.key").read_bytes(), demo_ca.issuing_pass)
    (existing_ca / "issuing-ca.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    ca_dir = tmp_path / "ca"
    bootstrap_ca.bootstrap(ca_dir, existing_ca, issuing_pass=IMPORT_PASS)

    assert "NOT encrypted" in capsys.readouterr().out
    data = (ca_dir / "issuing" / "issuing-ca.key").read_bytes()
    assert data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    with pytest.raises(TypeError):
        serialization.load_pem_private_key(data, password=None)
    assert load_issuing_key(ca_dir, IMPORT_PASS).key_size == 4096
    assert b"ENCRYPTED" not in (existing_ca / "issuing-ca.key").read_bytes()   # the original is left alone


def test_import_traditional_openssl_rsa_key(demo_ca, existing_ca, tmp_path):
    """An older `openssl genrsa -aes256` key ("BEGIN RSA PRIVATE KEY" with Proc-Type headers)."""
    key = serialization.load_pem_private_key((existing_ca / "issuing-ca.key").read_bytes(), demo_ca.issuing_pass)
    legacy = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                               serialization.BestAvailableEncryption(IMPORT_PASS))
    assert legacy.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
    (existing_ca / "issuing-ca.key").write_bytes(legacy)

    ca_dir = tmp_path / "ca"
    bootstrap_ca.bootstrap(ca_dir, existing_ca, issuing_pass=IMPORT_PASS)
    assert (ca_dir / "issuing" / "issuing-ca.key").read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")


def test_import_ec_issuing_ca(tmp_path, fast_keys):
    root_key = bootstrap_ca.new_key()
    root_cert = bootstrap_ca.make_root_cert(root_key)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    issuing_cert = bootstrap_ca.sign_issuing_csr(bootstrap_ca.make_issuing_csr(ec_key), root_cert, root_key)
    existing = tmp_path / "existing_ca"
    write_existing(existing, root_cert, issuing_cert, ec_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    ca_dir = tmp_path / "ca"
    assert bootstrap_ca.bootstrap(ca_dir, existing, issuing_pass=IMPORT_PASS) == "imported"
    assert isinstance(load_issuing_key(ca_dir, IMPORT_PASS), ec.EllipticCurvePrivateKey)


def test_import_wrong_passphrase(demo_ca, existing_ca, tmp_path):
    ca_dir = tmp_path / "ca"
    with pytest.raises(BootstrapError, match="does not decrypt"):
        bootstrap_ca.bootstrap(ca_dir, existing_ca, issuing_pass=b"not-the-passphrase")
    assert not ca_dir.exists()                                          # failed before writing anything


def test_import_key_that_does_not_match_the_certificate(demo_ca, existing_ca, tmp_path):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (existing_ca / "issuing-ca.key").write_bytes(bootstrap_ca.key_pem(other, IMPORT_PASS))
    with pytest.raises(BootstrapError, match="does not belong"):
        bootstrap_ca.bootstrap(tmp_path / "ca", existing_ca, issuing_pass=IMPORT_PASS)


def test_import_certificate_not_signed_by_the_root(demo_ca, existing_ca, tmp_path):
    other_root = bootstrap_ca.make_root_cert(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    (existing_ca / "root-ca.crt").write_bytes(bootstrap_ca.cert_pem(other_root))   # same name, different key
    with pytest.raises(BootstrapError, match="NOT signed by"):
        bootstrap_ca.bootstrap(tmp_path / "ca", existing_ca, issuing_pass=demo_ca.issuing_pass)


def test_import_with_only_part_of_the_files(demo_ca, existing_ca, tmp_path, capsys):
    (existing_ca / "issuing-ca.key").unlink()
    with pytest.raises(BootstrapError, match="only part"):
        bootstrap_ca.bootstrap(tmp_path / "ca", existing_ca, issuing_pass=demo_ca.issuing_pass)
    assert bootstrap_ca.main(["--ca-dir", str(tmp_path / "ca"), "--existing-dir", str(existing_ca)]) == 1
    assert "issuing-ca.key" in capsys.readouterr().err


def test_import_rejects_an_expired_issuing_ca(tmp_path, monkeypatch, fast_keys):
    long_ago = bootstrap_ca.now_utc() - timedelta(days=4000)           # a 3650-day certificate has run out
    with monkeypatch.context() as m:
        m.setattr(bootstrap_ca, "now_utc", lambda: long_ago)
        ca = bootstrap_ca.generate_ca()
    existing = tmp_path / "existing_ca"
    write_existing(existing, ca.root_cert, ca.issuing_cert, bootstrap_ca.key_pem(ca.issuing_key, IMPORT_PASS))
    with pytest.raises(BootstrapError, match="not valid right now"):
        bootstrap_ca.bootstrap(tmp_path / "ca", existing, issuing_pass=IMPORT_PASS)


def test_import_warns_when_the_issuing_ca_cannot_sign_crls(tmp_path, monkeypatch, capsys, fast_keys):
    cert_sign_only = x509.KeyUsage(
        digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=True, crl_sign=False, encipher_only=False, decipher_only=False)
    with monkeypatch.context() as m:
        m.setattr(bootstrap_ca, "ca_key_usage", lambda: cert_sign_only)
        ca = bootstrap_ca.generate_ca()
    existing = tmp_path / "existing_ca"
    write_existing(existing, ca.root_cert, ca.issuing_cert, bootstrap_ca.key_pem(ca.issuing_key, IMPORT_PASS))

    assert bootstrap_ca.bootstrap(tmp_path / "ca", existing, issuing_pass=IMPORT_PASS) == "imported"
    assert "lacks cRLSign" in capsys.readouterr().err                   # a warning, not a failure
