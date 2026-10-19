import shutil
import types

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from app import ca_core, create_app
from app.config import ca_folders
from app.db import init_db
from scripts import bootstrap_ca

ROOT_PASS = b"test-root-passphrase"
ISSUING_PASS = b"test-issuing-passphrase"


@pytest.fixture(scope="session")
def demo_ca(tmp_path_factory):
    """A real Root + Issuing CA (RSA-4096), generated once per test run in a temporary folder."""
    base = tmp_path_factory.mktemp("demo_ca")
    ca_dir = base / "ca"
    bootstrap_ca.bootstrap(ca_dir, existing_dir=base / "no_existing_ca",
                           issuing_pass=ISSUING_PASS, root_pass=ROOT_PASS)
    return types.SimpleNamespace(ca_dir=ca_dir, root_pass=ROOT_PASS, issuing_pass=ISSUING_PASS)


@pytest.fixture(scope="session")
def issuing_ca(demo_ca):
    """The demo Issuing CA with its key unlocked (reading an RSA-4096 key takes about a second: once per run)."""
    return ca_core.load_issuing_ca(demo_ca.ca_dir / "issuing", demo_ca.issuing_pass)


@pytest.fixture(scope="session")
def keys():
    """Applicant key pairs, generated once per run."""
    return types.SimpleNamespace(
        rsa1024=rsa.generate_private_key(public_exponent=65537, key_size=1024),
        rsa2048=rsa.generate_private_key(public_exponent=65537, key_size=2048),
        rsa3072=rsa.generate_private_key(public_exponent=65537, key_size=3072),
        ec256=ec.generate_private_key(ec.SECP256R1()),
        ec384=ec.generate_private_key(ec.SECP384R1()),
        ed25519=ed25519.Ed25519PrivateKey.generate(),
    )


@pytest.fixture
def app(tmp_path):
    """A fresh app wired to a throw-away database in a temporary folder."""
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "test.db")})
    with app.app_context():
        init_db()
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def ca_app(app, demo_ca, issuing_ca, tmp_path):
    """The app wired to the demo CA: its own empty issued/ folder, and the CA key already unlocked."""
    ca_dir = tmp_path / "ca"
    shutil.copytree(demo_ca.ca_dir / "issuing", ca_dir / "issuing")
    app.config.update(ca_folders(ca_dir))
    app.extensions["issuing_ca"] = issuing_ca
    return app
