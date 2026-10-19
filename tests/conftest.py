import types

import pytest

from app import create_app
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
