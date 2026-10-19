import pytest

from app import create_app
from app.db import init_db


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
