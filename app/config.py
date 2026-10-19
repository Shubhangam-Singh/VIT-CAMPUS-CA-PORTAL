"""Application settings.

Secrets (CA passphrases, Flask secret key) are read from environment variables and are
never hard-coded in the source code or committed to git.
"""
import os
import secrets
from pathlib import Path

# Project root = the folder that contains run.py (one level above this app/ package).
BASE_DIR = Path(__file__).resolve().parent.parent


def ca_folders(ca_dir):
    """The three ONLINE-CA settings for a CA folder made by bootstrap_ca.py.

    Used by the command line (--ca-dir) and by tests to point the app at another CA.
    Like the defaults in Config below, it never mentions the offline Root CA folder.
    """
    ca_dir = Path(ca_dir)
    return {"ISSUING_DIR": ca_dir / "issuing", "ISSUED_DIR": ca_dir / "issued", "CRL_DIR": ca_dir / "crl"}


class Config:
    # Signs the session cookie. If SECRET_KEY is not set, a random key is made at start-up
    # (fine for a demo; the only effect is that browser sessions reset when the server restarts).
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    # SQLite database file (instance/ is git-ignored).
    DATABASE = BASE_DIR / "instance" / "campus_ca.db"

    # Folders of the ONLINE CA, created by scripts/bootstrap_ca.py (Phase 1).
    # There is deliberately NO setting for the offline Root CA folder: the Root CA private
    # key must stay offline and the web application must never be able to load it.
    ISSUING_DIR = BASE_DIR / "ca" / "issuing"   # Issuing CA cert + key, Root CA cert (public), chain.pem
    ISSUED_DIR = BASE_DIR / "ca" / "issued"     # certificates issued to users
    CRL_DIR = BASE_DIR / "ca" / "crl"           # current CRL (PEM + DER)

    # Written into every certificate as its CRL Distribution Point: where to fetch the revocation list.
    CRL_URL = "http://localhost:5000/crl.pem"

    # The CA passphrases (ROOT_CA_PASS, ISSUING_CA_PASS) are NOT stored here: code reads them
    # from os.environ at the moment it needs them, so they never sit in app.config.
