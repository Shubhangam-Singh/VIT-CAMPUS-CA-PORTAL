"""Security hygiene guards from the project rules.

1. .gitignore must keep keys, .p12 files, the database and the CA folders out of git.
2. The web app must never be able to load the offline Root CA private key.
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_IGNORES = ["*.key", "*.p12", "*.db", "ca/", "instance/", "existing_ca/"]
ROOT_KEY_MARKERS = ("root_offline", "root-ca.key")


def test_gitignore_covers_secrets():
    # "utf-8-sig" = UTF-8 that tolerates a byte-order mark (some Windows editors add one)
    lines = {line.strip() for line in (ROOT / ".gitignore").read_text(encoding="utf-8-sig").splitlines()}
    missing = [pattern for pattern in REQUIRED_IGNORES if pattern not in lines]
    assert not missing, f".gitignore is missing: {missing}"


def test_app_config_has_no_path_to_the_root_ca(app):
    for name, value in app.config.items():
        text = str(value).lower()
        assert not any(marker in text for marker in ROOT_KEY_MARKERS), f"app.config[{name!r}] = {value!r}"


def test_app_code_never_mentions_the_root_ca_key():
    """No string literal in app/*.py may point at the offline Root CA folder or key file.

    The check reads the code as a syntax tree, so comments are ignored; only real strings count.
    """
    offenders = []
    for path in (ROOT / "app").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if any(marker in node.value for marker in ROOT_KEY_MARKERS):
                    offenders.append(f"{path.name}: {node.value[:60]!r}")
    assert not offenders, offenders
