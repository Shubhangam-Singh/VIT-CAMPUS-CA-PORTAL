"""Phase 2 checks for the command line: python -m app.cli issue ..."""
import re
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app import cli
from csr_factory import make_csr

PROJECT = Path(__file__).resolve().parent.parent


@pytest.fixture
def run_cli(demo_ca, tmp_path, monkeypatch, capsys):
    """Run `python -m app.cli issue ...` against the demo CA and a throw-away database.

    Returns run(*args) -> (exit code, stdout, stderr); run.database is the SQLite file it uses.
    """
    monkeypatch.setenv("ISSUING_CA_PASS", demo_ca.issuing_pass.decode())
    database = tmp_path / "cli.db"

    def run(*args):
        code = cli.main(["issue", "--ca-dir", str(demo_ca.ca_dir), "--database", str(database), *args])
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    run.database = database
    return run


def write_csr(path, key, encoding=serialization.Encoding.PEM):
    path.write_bytes(make_csr(key).public_bytes(encoding))
    return path


def student_args(csr_file, **replace):
    values = {"--template": "student_auth", "--name": "Asha Rao", "--email": "asha.rao@vit.ac.in",
              "--regno": "21BCE0001", "--csr": str(csr_file)}
    values.update(replace)
    return [item for pair in values.items() for item in pair]


def certificate_rows(database):
    with closing(sqlite3.connect(database)) as db:
        return db.execute("SELECT serial_hex, template FROM certificates").fetchall()


def test_issue_prints_a_summary_and_saves_the_certificate(run_cli, demo_ca, keys, tmp_path):
    code, out, err = run_cli(*student_args(write_csr(tmp_path / "asha.csr", keys.rsa2048)))

    assert (code, err) == (0, "")
    assert "Certificate issued" in out and "student_auth" in out
    assert "C=IN, O=VIT, CN=Asha Rao, emailAddress=asha.rao@vit.ac.in, serialNumber=21BCE0001" in out
    serial = re.search(r"serial\s+([0-9a-f]{32})", out).group(1)
    cert = x509.load_pem_x509_certificate((demo_ca.ca_dir / "issued" / f"{serial}.pem").read_bytes())
    assert f"{cert.serial_number:032x}" == serial
    assert certificate_rows(run_cli.database) == [(serial, "student_auth")]


def test_server_tls_with_two_dns_names_from_a_der_csr(run_cli, demo_ca, keys, tmp_path):
    csr_file = write_csr(tmp_path / "server.der", keys.ec256, serialization.Encoding.DER)
    code, out, err = run_cli("--template", "server_tls", "--name", "Lab Server", "--email", "labadmin@vit.ac.in",
                             "--regno", "SRV0001", "--csr", str(csr_file),
                             "--dns", "lab1.vit.local", "--dns", "www.lab1.vit.local")

    assert (code, err) == (0, "")
    serial = re.search(r"serial\s+([0-9a-f]{32})", out).group(1)
    cert = x509.load_pem_x509_certificate((demo_ca.ca_dir / "issued" / f"{serial}.pem").read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["lab1.vit.local", "www.lab1.vit.local"]


@pytest.mark.parametrize("what_goes_wrong, message", [
    ("small key", "RSA key too small"),
    ("missing csr file", "cannot read"),
    ("csr file is junk", "not a readable certificate request"),
    ("bad e-mail", "not a valid e-mail"),
    ("server_tls without --dns", "at least one DNS name"),
    ("no passphrase", "ISSUING_CA_PASS"),
])
def test_problems_give_exit_code_1_and_a_clear_message(run_cli, keys, tmp_path, monkeypatch, what_goes_wrong, message):
    csr_file = write_csr(tmp_path / "x.csr", keys.rsa2048)
    args = student_args(csr_file)
    if what_goes_wrong == "small key":
        args = student_args(write_csr(tmp_path / "small.csr", keys.rsa1024))
    elif what_goes_wrong == "missing csr file":
        args = student_args(tmp_path / "does-not-exist.csr")
    elif what_goes_wrong == "csr file is junk":
        (tmp_path / "junk.csr").write_text("hello")
        args = student_args(tmp_path / "junk.csr")
    elif what_goes_wrong == "bad e-mail":
        args = student_args(csr_file, **{"--email": "nope"})
    elif what_goes_wrong == "server_tls without --dns":
        args = student_args(write_csr(tmp_path / "ec.csr", keys.ec256), **{"--template": "server_tls"})
    elif what_goes_wrong == "no passphrase":
        monkeypatch.delenv("ISSUING_CA_PASS")

    code, out, err = run_cli(*args)

    assert code == 1 and out == ""
    assert err.startswith("ERROR:") and message in err
    assert certificate_rows(run_cli.database) == []


def test_an_unknown_template_is_refused_by_the_argument_parser(run_cli, keys, tmp_path, capsys):
    with pytest.raises(SystemExit) as stop:
        run_cli(*student_args(write_csr(tmp_path / "x.csr", keys.rsa2048), **{"--template": "root_ca"}))
    assert stop.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_the_module_runs_from_the_command_line():
    for command in (["--help"], ["issue", "--help"]):
        result = subprocess.run([sys.executable, "-m", "app.cli", *command], cwd=PROJECT,
                                capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr
    assert "--template" in result.stdout and "student_auth" in result.stdout
