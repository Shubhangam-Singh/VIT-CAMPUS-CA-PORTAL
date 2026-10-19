"""Command line for the CA.

    python -m app.cli issue --template student_auth --name "Asha Rao" --email asha@vit.ac.in \\
                            --regno 21BCE0001 --csr asha.csr
    python -m app.cli revoke --serial 7a4da5ea... --reason keyCompromise

Set the ISSUING_CA_PASS environment variable first: it unlocks the Issuing CA key.
By default the CA is the ca/ folder and the database is instance/campus_ca.db; --ca-dir and
--database point a command at another CA (for example a throw-away one for a demo or a test).
"""
import argparse
import sys
from pathlib import Path

from cryptography import x509
from flask import current_app

from . import create_app
from .ca_core import (REVOCATION_REASONS, Identity, IssuanceError, RevocationError, issue_certificate, load_csr,
                      normalize_serial, revoke_certificate, subject_text)
from .config import ca_folders
from .db import init_db
from .templates_def import TEMPLATES


def parse_args(argv):
    # Options shared by every command.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--ca-dir", type=Path,
                        help="CA folder made by scripts/bootstrap_ca.py (default: ca/ in the project)")
    common.add_argument("--database", type=Path, help="SQLite file (default: instance/campus_ca.db)")

    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Command line for the VIT campus CA.")
    commands = parser.add_subparsers(dest="command", required=True)

    issue = commands.add_parser("issue", parents=[common], help="issue one certificate from a CSR")
    issue.add_argument("--template", required=True, choices=sorted(TEMPLATES))
    issue.add_argument("--name", required=True, help="the applicant's full name (becomes the CN)")
    issue.add_argument("--email", required=True, help="the applicant's e-mail address")
    issue.add_argument("--regno", required=True, help="registration number (becomes serialNumber)")
    issue.add_argument("--csr", required=True, type=Path, help="certificate request file (PEM or DER)")
    issue.add_argument("--dns", action="append", default=[], metavar="HOST",
                       help="DNS name for a server_tls certificate (repeat it for several names)")

    revoke = commands.add_parser("revoke", parents=[common], help="revoke a certificate and publish a new CRL")
    revoke.add_argument("--serial", required=True, help="certificate serial number (hex)")
    revoke.add_argument("--reason", required=True, choices=sorted(REVOCATION_REASONS))
    return parser.parse_args(argv)


def run_issue(args):
    try:
        csr_bytes = args.csr.read_bytes()
    except OSError as err:
        raise IssuanceError(f"cannot read {args.csr}: {err.strerror}") from None

    identity = Identity(args.name, args.email, args.regno, tuple(args.dns))
    result = issue_certificate(load_csr(csr_bytes), identity, args.template, actor="cli")

    cert = result.certificate
    print("Certificate issued")
    print(f"  template  {args.template}")
    print(f"  serial    {result.serial_hex}")
    print(f"  subject   {subject_text(cert.subject)}")
    print(f"  valid     {cert.not_valid_before_utc:%Y-%m-%d} to {cert.not_valid_after_utc:%Y-%m-%d} (UTC)")
    print(f"  file      {result.pem_path}")


def run_revoke(args):
    serial_hex = normalize_serial(args.serial)
    if serial_hex is None:
        raise RevocationError(f"{args.serial!r} is not a serial number")
    crl = revoke_certificate(serial_hex, args.reason, actor="cli")
    number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    print(f"Certificate {serial_hex} revoked ({args.reason})")
    print(f"  CRL #{number} published: {len(list(crl))} revoked certificate(s), "
          f"next update {crl.next_update_utc:%Y-%m-%d %H:%M} UTC")
    print(f"  file      {Path(current_app.config['CRL_DIR']) / 'crl.pem'}")


def main(argv=None):
    args = parse_args(argv)

    overrides = {}
    if args.ca_dir:
        overrides.update(ca_folders(args.ca_dir.resolve()))
    if args.database:
        overrides["DATABASE"] = args.database.resolve()

    app = create_app(overrides)
    try:
        with app.app_context():       # the CA code reads its settings and the database from the Flask app
            init_db()
            {"issue": run_issue, "revoke": run_revoke}[args.command](args)
    except (IssuanceError, RevocationError) as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
