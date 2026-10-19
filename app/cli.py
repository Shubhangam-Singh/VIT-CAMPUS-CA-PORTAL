"""Command line for the CA.

    python -m app.cli issue --template student_auth --name "Asha Rao" --email asha@vit.ac.in \\
                            --regno 21BCE0001 --csr asha.csr

Set the ISSUING_CA_PASS environment variable first: it unlocks the Issuing CA key.
By default the CA is the ca/ folder and the database is instance/campus_ca.db; --ca-dir and
--database point a command at another CA (for example a throw-away one for a demo or a test).
"""
import argparse
import sys
from pathlib import Path

from . import create_app
from .ca_core import Identity, IssuanceError, issue_certificate, load_csr, subject_text
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
    return parser.parse_args(argv)


def run_issue(args):
    try:
        csr_bytes = args.csr.read_bytes()
    except OSError as err:
        raise IssuanceError(f"cannot read {args.csr}: {err.strerror}") from None

    identity = Identity(args.name, args.email, args.regno, tuple(args.dns))
    result = issue_certificate(load_csr(csr_bytes), identity, args.template)

    cert = result.certificate
    print("Certificate issued")
    print(f"  template  {args.template}")
    print(f"  serial    {result.serial_hex}")
    print(f"  subject   {subject_text(cert.subject)}")
    print(f"  valid     {cert.not_valid_before_utc:%Y-%m-%d} to {cert.not_valid_after_utc:%Y-%m-%d} (UTC)")
    print(f"  file      {result.pem_path}")


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
            run_issue(args)
    except IssuanceError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
