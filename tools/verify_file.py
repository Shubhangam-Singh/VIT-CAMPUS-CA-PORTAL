"""Verify a signed file and print a PASS/FAIL table.

    python tools/verify_file.py --file report.pdf                      (uses report.pdf.sig.json)
    python tools/verify_file.py --file report.pdf --crl-url http://127.0.0.1:5000/crl.pem

The only thing trusted is the Root CA certificate (--root, default ca/issuing/root-ca.crt).
Revocation is checked against a CRL file (--crl, default ca/crl/crl.pem) or a CRL downloaded
from the portal (--crl-url). With no CRL at all, check 5 FAILS: we never assume "not revoked".

Exit code: 0 if every check PASSED, 1 otherwise.
"""
import argparse
import sys
import textwrap
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))          # so that `app` can be imported when run as a script

from cryptography import x509  # noqa: E402

from app.signing import SigningError, load_crl, parse_signature_file, verify_signature  # noqa: E402


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Verify a file against its .sig.json signature.")
    parser.add_argument("--file", required=True, type=Path, help="the signed file")
    parser.add_argument("--sig", type=Path, help="the signature (default: <file>.sig.json)")
    parser.add_argument("--root", type=Path, default=PROJECT_ROOT / "ca" / "issuing" / "root-ca.crt",
                        help="trust anchor: the VIT Root CA certificate (default: ca/issuing/root-ca.crt)")
    parser.add_argument("--crl", type=Path, default=PROJECT_ROOT / "ca" / "crl" / "crl.pem",
                        help="CRL file (default: ca/crl/crl.pem)")
    parser.add_argument("--crl-url", help="download the CRL instead, e.g. http://127.0.0.1:5000/crl.pem")
    return parser.parse_args(argv)


def get_crl(args):
    """The CRL to check against, or None if there is none (check 5 will then fail)."""
    if args.crl_url:
        with urllib.request.urlopen(args.crl_url, timeout=15) as response:
            return load_crl(response.read())
    if args.crl.is_file():
        return load_crl(args.crl.read_bytes())
    return None


def main(argv=None):
    args = parse_args(argv)
    sig_path = args.sig or args.file.with_name(args.file.name + ".sig.json")
    try:
        data = args.file.read_bytes()
        document = parse_signature_file(sig_path.read_text(encoding="utf-8"))
        root = x509.load_pem_x509_certificate(args.root.read_bytes())
        crl = get_crl(args)
    except OSError as err:
        print(f"ERROR: cannot read {getattr(err, 'filename', None) or err}: {getattr(err, 'strerror', '')}",
              file=sys.stderr)
        return 1
    except (SigningError, ValueError) as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 1

    result = verify_signature(data, document, root, crl)

    print(f"Verifying {args.file.name} against {sig_path.name}\n")
    for check in result.checks:
        print(f"{'PASS' if check.passed else 'FAIL'}  {check.name}")
        print(textwrap.indent(textwrap.fill(check.detail, 96), "      "))
    print()
    if result.passed:
        s = result.signer
        print(f"RESULT: VALID - signed by {s['name']} (reg no {s['reg_no']}, {s['email']}) at {s['signed_at']}")
        return 0
    failed = ", ".join(check.name.split(".")[0] for check in result.checks if not check.passed)
    print(f"RESULT: NOT VALID - failed check(s) {failed}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
