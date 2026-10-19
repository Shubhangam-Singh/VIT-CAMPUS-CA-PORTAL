"""Sign a file with a code-signing certificate.

    python tools/sign_file.py --p12 ravi.p12 --file report.pdf

Writes report.pdf.sig.json next to the file. The .p12 password is taken from the P12_PASSWORD
environment variable if it is set; otherwise you are asked for it. It is never a command-line argument
(those end up in the shell history and the process list).

This runs on the SIGNER's computer: the private key never leaves it. (The /sign web page does the
same thing, but only as a demo, because it has to upload the .p12.)
"""
import argparse
import getpass
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))          # so that `app` can be imported when run as a script

from cryptography import x509  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from app.signing import SigningError, sign_with_p12, subject_value, to_json  # noqa: E402


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Sign a file with a code-signing certificate (.p12).")
    parser.add_argument("--p12", required=True, type=Path, help="your code-signing key + certificate (.p12)")
    parser.add_argument("--file", required=True, type=Path, help="the file to sign")
    parser.add_argument("--chain", type=Path,
                        help="CA certificates (PEM) to include if the .p12 has none, e.g. ca/issuing/chain.pem")
    parser.add_argument("--out", type=Path, help="where to write the signature (default: <file>.sig.json)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    password = os.environ.get("P12_PASSWORD") or getpass.getpass(f"Password for {args.p12.name}: ")
    try:
        data = args.file.read_bytes()
        p12_bytes = args.p12.read_bytes()
        fallback = x509.load_pem_x509_certificates(args.chain.read_bytes()) if args.chain else []
        document = sign_with_p12(data, args.file.name, p12_bytes, password, fallback)
    except OSError as err:
        print(f"ERROR: cannot read {err.filename}: {err.strerror}", file=sys.stderr)
        return 1
    except (SigningError, ValueError) as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 1

    out = args.out or args.file.with_name(args.file.name + ".sig.json")
    out.write_bytes(to_json(document).encode("utf-8"))

    signer = x509.load_pem_x509_certificate(document["signer_certificate"].encode("ascii"))
    print(f"Signed {args.file.name}")
    print(f"  signer     {subject_value(signer, NameOID.COMMON_NAME)} (reg no {subject_value(signer, NameOID.SERIAL_NUMBER)},"
          f" {subject_value(signer, NameOID.EMAIL_ADDRESS)})")
    print(f"  sha256     {document['sha256']}")
    print(f"  algorithm  {document['algorithm']}")
    print(f"  signed_at  {document['signed_at']}")
    print(f"  written    {out}")
    if not document["chain"]:
        print("WARNING: the signature has no CA chain, so a verifier cannot connect it to the Root CA."
              " Sign again with --chain ca/issuing/chain.pem", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
