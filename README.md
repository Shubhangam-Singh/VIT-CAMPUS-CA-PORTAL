# VIT Campus CA Portal

A demo Public Key Infrastructure for the BCSE330L case study at VIT Vellore:

offline Root CA -> online Issuing CA -> Registration Authority (RA) -> end-entity X.509v3 certificates.

> Work in progress: the project is built phase by phase (see `git tag`).
> The full README (architecture, report-to-feature table, limitations) arrives in Phase 6.

## Quick start

Run these from the `campus-ca-portal` folder.

### 1. Virtual environment and dependencies

PowerShell:

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt

Git Bash:

    python -m venv .venv
    source .venv/Scripts/activate
    pip install -r requirements.txt

### 2. Create the database (safe to repeat)

    flask --app app init-db

### 3. Create the demo CA (Root + Issuing)

CA passphrases come from environment variables, so they are never written to a file.
Set them in the terminal you run the script from (they last until you close it).

PowerShell:

    $env:ROOT_CA_PASS    = "choose a root passphrase"
    $env:ISSUING_CA_PASS = "choose a different issuing passphrase"

Git Bash:

    export ROOT_CA_PASS='choose a root passphrase'
    export ISSUING_CA_PASS='choose a different issuing passphrase'

Then run:

    python scripts/bootstrap_ca.py

This creates the git-ignored `ca/` folder:

| Path | What it is |
| --- | --- |
| `ca/root_offline/` | Root CA private key + certificate. **Move this folder offline** when you are done; the web app never reads it. |
| `ca/issuing/` | Issuing CA key, CSR and certificate, a public copy of the Root certificate, and `chain.pem` (issuing + root). |
| `ca/issued/`, `ca/crl/` | Empty for now: issued certificates (Phase 2) and the CRL (Phase 4). |

The script refuses to run again if the CA already exists, because a new CA would make every
certificate issued so far untrusted. To start over on purpose, delete the `ca/` folder yourself.

**Using your own CA instead:** put `root-ca.crt`, `issuing-ca.crt` and `issuing-ca.key` (PEM; the key may
be encrypted, in which case `ISSUING_CA_PASS` must be its passphrase) into `existing_ca/` and run the same
command. Only `ISSUING_CA_PASS` is needed, and no Root key is required.

### 4. Issue a certificate from the command line

First make a certificate request (CSR) the way an applicant's software would. In Git Bash, from the
project folder (`demo_work/` is git-ignored):

    mkdir -p demo_work
    export MSYS_NO_PATHCONV=1
    openssl req -new -newkey rsa:2048 -nodes -keyout demo_work/student.key -out demo_work/student.csr -subj "/CN=ignored by the CA"

Then ask the CA to issue it. `ISSUING_CA_PASS` must be set, as in step 3. The name in the CSR is
ignored: the CA takes the identity from these options.

    python -m app.cli issue --template student_auth --name "Asha Rao" --email asha.rao@vit.ac.in --regno 21BCE0001 --csr demo_work/student.csr

The certificate is saved in `ca/issued/<serial>.pem` and recorded in the database. Check it with OpenSSL:

    openssl verify -CAfile ca/issuing/root-ca.crt -untrusted ca/issuing/issuing-ca.crt ca/issued/<serial>.pem

| Template | Key the CSR must have | Valid for | Purpose |
| --- | --- | --- | --- |
| `student_auth` | RSA, at least 2048 bits | 365 days | TLS client authentication |
| `faculty_email` | RSA, at least 2048 bits | 730 days | S/MIME e-mail (SAN = the e-mail address) |
| `server_tls` | EC P-256 (`-newkey ec -pkeyopt ec_paramgen_curve:P-256`) | 365 days | TLS server; needs one or more `--dns HOST` |
| `code_signing` | RSA, at least 3072 bits | 730 days | Code and document signing |

### 5. Run the portal

The RA's "Approve" button unlocks the Issuing CA key, so set `ISSUING_CA_PASS` in the same terminal first
(`$env:ISSUING_CA_PASS = "..."` in PowerShell, `export ISSUING_CA_PASS='...'` in Git Bash), then:

    python run.py

Open http://127.0.0.1:5000 and try the workflow:

1. **Request a certificate**: choose student or faculty (only that role's templates are offered), fill in
   name, e-mail and registration number, then either upload a CSR or tick **Demo mode**. Keep the tracking ID.
2. **RA dashboard** (`/admin`): approve (this issues the certificate) or reject with a reason.
   There is no login in the demo.
3. **Status page** (`/request/<tracking ID>`): download `cert.pem` and `chain.pem`, plus `cert.p12` for
   demo-mode requests. The .p12 password is shown only once, on the first visit after approval.

Every step is recorded in the `audit_log` table (who, what, when).

No CSR at hand? `python scripts/make_sample_csrs.py` writes ready-to-upload samples (and some the CA
must refuse) into `demo_work/`.

### Certificate lifecycle and revocation

- **Certificates** (`/admin/certs`): every issued certificate with its status (valid / expired / revoked)
  and days left; rows expiring within 30 days are highlighted. Click a serial for the parsed fields.
- **Revoke** (on the detail page, or `python -m app.cli revoke --serial <hex> --reason keyCompromise`):
  each revocation signs and publishes a new CRL (next CRL number, nextUpdate = +7 days).
- **CRL**: `/crl.pem` and `/crl.der` (the CRL Distribution Point in every certificate).
- **Status API**: `/api/status/<serial>` returns `good`, `revoked` (with time and reason), `expired` or `unknown`.
- **OCSP**: `POST /ocsp` is a real OCSP responder (RFC 6960).
- **Audit log** (`/admin/audit`) with CSV export.

Check revocation with OpenSSL (Git Bash, from the project folder, with the portal running):

    curl -s -o crl.pem http://127.0.0.1:5000/crl.pem
    openssl crl -in crl.pem -text -noout
    openssl verify -crl_check -CAfile ca/issuing/root-ca.crt -untrusted ca/issuing/issuing-ca.crt -CRLfile crl.pem ca/issued/<serial>.pem
    openssl ocsp -issuer ca/issuing/issuing-ca.crt -cert ca/issued/<serial>.pem -url http://127.0.0.1:5000/ocsp -CAfile ca/issuing/chain.pem

A revoked certificate fails `verify` with `error 23 at 0 depth lookup: certificate revoked`.

### Sign and verify files (non-repudiation)

You need a **code_signing** certificate as a `.p12`. A demo-mode request gives you one directly. For a
CSR-based request, combine your key with the issued certificate (Git Bash):

    openssl pkcs12 -export -inkey demo_work/code_signing_rsa3072.key -in ca/issued/<serial>.pem \
            -certfile ca/issuing/chain.pem -out demo_work/ravi.p12

Sign (the .p12 password comes from `P12_PASSWORD`, or you are asked for it):

    python tools/sign_file.py --p12 demo_work/ravi.p12 --file report.pdf        # writes report.pdf.sig.json

Verify (prints a PASS/FAIL table; exit code 0 only if all five checks pass):

    python tools/verify_file.py --file report.pdf --crl-url http://127.0.0.1:5000/crl.pem

The five checks: (1) file hash matches, (2) RSA-PSS signature valid with the signer's public key,
(3) certificate chains to our Root CA (root-ca.crt is the only trust anchor), (4) codeSigning EKU and
`signed_at` within the certificate's validity, (5) not revoked on the current CRL. The same checks are on
the web: `/verify` for anyone, and `/sign` as a demo only (it uploads the .p12). To do all five by hand
with OpenSSL, see [docs/VERIFY_WITH_OPENSSL.md](docs/VERIFY_WITH_OPENSSL.md).

### 6. Run the tests

    pytest

## Tips

- **VS Code shows "Cannot find module" on imports?** Press Ctrl+Shift+P, choose *Python: Select Interpreter*
  and pick the one inside `.venv`.
- **Use `127.0.0.1` rather than `localhost` in scripts and commands on Windows.** `localhost` tries IPv6
  first, and clients that try one address at a time (Python, PowerShell) then wait about 2 seconds.
- **Git Bash rewrites arguments that start with `/`**, which breaks `openssl ... -subj "/C=IN/CN=x"`.
  Run `export MSYS_NO_PATHCONV=1` first.
