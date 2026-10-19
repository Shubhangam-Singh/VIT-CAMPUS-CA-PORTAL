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

    python run.py

Then open http://localhost:5000

### 6. Run the tests

    pytest

## Tips

- **VS Code shows "Cannot find module" on imports?** Press Ctrl+Shift+P, choose *Python: Select Interpreter*
  and pick the one inside `.venv`.
- **Use `127.0.0.1` rather than `localhost` in scripts and commands on Windows.** `localhost` tries IPv6
  first, and clients that try one address at a time (Python, PowerShell) then wait about 2 seconds.
- **Git Bash rewrites arguments that start with `/`**, which breaks `openssl ... -subj "/C=IN/CN=x"`.
  Run `export MSYS_NO_PATHCONV=1` first.
