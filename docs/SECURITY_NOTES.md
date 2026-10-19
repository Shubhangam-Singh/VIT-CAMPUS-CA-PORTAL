# Security notes: what is demo-only and what is production-grade

This portal is a teaching demo. Some parts are built the way a real CA builds them; others are
deliberate shortcuts so it can be shown on one laptop. This page says which is which.

## Built the way a real CA would build it

| Area | What the code does | Where |
| --- | --- | --- |
| Hierarchy | Two tiers: an offline Root CA signs only the Issuing CA. `pathlen:0` on the Issuing CA means no sub-CA can ever be created, even with its key (tested). | `scripts/bootstrap_ca.py`, `tests/test_signing.py` |
| Root key isolation | The web app has no setting for `ca/root_offline/`, and a test fails if any string in `app/` mentions it. | `app/config.py`, `tests/test_repo_hygiene.py` |
| Key strength | RSA-4096 CAs; RSA >= 2048 / 3072 or EC P-256 for users; SHA-256 everywhere. | `templates_def.py` |
| CA keys at rest | Encrypted PKCS#8 (`BestAvailableEncryption`). Passphrases only from environment variables, never in files, `app.config` or git. | `bootstrap_ca.py`, `ca_core.load_issuing_ca` |
| Proof of possession | The CSR's signature must verify; otherwise nothing is issued. | `ca_core.check_csr` |
| The CA decides, not the applicant | The CSR's subject and requested extensions are ignored. The subject comes from the RA-verified identity, and every extension from the template. | `ca_core.build_certificate`, tests |
| Certificate profile | `CA:FALSE` critical, critical KeyUsage, EKU, SKI, AKI, CRL distribution point; random 128-bit serials; a certificate never outlives its CA. Passes `openssl verify -x509_strict`. | `ca_core.build_certificate` |
| Strict input checks | Name, e-mail, registration number and DNS names are validated before they go into a certificate (no wildcards, nothing that breaks the ASN.1 string types). | `ca_core.check_identity` |
| Consistency | A certificate's database row and PEM file are written together or not at all, and an existing file is never overwritten. | `ca_core.save_certificate` |
| Revocation | Every revocation signs a new CRL (CRL number + 1, nextUpdate + 7 days, reason codes, AKI). The CA key is unlocked *before* anything changes. | `ca_core.revoke_certificate`, `publish_crl` |
| OCSP | Real RFC 6960 responses, signed, with the nonce echoed; answers UNKNOWN for other issuers. | `ca_core.build_ocsp_response` |
| Signature verification | Five independent checks; the only trust anchor is `root-ca.crt`; the path is built and checked by hand (signatures, validity, CA flag, keyCertSign, pathlen). It fails closed: no CRL, a stale CRL or a forged CRL means FAIL. | `app/signing.py` |
| Accountability | Every step is in the audit log (who, what, when); the CSV export neutralises spreadsheet formulas. | `app/audit.py`, `routes_admin.audit_csv` |
| Web basics | Jinja auto-escaping, `secure_filename` for uploads, 20 MB upload limit, `Cache-Control: no-store` on the page that shows a password, listening on 127.0.0.1 only. | routes, `config.py`, `run.py` |
| Secrets hygiene | `.gitignore` covers `*.key`, `*.p12`, `*.db`, `ca/`, `instance/`, `existing_ca/`, `demo_work/` (tested). | `.gitignore`, tests |

## Demo-only shortcuts (do NOT do this in production)

| Shortcut | Why it is unsafe | What production does |
| --- | --- | --- |
| `/admin` has no login and no CSRF protection | Anyone who reaches the page acts as the RA. | RA accounts with MFA, role-based access, CSRF tokens, two-person approval for sensitive templates. |
| One shared RA identity (`ra-admin`) in the audit log | You cannot tell which RA officer approved what. | Named accounts; the audit log records the real person. |
| Identity data is typed by the applicant | The RA is assumed to check it against the VIT ID out of band. | Fetch identity from the university directory (LDAP / SSO), and verify the e-mail address. |
| Demo mode: the server generates the user's key | The CA operator could keep a copy, so non-repudiation is lost. | The key is generated on the user's device (browser, smart card, OS key store); only the CSR is sent. |
| The `.p12` password is stored until its first display | It sits in the database in plain text for a while. | No server-side key generation at all, or delivery over a separate channel. |
| `/sign` uploads the private key | Same problem as demo mode. | Sign locally (`tools/sign_file.py`, or a smart card / HSM). |
| The Issuing CA key is decrypted in the app's memory | A compromised web server would expose the key. | Keep it in an HSM; the app sends signing requests and the key never leaves. |
| The Root key is created on the same machine | "Offline" is only a reminder to move the folder. | Key ceremony on an air-gapped machine, the key split across smart cards (M-of-N), witnesses. |
| Flask development server, plain HTTP | Not hardened; traffic is readable. | gunicorn / uWSGI behind nginx with TLS; HSTS. |
| The tracking ID is the only secret for a request | Anyone with the ID can download the certificate (public data) and see the request. | Authenticated applicant accounts. |
| SQLite and a plain audit table | No tamper evidence; one file. | PostgreSQL with backups; a hash-chained or append-only (WORM) audit log. |
| `signed_at` is the signer's own claim | It cannot prove when a file was signed, so a revoked certificate always fails. | RFC 3161 time-stamping authority. |
| The OCSP responder signs with the CA key | More use of the most valuable key. | A dedicated OCSP-signing certificate (`id-kp-OCSPSigning`) and OCSP stapling. |
| The CRL URL is `http://localhost:5000/crl.pem` | Only works on this machine. | A public, highly available URL (often a CDN) for the CRL and OCSP. |
| No rate limiting | Enrollment and verification could be flooded. | Rate limits and request quotas. |
| File permissions on Windows | `chmod 600` has no effect; the user profile's NTFS permissions protect the keys. | Dedicated service account, restrictive ACLs, keys in an HSM anyway. |

## What the tests prove

`pytest` runs the whole suite. Besides normal behaviour, it checks the security rules directly, for
example:
- the Root key is unreachable from the app;
- CSR subjects and extensions are ignored;
- wrong key sizes, curves and types are refused;
- a broken CSR signature is refused;
- `pathlen:0` stops a sub-CA;
- a forged look-alike CA is rejected;
- a stale or forged CRL fails verification;
- the `.p12` password is shown once and never to the RA.

Each security rule was also checked by "mutation testing": the rule was deliberately broken in the code,
and the suite had to notice.
