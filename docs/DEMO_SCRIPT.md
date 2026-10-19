# 5-minute demo and viva preparation

## Before the demo (2 minutes, not part of the 5)

1. In PowerShell, from the project folder:

       .\.venv\Scripts\Activate.ps1
       $env:ISSUING_CA_PASS = "<your issuing passphrase>"
       python run.py

   (Only the first time: also set `ROOT_CA_PASS` and run `python scripts\bootstrap_ca.py`.)
2. Run `python scripts\make_sample_csrs.py` so `demo_work\` holds ready-made CSRs.
3. Open http://127.0.0.1:5000 in the browser and a Git Bash terminal in the project folder.

## The 5 minutes

| Time | Show | Say |
| --- | --- | --- |
| 0:00-0:40 | Home page, "How the trust chain works" | "Two-tier PKI: an offline Root CA that only signs the Issuing CA, an online Issuing CA, and an RA that checks identity. The web app cannot even reach the Root key." |
| 0:40-1:40 | **Request a certificate** -> I am a student -> fill in -> upload `demo_work/student_auth_rsa2048.csr` -> tracking ID. Then quickly upload `bad_rsa1024_too_small.csr` | "The applicant made their own key pair; only the CSR is sent. The CA checks the CSR's signature (proof of possession) and the key size. A 1024-bit key is refused." |
| 1:40-2:20 | **RA dashboard** -> Approve. Back on the status page: download `cert.pem` and `chain.pem` | "Approval calls issue_certificate(): the subject comes from the verified identity, not from the CSR; the extensions come from the template." |
| 2:20-2:50 | Git Bash: `openssl x509 -in <cert> -noout -text` and `openssl verify -CAfile ca/issuing/root-ca.crt -untrusted chain.pem cert.pem` | "OpenSSL, which is independent of my code, accepts it: CA:FALSE, clientAuth, CRL URL." |
| 2:50-3:40 | **Certificates** -> open it -> Revoke (keyCompromise). Then `curl -s -o crl.pem http://127.0.0.1:5000/crl.pem`, `openssl crl -in crl.pem -noout -text`, and `openssl verify -crl_check ... -CRLfile crl.pem cert.pem` -> `certificate revoked` | "Each revocation publishes a new CRL signed by the Issuing CA, with the next CRL number and a 7-day nextUpdate." |
| 3:40-4:40 | **Verify a signature**: show a file signed by a code-signing certificate (5 x PASS), then the same file with one byte changed (check 1 FAIL) | "Non-repudiation: RSA-PSS over SHA-256. Five independent checks; the only thing trusted is our Root certificate." |
| 4:40-5:00 | **Audit log**, then the summary of `bash scripts/demo_end_to_end.sh` | "Every action is logged: who, what, when. The whole flow is also scripted and checks itself." |

Tip: prepare the signed file for 3:40 beforehand (a demo-mode code_signing request gives a `.p12` for `/sign`),
or show the end of `docs/demo_output.txt` instead.

## 10 likely viva questions

1. **Why two tiers, and why keep the Root offline?**
   If the online Issuing CA is compromised, the Root (offline, untouched) revokes it and signs a new one;
   every user keeps trusting the same Root. If a single online root were compromised, the whole PKI would
   have to be rebuilt and redistributed.

2. **What does `pathlen:0` do?**
   It allows the Issuing CA to sign end-entity certificates but no further CA certificates. Even someone
   holding its key cannot build a working sub-CA. A test signs a "Rogue Sub CA" with the real Issuing CA
   key and shows that verification rejects certificates below it.

3. **Why ignore the subject in the CSR?**
   The applicant controls the CSR, so they could claim any name. The RA verifies the identity, and the CA
   builds the subject from that. From the CSR we use only the public key, plus its signature as proof that
   the applicant holds the matching private key.

4. **What is proof of possession?**
   The CSR is signed with the applicant's private key. Verifying that signature with the public key inside
   the CSR proves they hold the private key, so nobody can get a certificate for someone else's public key.

5. **CRL vs OCSP: what is the difference?**
   A CRL is a signed list of all revoked serials, published periodically (here: new one on every
   revocation, nextUpdate 7 days). OCSP answers for one certificate at a time, online, and can be fresher.
   The portal has both: `/crl.pem` and `POST /ocsp`, plus a simple JSON `/api/status`.

6. **Why does a signature from a revoked certificate fail, even if it was signed before the revocation?**
   Because `signed_at` is just a claim inside the signature file; nobody vouches for it. With an RFC 3161
   trusted timestamp we could prove the signing time and accept signatures made before the revocation
   (unless the reason is keyCompromise and the key could have been misused earlier).

7. **What are the five verification checks?**
   (1) the file hash matches, (2) the RSA-PSS signature is valid with the signer's public key, (3) the
   certificate chains to our Root CA, (4) the certificate has the codeSigning EKU and `signed_at` is within
   its validity, and (5) it is not on the current CA-signed CRL.

8. **Why RSA-PSS instead of PKCS#1 v1.5?**
   PSS is randomized, with a security proof; v1.5 signatures are deterministic and have a history of
   implementation attacks. PSS is the recommended RSA signature scheme today (RFC 8017).

9. **Why is demo mode "DEMO ONLY"?**
   The server generates the user's private key, so the CA could keep a copy. Then the user could deny
   having signed something (non-repudiation is lost). In a real PKI the key is generated on the user's
   device and never leaves it.

10. **How are the CA keys protected, and what would you do in production?**
    They are encrypted with passphrases that only come from environment variables; the web app cannot even
    see the Root key. In production: an HSM for the Issuing CA, an offline key ceremony for the Root with the
    key split across smart cards, MFA for RA staff, and a tamper-evident audit log.

Bonus answers worth having ready:

- **Why 128-bit random serials?** So serials cannot be predicted. Unpredictable serials blocked the 2008 MD5
  collision attack on a real CA.
- **Why is "expired" not stored in the database?** It depends on the clock, so it is computed each time from
  `not_after`. Only "revoked" is a decision that must be stored.
- **What stops a student requesting a server certificate?** The role -> template matrix. It is applied when
  the form is shown, again when it is submitted, and again when the RA approves.
