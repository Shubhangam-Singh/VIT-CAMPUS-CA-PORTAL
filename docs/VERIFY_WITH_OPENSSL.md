# Verifying a signed file by hand with OpenSSL

The portal's `/verify` page and `tools/verify_file.py` run five checks. This page does the same five
checks with plain OpenSSL, so you can show that nothing depends on our own code.

Run everything in **Git Bash** from the project folder. The example verifies `report.pdf` and its
signature `report.pdf.sig.json`. The commands need the CA's public files (`ca/issuing/root-ca.crt`) and
the current CRL.

## 0. Unpack the signature file

`report.pdf.sig.json` is JSON. Write its parts out as files that OpenSSL can read:

```bash
python - report.pdf.sig.json <<'EOF'
import base64, json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
open("signature.bin", "wb").write(base64.b64decode(doc["signature"]))
open("signer.pem", "w").write(doc["signer_certificate"])
open("untrusted_chain.pem", "w").write("".join(doc["chain"]))
print("sha256 in the signature file:", doc["sha256"])
print("signed_at:", doc["signed_at"])
EOF
```

`untrusted_chain.pem` comes from the signer, so it is never trusted. It only helps OpenSSL find the path.
Trust comes from `ca/issuing/root-ca.crt` alone.

## 1. File hash matches

```bash
openssl dgst -sha256 report.pdf
```

The hex value must equal the `sha256 in the signature file` printed above.

## 2. Signature is valid

```bash
openssl x509 -in signer.pem -pubkey -noout > signer_pub.pem
openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 \
        -verify signer_pub.pem -signature signature.bin report.pdf
```

Expected: `Verified OK`. If even one byte of the file changed, you get `Verification failure`.

## 3. Certificate chains to the VIT Root CA

```bash
openssl verify -x509_strict -CAfile ca/issuing/root-ca.crt -untrusted untrusted_chain.pem signer.pem
```

Expected: `signer.pem: OK`.

## 4. Code-signing certificate, valid when signed

```bash
openssl x509 -in signer.pem -noout -ext extendedKeyUsage -dates
```

Expected: `Code Signing` is listed, and `signed_at` lies between `notBefore` and `notAfter`.

## 5. Not revoked (current CRL)

```bash
curl -s -o crl.pem http://127.0.0.1:5000/crl.pem
openssl verify -crl_check -CAfile ca/issuing/root-ca.crt -untrusted untrusted_chain.pem -CRLfile crl.pem signer.pem
```

Expected: `signer.pem: OK`. A revoked signer gives:

```
error 23 at 0 depth lookup: certificate revoked
error signer.pem: verification failed
```

To see when and why it was revoked:

```bash
openssl crl -in crl.pem -noout -text
```

The revocation time printed there is the one the portal compares with `signed_at`.

## Why each check is needed

| Check | What it stops |
| --- | --- |
| 1. Hash | The file being changed after signing |
| 2. Signature | Someone editing the hash inside the `.sig.json` to match a changed file |
| 3. Chain | A forged look-alike "VIT Root CA" or "VIT Issuing CA" created by an attacker |
| 4. EKU and time | A login or e-mail certificate being used to sign code; a signing time outside the certificate's life |
| 5. CRL | A stolen key (keyCompromise) still being accepted after the RA revoked it |

`signed_at` is the signer's own claim. Without a trusted timestamp (RFC 3161, listed as future work)
it cannot be proven, which is why a revoked certificate is never accepted, whatever `signed_at` says.
