#!/usr/bin/env bash
# End-to-end demo of the whole PKI from the command line:
#   bootstrap -> issue -> verify -> revoke -> CRL check -> sign -> verify -> tamper test -> revoked signer
#
#   bash scripts/demo_end_to_end.sh        (Git Bash on Windows, or any Linux / macOS shell)
#
# It builds a THROW-AWAY CA in demo_work/e2e/ with random one-time passphrases, so your real ca/
# folder and database are never touched. Every step says what it EXPECTS; the summary at the end
# counts the surprises, and the exit code is 0 only if there were none.
# Everything printed is also saved to docs/demo_output.txt.

set -u
cd "$(dirname "$0")/.."            # the project folder
export MSYS_NO_PATHCONV=1          # Git Bash: leave "/CN=..." alone (all paths below are relative)

if [ -x .venv/Scripts/python.exe ]; then PY=.venv/Scripts/python.exe     # Windows venv
elif [ -x .venv/bin/python ]; then PY=.venv/bin/python                    # Linux / macOS venv
else PY=python; fi

W=demo_work/e2e
OUT=docs/demo_output.txt
GOOD=0
SURPRISES=0

step() { printf '\n========== %s ==========\n' "$1"; }

run() {  # run <command...>: show it, run it, keep its output in OUTPUT and its exit code in RC
    printf '$ %s\n' "$*"
    OUTPUT=$("$@" 2>&1)
    RC=$?
    OUTPUT=$(printf '%s' "$OUTPUT" | tr -d '\r')      # this Windows OpenSSL ends lines with \r\n
    printf '%s\n' "$OUTPUT" | sed 's/^/    /'
}

expect() {  # expect ok|fail "<text the output must contain, or ''>" "<what this proves>"
    local want=$1 needle=$2 meaning=$3 good=1
    [ "$want" = ok ] && [ "$RC" -ne 0 ] && good=0
    [ "$want" = fail ] && [ "$RC" -eq 0 ] && good=0
    [ -n "$needle" ] && ! printf '%s\n' "$OUTPUT" | grep -qF -- "$needle" && good=0
    if [ $good = 1 ]; then
        echo "  [as expected] $meaning"; GOOD=$((GOOD + 1))
    else
        echo "  [SURPRISE] expected it to ${want/ok/succeed} ${needle:+(showing \"$needle\")}: $meaning"
        SURPRISES=$((SURPRISES + 1))
    fi
}

serial_from_output() { printf '%s\n' "$OUTPUT" | grep -m1 'serial' | awk '{print $2}'; }

main() {
    echo "VIT Campus CA Portal - end-to-end demo, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Throw-away CA in $W (your real ca/ folder is not used)."
    rm -rf "$W"
    mkdir -p "$W/no_existing_ca"
    # One-time random passphrases for this throw-away CA only.
    export ROOT_CA_PASS ISSUING_CA_PASS P12_PASSWORD
    ROOT_CA_PASS=$(openssl rand -hex 16 | tr -d '\r')
    ISSUING_CA_PASS=$(openssl rand -hex 16 | tr -d '\r')
    P12_PASSWORD=$(openssl rand -hex 12 | tr -d '\r')
    local CA="--ca-dir $W/ca --database $W/demo.db"          # the CLI options that select this CA
    local ROOT=$W/ca/issuing/root-ca.crt ISSUING=$W/ca/issuing/issuing-ca.crt CHAIN=$W/ca/issuing/chain.pem

    step "1. Bootstrap: offline Root CA -> online Issuing CA"
    run "$PY" scripts/bootstrap_ca.py --ca-dir "$W/ca" --existing-dir "$W/no_existing_ca"
    expect ok "verifies against the Root CA certificate ... OK" "Root CA (RSA-4096, 20 y) signed the Issuing CA (RSA-4096, 10 y, pathlen 0)"
    run openssl x509 -in "$ISSUING" -noout -subject -issuer -ext basicConstraints,keyUsage
    expect ok "CA:TRUE, pathlen:0" "the Issuing CA may sign end-entity certificates but no further CAs"
    run openssl verify -CAfile "$ROOT" "$ISSUING"
    expect ok ": OK" "OpenSSL accepts the Issuing CA certificate"

    step "2. Applicants make their own key pairs and CSRs (the private keys never leave them)"
    run openssl req -new -quiet -newkey rsa:2048 -nodes -keyout "$W/asha.key" -out "$W/asha.csr" -subj "/CN=ignored by the CA"
    expect ok "" "student Asha: RSA-2048 key + CSR"
    run openssl req -new -quiet -newkey rsa:3072 -nodes -keyout "$W/ravi.key" -out "$W/ravi.csr" -subj "/CN=ignored by the CA"
    expect ok "" "Ravi: RSA-3072 key + CSR (code signing needs at least 3072 bits)"

    step "3. The RA has verified their identity; the CA issues from templates"
    run "$PY" -m app.cli issue $CA --template student_auth --name "Asha Rao" --email asha.rao@vit.ac.in --regno 21BCE0001 --csr "$W/asha.csr"
    expect ok "Certificate issued" "student_auth certificate for Asha"
    ASHA=$(serial_from_output)
    run "$PY" -m app.cli issue $CA --template code_signing --name "Ravi Kumar" --email ravi.kumar@vit.ac.in --regno 21BCE0002 --csr "$W/ravi.csr"
    expect ok "Certificate issued" "code_signing certificate for Ravi"
    RAVI=$(serial_from_output)
    run "$PY" -m app.cli issue $CA --template code_signing --name "Asha Rao" --email asha.rao@vit.ac.in --regno 21BCE0001 --csr "$W/asha.csr"
    expect fail "RSA key too small" "policy: a 2048-bit key is refused for code signing"

    step "4. Anyone can check a certificate with OpenSSL"
    run openssl verify -CAfile "$ROOT" -untrusted "$ISSUING" "$W/ca/issued/$ASHA.pem"
    expect ok ": OK" "Asha's certificate chains to the Root CA"
    run openssl verify -CAfile "$ROOT" -untrusted "$ISSUING" "$W/ca/issued/$RAVI.pem"
    expect ok ": OK" "Ravi's certificate chains to the Root CA"
    run openssl x509 -in "$W/ca/issued/$ASHA.pem" -noout -subject -ext basicConstraints,keyUsage,extendedKeyUsage,crlDistributionPoints
    expect ok "TLS Web Client Authentication" "template extensions are in the certificate (CA:FALSE, clientAuth, CRL URL)"

    step "5. Asha's laptop is stolen: the RA revokes her certificate"
    run "$PY" -m app.cli revoke $CA --serial "$ASHA" --reason keyCompromise
    expect ok "CRL #1 published" "revocation recorded and a new CRL signed by the Issuing CA"
    run openssl crl -in "$W/ca/crl/crl.pem" -noout -text
    expect ok "Serial Number: $(echo "$ASHA" | tr a-f A-F)" "the CRL lists Asha's serial with reason Key Compromise"

    step "6. CRL check"
    run openssl verify -crl_check -CAfile "$ROOT" -untrusted "$ISSUING" -CRLfile "$W/ca/crl/crl.pem" "$W/ca/issued/$ASHA.pem"
    expect fail "certificate revoked" "Asha's certificate is now rejected"
    run openssl verify -crl_check -CAfile "$ROOT" -untrusted "$ISSUING" -CRLfile "$W/ca/crl/crl.pem" "$W/ca/issued/$RAVI.pem"
    expect ok ": OK" "Ravi's certificate is still fine"

    step "7. Ravi signs his report (RSA-PSS, SHA-256)"
    run openssl pkcs12 -export -inkey "$W/ravi.key" -in "$W/ca/issued/$RAVI.pem" -certfile "$CHAIN" -name "Ravi Kumar" -out "$W/ravi.p12" -passout env:P12_PASSWORD
    expect ok "" "Ravi packs his key + certificate + CA chain into ravi.p12"
    printf '%%PDF-1.4\nBCSE330L case study: PKI for VIT Vellore\nBudget: INR 50,000\n' > "$W/report.pdf"
    run "$PY" tools/sign_file.py --p12 "$W/ravi.p12" --file "$W/report.pdf"
    expect ok "Signed report.pdf" "report.pdf.sig.json written"

    step "8. Anyone verifies the signature"
    run "$PY" tools/verify_file.py --file "$W/report.pdf" --root "$ROOT" --crl "$W/ca/crl/crl.pem"
    expect ok "RESULT: VALID - signed by Ravi Kumar" "all five checks pass and the signer is identified"

    step "9. Tamper test: one byte of the report is changed"
    cp "$W/report.pdf.sig.json" "$W/tampered.pdf.sig.json"
    sed 's/50,000/90,000/' "$W/report.pdf" > "$W/tampered.pdf"
    run "$PY" tools/verify_file.py --file "$W/tampered.pdf" --root "$ROOT" --crl "$W/ca/crl/crl.pem"
    expect fail "FAIL  1. File hash matches" "the changed file is detected (check 1 fails)"

    step "10. Ravi's key is reported stolen too: revoke, then verify the ORIGINAL report again"
    run "$PY" -m app.cli revoke $CA --serial "$RAVI" --reason keyCompromise
    expect ok "CRL #2 published" "second revocation, CRL number goes up"
    run "$PY" tools/verify_file.py --file "$W/report.pdf" --root "$ROOT" --crl "$W/ca/crl/crl.pem"
    expect fail "FAIL  5. Not revoked" "a signature from a revoked certificate is no longer accepted"

    step "Summary"
    echo "  steps as expected: $GOOD"
    echo "  surprises:         $SURPRISES"
    [ "$SURPRISES" -eq 0 ] && echo "  DEMO COMPLETED: everything behaved as expected." || echo "  DEMO FAILED: see [SURPRISE] lines above."
    [ "$SURPRISES" -eq 0 ]
}

mkdir -p docs
main 2>&1 | tee "$OUT"
exit "${PIPESTATUS[0]}"
