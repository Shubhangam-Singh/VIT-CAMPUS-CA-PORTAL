#!/usr/bin/env bash
# S/MIME demo: a faculty_email certificate signs an e-mail with `openssl cms`.
#
#   bash scripts/smime_demo.sh        (Git Bash on Windows, or any Linux / macOS shell)
#
# 1. a throw-away CA issues Dr. Meera Iyer a faculty_email certificate (SAN = her e-mail address)
# 2. she signs a message:            openssl cms -sign
# 3. anyone verifies it:             openssl cms -verify  (trusting only root-ca.crt)
# 4. one word is changed in transit: verification FAILS
# 5. a student_auth (login) certificate cannot sign e-mail: wrong key purpose
# Your real ca/ folder is never touched. Output is also saved to docs/smime_demo_output.txt.

set -u
cd "$(dirname "$0")/.."            # the project folder
export MSYS_NO_PATHCONV=1          # Git Bash: leave "/CN=..." alone (all paths below are relative)

if [ -x .venv/Scripts/python.exe ]; then PY=.venv/Scripts/python.exe
elif [ -x .venv/bin/python ]; then PY=.venv/bin/python
else PY=python; fi

W=demo_work/smime
OUT=docs/smime_demo_output.txt
GOOD=0
SURPRISES=0

step() { printf '\n========== %s ==========\n' "$1"; }

run() {  # run <command...>: show it, run it, keep its output in OUTPUT and its exit code in RC
    printf '$ %s\n' "$*"
    OUTPUT=$("$@" 2>&1)
    RC=$?
    OUTPUT=$(printf '%s' "$OUTPUT" | tr -d '\r')
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
    echo "VIT Campus CA Portal - S/MIME demo, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    rm -rf "$W"
    mkdir -p "$W/no_existing_ca"
    export ROOT_CA_PASS ISSUING_CA_PASS
    ROOT_CA_PASS=$(openssl rand -hex 16 | tr -d '\r')
    ISSUING_CA_PASS=$(openssl rand -hex 16 | tr -d '\r')
    local CA="--ca-dir $W/ca --database $W/demo.db"
    local ROOT=$W/ca/issuing/root-ca.crt CHAIN=$W/ca/issuing/chain.pem

    step "1. A throw-away CA issues Dr. Meera Iyer a faculty_email certificate"
    run "$PY" scripts/bootstrap_ca.py --ca-dir "$W/ca" --existing-dir "$W/no_existing_ca"
    expect ok "verifies against the Root CA certificate ... OK" "demo Root CA + Issuing CA created"
    run openssl req -new -quiet -newkey rsa:2048 -nodes -keyout "$W/meera.key" -out "$W/meera.csr" -subj "/CN=ignored by the CA"
    expect ok "" "Meera makes her own RSA-2048 key and CSR"
    run "$PY" -m app.cli issue $CA --template faculty_email --name "Dr. Meera Iyer" --email meera.iyer@vit.ac.in --regno FAC1001 --csr "$W/meera.csr"
    expect ok "Certificate issued" "faculty_email certificate issued"
    cp "$W/ca/issued/$(serial_from_output).pem" "$W/meera.pem"
    run openssl x509 -in "$W/meera.pem" -noout -subject -ext keyUsage,extendedKeyUsage,subjectAltName
    expect ok "email:meera.iyer@vit.ac.in" "E-mail Protection + her address in the SAN, as S/MIME needs"

    step "2. Meera signs an e-mail"
    printf 'From: meera.iyer@vit.ac.in\nTo: hod.scope@vit.ac.in\nSubject: Lab budget\n\nPlease release INR 50,000 for the PKI lab.\n' > "$W/message.txt"
    run cat "$W/message.txt"
    run openssl cms -sign -in "$W/message.txt" -signer "$W/meera.pem" -inkey "$W/meera.key" -certfile "$CHAIN" -out "$W/signed.eml"
    expect ok "" "signed.eml is a multipart/signed S/MIME message (text + detached signature + certificates)"
    run head -5 "$W/signed.eml"
    expect ok "multipart/signed" "it is an S/MIME signed message"

    step "3. The receiver verifies it, trusting only the VIT Root CA"
    run openssl cms -verify -in "$W/signed.eml" -CAfile "$ROOT" -out "$W/verified.txt"
    expect ok "Verification successful" "signature valid, chain to the Root CA valid, certificate allowed for e-mail"
    run cat "$W/verified.txt"
    expect ok "INR 50,000" "the verified text is exactly what Meera wrote"

    step "4. Someone changes one word in transit"
    sed 's/50,000/90,000/' "$W/signed.eml" > "$W/tampered.eml"
    run grep "INR" "$W/tampered.eml"
    run openssl cms -verify -in "$W/tampered.eml" -CAfile "$ROOT" -out "$W/tampered_out.txt"
    expect fail "Verification failure" "the change is detected: the content no longer matches the signed digest"

    step "5. A student LOGIN certificate cannot sign e-mail"
    run openssl req -new -quiet -newkey rsa:2048 -nodes -keyout "$W/asha.key" -out "$W/asha.csr" -subj "/CN=ignored by the CA"
    run "$PY" -m app.cli issue $CA --template student_auth --name "Asha Rao" --email asha.rao@vit.ac.in --regno 21BCE0001 --csr "$W/asha.csr"
    cp "$W/ca/issued/$(serial_from_output).pem" "$W/asha.pem"
    run openssl cms -sign -in "$W/message.txt" -signer "$W/asha.pem" -inkey "$W/asha.key" -certfile "$CHAIN" -out "$W/asha_signed.eml"
    run openssl cms -verify -in "$W/asha_signed.eml" -CAfile "$ROOT" -out "$W/asha_out.txt"
    expect fail "unsuitable certificate purpose" "its EKU is clientAuth only, so S/MIME verification refuses it"

    step "Summary"
    echo "  steps as expected: $GOOD"
    echo "  surprises:         $SURPRISES"
    [ "$SURPRISES" -eq 0 ] && echo "  S/MIME DEMO COMPLETED: everything behaved as expected." || echo "  S/MIME DEMO FAILED: see [SURPRISE] lines above."
    [ "$SURPRISES" -eq 0 ]
}

mkdir -p docs
main 2>&1 | tee "$OUT"
exit "${PIPESTATUS[0]}"
