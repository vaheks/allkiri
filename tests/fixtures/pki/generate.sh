#!/usr/bin/env bash
# Regenerates the allkiri test PKI. Run only when the fixtures must change:
# every golden file in tests/fixtures/golden depends on these exact keys.
#
# Needs OpenSSL >= 3.4 for -not_before / -not_after (fixed validity, so the
# fixtures never expire on their own before 2050).
set -euo pipefail
# Git Bash on Windows would otherwise rewrite "/C=EE/..." into a filesystem path.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"
cd "$(dirname "$0")"

NOT_BEFORE=20200101000000Z
NOT_AFTER=20500101000000Z
DAYS_UNUSED=1

issue() { # name subject serial section key-generation-command...
  local name=$1 subject=$2 serial=$3 section=$4; shift 4
  "$@" >"$name.key.pem"
  openssl req -new -key "$name.key.pem" -subj "$subject" -out "$name.csr" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA ca.cert.pem -CAkey ca.key.pem -set_serial "$serial" \
    -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" -sha256 \
    -extfile extensions.cnf -extensions "$section" -out "$name.cert.pem" 2>/dev/null
  rm -f "$name.csr"
  echo "issued $name"
}

# Root CA: RSA 3072, self-signed.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out ca.key.pem 2>/dev/null
openssl req -x509 -new -key ca.key.pem -subj "/C=EE/O=allkiri test PKI/CN=allkiri Test CA" \
  -set_serial 1 -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" -sha256 \
  -config extensions.cnf -extensions ca -out ca.cert.pem 2>/dev/null
echo "issued ca"

issue signer-ec256 "/C=EE/CN=ALLKIRI,TESTER,38001085718/SN=ALLKIRI/GN=TESTER/serialNumber=PNOEE-38001085718" 1001 signer \
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve
issue signer-ec384 "/C=EE/CN=ALLKIRI,TESTER,38001085718/SN=ALLKIRI/GN=TESTER/serialNumber=PNOEE-38001085718" 1002 signer \
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve
issue signer-rsa "/C=EE/O=Allkiri OÜ/organizationIdentifier=NTREE-00000000/CN=Allkiri test e-seal" 1003 signer \
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
# An RSA key with a personal subject, for Smart-ID: its keys are always RSA, and
# the common name follows the profile SK has issued since 2019, which puts the
# given name first — the opposite of the older one the EC signers above use.
# Kept ASCII on purpose: Git Bash does not hand UTF-8 through to -subj, and the
# diacritics real Smart-ID subjects carry are covered by the integration test.
issue signer-rsa-person "/C=EE/CN=MARY ANN,OCONNEZ-SUSLIK TESTNUMBER/SN=OCONNEZ-SUSLIK TESTNUMBER/GN=MARY ANN/serialNumber=PNOEE-40504040001" 1004 signer \
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
# An ID-card authentication certificate. A real card carries two: this one for
# authentication (digitalSignature, clientAuth) and a signing one carrying
# nonRepudiation, which signer-ec384 above stands in for.
issue card-auth "/C=EE/CN=JOEORG,JAAK-KRISTJAN,38001085718/SN=JOEORG/GN=JAAK-KRISTJAN/serialNumber=PNOEE-38001085718" 1005 card-auth \
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve
issue tsa "/C=EE/O=allkiri test PKI/CN=allkiri Test TSA" 2001 tsa \
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve
issue ocsp "/C=EE/O=allkiri test PKI/CN=allkiri Test OCSP Responder" 3001 ocsp \
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve

for f in *.cert.pem; do openssl x509 -in "$f" -noout -subject -serial | tr '\n' ' '; echo; done
