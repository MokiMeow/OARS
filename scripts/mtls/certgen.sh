#!/bin/sh
set -eu

CERT_DIR="${CERT_DIR:-/certs}"
CA_CN="${CA_CN:-oars-dev-ca}"
SERVER_CN="${SERVER_CN:-oars}"
CLIENT_CN="${CLIENT_CN:-oars-worker}"

mkdir -p "$CERT_DIR"

echo "[certgen] Generating CA..."
openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 3650 \
  -subj "/CN=${CA_CN}" \
  -keyout "${CERT_DIR}/ca.key" \
  -out "${CERT_DIR}/ca.crt" >/dev/null 2>&1

echo "[certgen] Generating server cert..."
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=${SERVER_CN}" \
  -keyout "${CERT_DIR}/server.key" \
  -out "${CERT_DIR}/server.csr" >/dev/null 2>&1

cat > "${CERT_DIR}/server.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:oars,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -sha256 -days 825 \
  -in "${CERT_DIR}/server.csr" \
  -CA "${CERT_DIR}/ca.crt" \
  -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/server.crt" \
  -extfile "${CERT_DIR}/server.ext" >/dev/null 2>&1

echo "[certgen] Generating client cert..."
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=${CLIENT_CN}" \
  -keyout "${CERT_DIR}/client.key" \
  -out "${CERT_DIR}/client.csr" >/dev/null 2>&1

cat > "${CERT_DIR}/client.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

openssl x509 -req -sha256 -days 825 \
  -in "${CERT_DIR}/client.csr" \
  -CA "${CERT_DIR}/ca.crt" \
  -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/client.crt" \
  -extfile "${CERT_DIR}/client.ext" >/dev/null 2>&1

fp="$(openssl x509 -in "${CERT_DIR}/client.crt" -noout -fingerprint -sha256 | awk -F= '{print $2}' | tr -d ':')"
cat > "${CERT_DIR}/trusted-identities.json" <<EOF
[
  {
    "subject": "${CLIENT_CN}",
    "fingerprintSha256": "${fp}"
  }
]
EOF

echo "[certgen] Done."
echo "[certgen] Wrote:"
echo "  - ${CERT_DIR}/ca.crt"
echo "  - ${CERT_DIR}/server.crt"
echo "  - ${CERT_DIR}/server.key"
echo "  - ${CERT_DIR}/client.crt"
echo "  - ${CERT_DIR}/client.key"
echo "  - ${CERT_DIR}/trusted-identities.json"

