#!/usr/bin/env bash
# Generate a throwaway CA + an HTTPS server certificate for the local Pebble
# ACME server used by the end-to-end ACME test (test/acme-test.sh).
#
# The server cert's SAN includes host.containers.internal — the name the
# enclave uses to reach Pebble's ACME directory through gvproxy. The CA cert
# is fed to the enclave (ENCLAVE_NITRIDING_ACME_CA) so its ACME client trusts
# Pebble's API endpoint.
#
# Run host-side by `make test-acme` BEFORE docker compose brings Pebble up —
# Pebble reads the cert at startup. Output is git-ignored (see .gitignore).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

# Throwaway P-256 CA (1-day validity — regenerated every run).
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/pebble-ca.key"
openssl req -x509 -new -key "$DIR/pebble-ca.key" -days 1 -sha256 \
  -subj "/CN=Pebble Test CA" -out "$DIR/pebble-ca.crt"

# Pebble API server cert, signed by the CA, SAN host.containers.internal.
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/pebble-cert.key"
openssl req -new -key "$DIR/pebble-cert.key" \
  -subj "/CN=host.containers.internal" -out "$DIR/pebble-cert.csr"
openssl x509 -req -in "$DIR/pebble-cert.csr" -days 1 -sha256 \
  -CA "$DIR/pebble-ca.crt" -CAkey "$DIR/pebble-ca.key" -CAcreateserial \
  -extfile <(printf 'subjectAltName=DNS:host.containers.internal,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n') \
  -out "$DIR/pebble-cert.pem"

rm -f "$DIR/pebble-cert.csr" "$DIR/pebble-ca.srl"
echo "Generated Pebble CA + API cert (SAN host.containers.internal) in $DIR"
