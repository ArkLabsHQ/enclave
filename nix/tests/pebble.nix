# Pebble API TLS uses a throwaway CA trusted via ENCLAVE_NITRIDING_ACME_CA;
# its separate issuance root comes from the management API at test time.
# tlsPort=443 targets the enclave; dead httpPort=5002 makes HTTP-01 fail.
{ pkgs, apiIP }:
pkgs.runCommand "pebble-fixtures" { nativeBuildInputs = [ pkgs.openssl ]; } ''
  mkdir -p $out

  openssl ecparam -name prime256v1 -genkey -noout -out ca.key
  openssl req -x509 -new -key ca.key -days 3650 -sha256 \
    -subj "/CN=Enclave E2E Pebble API CA" -out $out/ca.crt

  # SANs cover enclave access via apiIP and AWS-node loopback checks.
  openssl ecparam -name prime256v1 -genkey -noout -out $out/api.key
  openssl req -new -key $out/api.key -subj "/CN=pebble-api" -out api.csr
  printf 'subjectAltName=IP:${apiIP},IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' > ext.cnf
  openssl x509 -req -in api.csr -days 3650 -sha256 \
    -CA $out/ca.crt -CAkey ca.key -CAcreateserial \
    -extfile ext.cnf \
    -out $out/api.crt

  cat > $out/pebble-config.json <<EOF
  {
    "pebble": {
      "listenAddress": "0.0.0.0:14000",
      "managementListenAddress": "127.0.0.1:15000",
      "certificate": "$out/api.crt",
      "privateKey": "$out/api.key",
      "httpPort": 5002,
      "tlsPort": 443,
      "ocspResponderURL": "",
      "externalAccountBindingRequired": false
    }
  }
  EOF
''
