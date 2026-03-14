# Troubleshooting Guide

## Common Errors

### `enclave init error: apply KMS policy: KMS key is locked to a different PCR0`

**Cause**: The KMS key has a PCR0-restricted policy from a previous enclave build. The current EIF has a different PCR0 (any code or dependency change produces a new PCR0).

**Fix**: Run `enclave migrate` to create a new KMS key locked to the new PCR0, or use `enclave lock` to apply the new PCR0 to the existing key (only works if the key policy still allows PutKeyPolicy).

### `enclave init error: load secrets from KMS: KMS secret loading timed out after 5m0s`

**Cause**: KMS Decrypt is failing repeatedly. Common reasons:
- PCR0 mismatch (see above)
- IAM role doesn't have KMS permissions
- IMDS proxy not reachable (enclave can't get AWS credentials)

**Fix**:
1. Check supervisor logs: `journalctl -u enclave-watchdog`
2. Verify the KMS key policy allows Decrypt for the EC2 role with the current PCR0
3. Verify IMDS is accessible: the enclave uses viproxy to reach the host's IMDS endpoint

### `enclave init error: generate attestation key: POST /enclave/hash status 403`

**Cause**: nitriding rejected the attestation key hash registration. This happens if the hash was already set (nitriding only accepts one hash registration per boot).

**Fix**: This usually means the supervisor restarted without the enclave restarting. Restart the full enclave: `systemctl restart enclave-watchdog`.

### `migration already in progress`

**Cause**: A previous migration is still running or was interrupted without cleanup.

**Fix**: The migration is idempotent. Wait for the current migration to complete, or re-run `enclave migrate` — it will resume from the last checkpoint.

### `secret value too large (N bytes, max 65536)`

**Cause**: Dynamic secret value exceeds the 64KB limit.

**Fix**: Reduce the secret value size. If you need to store larger data, use the storage API (`PUT /v1/storage/{key}`) which supports up to 10MB.



## Log Locations

| Component | Location | Command |
|-----------|----------|---------|
| Enclave supervisor | systemd journal | `journalctl -u enclave-watchdog -f` |
| Management server | systemd journal | `journalctl -u enclave-mgmt -f` |
| nitriding (TLS proxy) | Inside enclave, stdout | Appears in supervisor logs |
| CDK deploy | Terminal output | Check `cdk-outputs.json` for stack outputs |

All logs are JSON-structured. Use `jq` to filter:

```bash
# Show only errors
journalctl -u enclave-watchdog -o cat | jq 'select(.level == "ERROR")'

# Show KMS operations
journalctl -u enclave-watchdog -o cat | jq 'select(.msg | contains("KMS"))'

# Show HTTP requests slower than 1 second
journalctl -u enclave-watchdog -o cat | jq 'select(.duration_ms > 1000)'
```

## Debug Procedures

### Verify enclave is running

```bash
# From the EC2 host:
nitro-cli describe-enclaves

# Via management server:
curl http://127.0.0.1:8443/health
```

### Check enclave health and metrics

```bash
# Via nitriding's HTTPS endpoint (from host, self-signed cert):
curl -sk https://127.0.0.1:443/v1/enclave-info | jq .

# Check metrics:
curl -sk https://127.0.0.1:443/v1/enclave-info | jq .metrics
```

### Verify KMS key policy

```bash
DEPLOYMENT=dev
APP_NAME=myapp

# Get key ID from SSM
KEY_ID=$(aws ssm get-parameter --name "/$DEPLOYMENT/$APP_NAME/KMSKeyID" --query 'Parameter.Value' --output text)

# Get key policy
aws kms get-key-policy --key-id "$KEY_ID" --policy-name default --query Policy --output text | jq .
```

### Verify attestation

```bash
# Get attestation pubkey
curl -sk https://127.0.0.1:443/v1/enclave-info | jq -r .attestation_pubkey

# Verify a signed response
RESPONSE=$(curl -sk -D- https://127.0.0.1:443/v1/enclave-info)
# Check X-Attestation-Signature and X-Attestation-Pubkey headers
```

### Check secret ciphertexts in SSM

```bash
DEPLOYMENT=dev
APP_NAME=myapp

# List all parameters for this deployment
aws ssm get-parameters-by-path --path "/$DEPLOYMENT/$APP_NAME/" --query 'Parameters[].Name'

# Check if a specific secret has a ciphertext
aws ssm get-parameter --name "/$DEPLOYMENT/$APP_NAME/MySecret/Ciphertext" --query 'Parameter.Value' --output text
```

### Debug networking (vsock)

Inside the enclave, all external communication goes through vsock:
- **gvproxy**: vsock port 1024 — TCP proxy for outbound connections
- **nitriding**: listens on vsock for TLS-terminated inbound connections
- **IMDS proxy**: optional, provides AWS credentials via viproxy

```bash
# Check vsock device exists on host
ls -la /dev/vsock

# Check kernel modules
lsmod | grep vsock
```

### Debug storage

```bash
DEPLOYMENT=dev
APP_NAME=myapp

# Get bucket name
BUCKET=$(aws ssm get-parameter --name "/$DEPLOYMENT/$APP_NAME/StorageBucketName" --query 'Parameter.Value' --output text)

# List storage objects (encrypted)
aws s3 ls "s3://$BUCKET/data/"

# Check DEK ciphertext exists
aws ssm get-parameter --name "/$DEPLOYMENT/$APP_NAME/StorageDEK/Ciphertext" --query 'Parameter.Value' --output text | head -c 50
```
