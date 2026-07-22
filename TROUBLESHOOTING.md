# Troubleshooting Guide

## Common Errors

### `enclave init error: apply KMS policy: KMS key is locked to a different PCR0`

**Cause**: The KMS key has a PCR0-restricted policy from a previous enclave build. The current EIF has a different PCR0 (any code or dependency change produces a new PCR0).

**Fix**: Publish the candidate, then run `enclave migration request`, wait for
`enclave migration status` to report `eligible`, and run `enclave migration
finalise`. See [OPERATIONS.md](OPERATIONS.md#migration). OpenTofu publication
alone does not activate the new PCR0.

### `enclave init error: load secrets from KMS: KMS secret loading timed out after 5m0s`

**Cause**: KMS Decrypt is failing repeatedly. Common reasons:
- PCR0 mismatch (see above)
- IAM role doesn't have KMS permissions
- IMDS proxy not reachable (enclave can't get AWS credentials)

**Fix**:
1. Check supervisor logs: `journalctl -u enclave-supervisor`
2. Verify the KMS key policy allows Decrypt for the EC2 role with the current PCR0
3. Verify IMDS is accessible: the enclave uses viproxy to reach the host's IMDS endpoint

### `enclave init error: generate attestation key: POST /enclave/hash status 403`

**Cause**: nitriding rejected the attestation key hash registration. This happens if the hash was already set (nitriding only accepts one hash registration per boot).

**Fix**: This usually means the supervisor restarted without the enclave restarting. Restart the full stack: `systemctl restart enclave-supervisor`.

### `migration already in progress`

**Cause**: The host serializes request, abort, and finalise operations; another
operation currently holds the migration lock.

**Fix**: Wait for that operation and inspect `journalctl -u enclave-supervisor`.
Do not assume a generic retry is idempotent. Use `enclave migration finalise
--resume` only if enclave finalisation definitely succeeded and a later host
orchestration step failed.

### Migration status is `none`, `cooling_down`, or `aborted`

- `none`: no valid request head exists for this source PCR0. Publish one with
  `enclave migration request`.
- `cooling_down`: wait until `eligible_at`. Cooldown is derived from the selected
  S3 version's `LastModified`; there is no host timer to restart.
- `aborted`: publish a new request if the candidate is still intended.

A zero cooldown still requires a matching published request, which is then
immediately eligible.

### Migration intent head is ambiguous or unavailable

An exact earliest-`LastModified` tie at the highest valid sequence fails closed.
The sequence is retained, so a new request can append past the ambiguity. S3
list, exact-version fetch, or read failures are reported as store unavailability,
not `none`.

Use the anonymous `list-object-versions` and exact-version `get-object` commands
in [OPERATIONS.md](OPERATIONS.md#authoritative-s3-log). Preserve all versions;
do not inspect only `IsLatest`.

### Candidate identity or readiness verification rolled the EIF back

After candidate start, the supervisor uses a fresh raw `http.Client`, not a
verified enclave client, to require `/health` HTTP 200 with status `ready` and
an exact lowercase target in `/v1/enclave-info` at
`migration.source_pcr0`. Wrong or malformed identity, non-ready or malformed
responses, transport failure, and timeout all prevent cleanup and roll the EIF
back.

Inspect the migration output and host journal for `new enclave verification
failed` followed by rollback events. Before rollback completes, or while
diagnosing a candidate manually, compare both operational responses with the
intended PCR0:

```bash
EXPECTED_PCR0="$(tofu -chdir=tofu output -raw candidate_pcr0)"
curl -sk https://127.0.0.1:443/health | jq .
curl -sk https://127.0.0.1:443/v1/enclave-info \
  | jq --arg expected "$EXPECTED_PCR0" \
    '{reported: .migration.source_pcr0, expected: $expected}'
enclave verify --base-url https://<enclave-address> --expected-pcr0 <candidate-pcr0>
```

After automatic rollback, these endpoints normally report the restored source,
so use the journal to diagnose the failed candidate. HTTP 503 and startup
transport failures are retried until the readiness timeout; invalid HTTP 200
content, a non-200/non-503 response, or a wrong PCR0 fails immediately.

The supervisor probes are operational only. They do not verify a nonce-bound
Nitro attestation, Nitro certificate chain, TLS identity, or locally derived EIF
PCR. `enclave verify` is the separate cryptographic operation. No migration-log
verifier CLI is shipped.

### State-origin receipt startup failure

The active KMS key and current lowercase PCR0 select one exact regular receipt.
Inspect the active key, exact receipt, transition receipt, and receipt siblings:

```bash
DEPLOYMENT=dev
APP_NAME=myapp
LOCK_SEGMENT=unlocked  # use locked when is_kms_key_locked=true
CURRENT_PCR0=<96-lowercase-current-pcr0>

KEY_ID="$(aws ssm get-parameter \
  --name "/$DEPLOYMENT/$APP_NAME/$LOCK_SEGMENT/KMSKeyID" \
  --query 'Parameter.Value' --output text)"
REGULAR="/$DEPLOYMENT/$APP_NAME/StateOriginReceipt/$KEY_ID/$CURRENT_PCR0"
TRANSITION="/$DEPLOYMENT/$APP_NAME/MigrationStateOriginReceipt/$KEY_ID"

aws ssm get-parameter --name "$REGULAR" --query 'Parameter.Name' --output text
aws ssm get-parameter --name "$TRANSITION" --query 'Parameter.Name' --output text
aws ssm get-parameters-by-path \
  --path "/$DEPLOYMENT/$APP_NAME/StateOriginReceipt/$KEY_ID/" \
  --recursive --query 'Parameters[].Name' --output text
```

- If the exact regular receipt exists, any signature, purpose, state-root, or
  PCR0 verification failure is fatal. The runtime does not try the transition
  receipt.
- If the exact regular receipt is absent, the transition receipt,
  `MigrationPreviousPCR0`, and `MigrationPreviousPCR0Attestation` must exist and
  verify against an exact two-PCR KMS policy. A receipt for the other admitted
  PCR0 is neither used nor treated as a blocker.
- The legacy `StateOriginReceipt/<kms-key-id>` path is never read. Do not create
  it as a workaround.
- A regular receipt may exist even when later freshness, listener, environment,
  secret, or child startup failed. It proves state adoption, not readiness.
- Receipts under an old key such as K-AB remain deliberate rollback evidence,
  but are ignored after active `KMSKeyID` moves to K-AC.

For a non-genesis source, rollback-to-self can use its own exact receipt or the
transition evidence when that receipt is absent. The separately tracked genesis
rollback-to-self defect remains out of scope, so a failed first-generation
activation may not restore a genesis source correctly.

### `secret value too large (N bytes, max 65536)`

**Cause**: Dynamic secret value exceeds the 64KB limit.

**Fix**: Reduce the secret value size. If you need to store larger data, use the storage API (`PUT /v1/storage/{key}`) which supports up to 10MB.



## Log Locations

| Component | Location | Command |
|-----------|----------|---------|
| Host supervisor (gvproxy, IMDS, lifecycle, management API) | systemd journal | `journalctl -u enclave-supervisor -f` |
| In-enclave runtime (nitriding, app, runtime binary) | `GET /enclave-logs` via supervisor | Appears in supervisor's CloudWatch stream |
| OpenTofu deploy | Terminal output | Run `tofu output` for deployment outputs |

All logs are JSON-structured. Use `jq` to filter:

```bash
# Show only errors
journalctl -u enclave-supervisor -o cat | jq 'select(.level == "ERROR")'

# Show KMS operations
journalctl -u enclave-supervisor -o cat | jq 'select(.msg | contains("KMS"))'

# Show HTTP requests slower than 1 second
journalctl -u enclave-supervisor -o cat | jq 'select(.duration_ms > 1000)'
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
LOCK_SEGMENT=unlocked  # use locked when is_kms_key_locked=true

# Get key ID from SSM
KEY_ID=$(aws ssm get-parameter --name "/$DEPLOYMENT/$APP_NAME/$LOCK_SEGMENT/KMSKeyID" --query 'Parameter.Value' --output text)

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
LOCK_SEGMENT=unlocked  # use locked when is_kms_key_locked=true
KEY_ID=$(aws ssm get-parameter --name "/$DEPLOYMENT/$APP_NAME/$LOCK_SEGMENT/KMSKeyID" --query 'Parameter.Value' --output text)

# List all parameters for this deployment
aws ssm get-parameters-by-path --path "/$DEPLOYMENT/$APP_NAME/" --query 'Parameters[].Name'

# Check if a specific secret has a ciphertext
aws ssm get-parameter --name "/$DEPLOYMENT/$APP_NAME/$LOCK_SEGMENT/MySecret/Ciphertext/$KEY_ID" --query 'Parameter.Value' --output text
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
LOCK_SEGMENT=unlocked

# Get bucket name
BUCKET=$(aws ssm get-parameter --name "/$DEPLOYMENT/$APP_NAME/StorageBucketName" --query 'Parameter.Value' --output text)

# List storage objects (encrypted)
aws s3 ls "s3://$BUCKET/data/"

# Check DEK ciphertext exists
KEY_ID=$(aws ssm get-parameter --name "/$DEPLOYMENT/$APP_NAME/$LOCK_SEGMENT/KMSKeyID" --query 'Parameter.Value' --output text)
aws ssm get-parameter --name "/$DEPLOYMENT/$APP_NAME/$LOCK_SEGMENT/StorageDEK/Ciphertext/$KEY_ID" --query 'Parameter.Value' --output text | head -c 50
```
