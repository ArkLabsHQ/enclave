# Operations Guide

## Architecture Overview

The Simple Enclave framework runs three components:

1. **Enclave supervisor** (`enclave-supervisor`) — runs inside the Nitro Enclave. Manages attestation keys, KMS secrets, encrypted storage, and proxies requests to your app.
2. **Management server** (`mgmt`) — runs on the EC2 host at `127.0.0.1:8443`. Provides health checks, metrics, start/stop, key deletion, and migration endpoints.
3. **Your application** — runs inside the enclave as a child process of the supervisor.


## Monitoring

### Structured logs

All components output JSON-structured logs to stderr via `log/slog`. Log fields include:

- `time`, `level`, `msg` — standard slog fields
- `method`, `path`, `status`, `duration_ms` — HTTP request logs (supervisor)
- `step`, `total`, `status`, `msg` — migration progress (mgmt)
- `key_id`, `pcr0`, `error` — KMS/attestation operations

Logs are written to the systemd journal and can be viewed with:

```bash
journalctl -u enclave-watchdog -f        # enclave (supervisor + app)
journalctl -u enclave-mgmt -f            # management server
```

### Metrics

The supervisor exposes operational metrics in the `GET /v1/enclave-info` response under the `metrics` field:

| Metric | Description |
|--------|-------------|
| `http_requests` | Total HTTP requests handled |
| `http_errors` | Requests returning 4xx/5xx |
| `kms_operations` | KMS Decrypt calls (DEK decryption) |
| `kms_errors` | Failed KMS Decrypt calls |
| `storage_reads` | S3 GetObject calls |
| `storage_writes` | S3 PutObject calls |
| `storage_deletes` | S3 DeleteObject calls |
| `storage_errors` | Failed storage operations |
| `secret_reads` | Dynamic secret reads |
| `secret_writes` | Dynamic secret writes |
| `secret_deletes` | Dynamic secret deletes |

The management server proxies nitriding's Prometheus metrics at `GET /metrics`.

### Health checks

- **Supervisor**: `GET /health` returns `{"status":"ready"}` when initialized, `503` during init or on error
- **Management**: `GET /health` runs `nitro-cli describe-enclaves` and returns enclave state

## Scaling

### Vertical scaling

Change the `instance_type` in `enclave.yaml` and redeploy. The instance must be from a Nitro Enclave-supported family (m5, m6i, c5, c6i, r5, r6i, etc.).

Enclave CPU and memory are configured in `enclave.yaml` (passed to `nitro-cli run-enclave`). Ensure the enclave allocation leaves enough resources for the host.

### Horizontal scaling

The framework currently deploys a single EC2 instance. For horizontal scaling:

1. Deploy multiple instances behind a load balancer
2. Each instance gets its own enclave with the same PCR0
3. All instances share the same KMS key (PCR0-restricted) and SSM parameters
4. Storage (S3) is shared — ensure your app handles concurrent access

## Instance Failure Recovery

### Automatic recovery

The enclave runs under a systemd watchdog service (`enclave-watchdog`) with `Restart=always`. If the enclave process crashes, systemd restarts it automatically.

### Manual recovery

If the EC2 instance itself fails:

1. The CDK stack creates a new instance from the same AMI
2. The new instance boots, runs `user_data` which starts the enclave
3. The enclave decrypts secrets from SSM using KMS attestation (same PCR0)
4. Storage data persists in S3 — the new instance picks up where the old one left off

### Disaster recovery

If the KMS key is compromised or needs replacement:

1. Use `enclave migrate` to create a new KMS key locked to a new PCR0
2. The migration exports secrets under the new key, replaces the EIF, and restarts
3. The old KMS key is scheduled for deletion (7-day pending window)

## Migration

The `enclave migrate` command performs a locked-key migration in 9 steps:

1. Read current KMS key ID
2. Create new KMS key with transitional policy
3. Apply transitional KMS policy (Encrypt + PutKeyPolicy, no Decrypt)
4. Store migration parameters in SSM
5. Call `POST /v1/export-key` on old enclave (re-encrypts secrets under new key)
6. Poll for migration ciphertexts in SSM
7. Adopt ciphertexts and update KMS key ID
8. Download new EIF, stop old enclave, replace, restart
9. Clean up migration SSM parameters

The new enclave self-applies a PCR0-restricted policy on boot, locking Decrypt to its attestation identity. The old KMS key is scheduled for deletion by the new enclave.

**Idempotency**: if migration fails partway, re-running it resumes from the last checkpoint (MigrationKMSKeyID in SSM).

## Deployment

### Deploy

```bash
enclave deploy
```

This runs `cdk deploy` with the configuration from `enclave.yaml`, builds the EIF, uploads it to S3, and starts the enclave.

### Destroy

```bash
enclave destroy
```

**Warning**: this deletes all infrastructure including the KMS key and S3 bucket. Secrets and storage data will be permanently lost.

### Status

```bash
enclave status
```

Shows the current enclave state, instance ID, and CDK stack outputs.
