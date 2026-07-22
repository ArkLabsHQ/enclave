# Operations Guide

This is the authoritative operator runbook. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the authoritative protocol, wire-format,
trust, and canonical-selection details.

## Architecture Overview

The Simple Enclave framework runs three components:

1. **Runtime** (`runtime`) — runs inside the Nitro Enclave. Manages attestation keys, KMS secrets, encrypted storage, and proxies requests to your app.
2. **Supervisor** (`supervisor`) — runs on the EC2 host at `127.0.0.1:8443`. Provides health checks, metrics, start/stop, key deletion, and migration endpoints.
3. **Your application** — runs inside the enclave as a child process of the supervisor.


## Monitoring

### Structured logs

All components output JSON-structured logs to stderr via `log/slog`. Log fields include:

- `time`, `level`, `msg` — standard slog fields
- `method`, `path`, `status`, `duration_ms` — HTTP request logs (supervisor)
- `step`, `total`, `status`, `msg` — migration progress (supervisor)
- `key_id`, `pcr0`, `error` — KMS/attestation operations

Logs are written to the systemd journal and can be viewed with:

```bash
journalctl -u enclave-supervisor -f      # host supervisor (gvproxy + IMDS + lifecycle + management API)
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

The host-side `enclave-supervisor.service` runs with `Restart=always`. Inside that process, the supervisor's watchdog auto-restarts the enclave with bounded backoff (1s → 30s) when `nitro-cli describe-enclaves` shows it's no longer running; if the supervisor itself exits, systemd brings it back (which relaunches gvproxy, IMDS forwarder, and watchdog).

### Manual recovery

If the EC2 instance itself fails:

1. The OpenTofu module creates a new instance from the same AMI
2. The new instance boots, runs `user_data` which starts the enclave
3. The enclave decrypts secrets from SSM using KMS attestation (same PCR0)
4. Storage data persists in S3 — the new instance picks up where the old one left off

### Disaster recovery

If the KMS key is compromised or needs replacement:

1. Build and publish a PCR0-addressed candidate with `enclave build`, `enclave
   tofu`, and `tofu apply`.
2. Use the manual request, status, and finalise procedure below.
3. Independently verify the activated enclave against the candidate PCR0.

## Migration

### Security posture

The EC2 host has no direct KMS plaintext path in either policy mode. KMS
`Decrypt` is recipient-attestation and PCR0 gated, and the response is wrapped to
an ephemeral key held inside the enclave.

- Default `is_kms_key_locked: false`: AWS account root can rewrite the policy
  through `kms:PutKeyPolicy`, but root never has direct `kms:Decrypt`.
- Strict `is_kms_key_locked: true`: no principal, including account root, can
  rewrite the policy after key creation.

### Publish the candidate

```bash
enclave build
enclave tofu
tofu -chdir=tofu init
tofu -chdir=tofu apply
```

An apply publishes a candidate; it does not automatically request, finalise, or
activate a migration on an existing host. Migration resolves these OpenTofu
outputs:

```bash
tofu -chdir=tofu output candidate_pcr0
tofu -chdir=tofu output candidate_artifact_bucket
tofu -chdir=tofu output candidate_eif_key
tofu -chdir=tofu output candidate_supervisor_key
tofu -chdir=tofu output migration_intent_bucket
tofu -chdir=tofu output instance_id
```

Candidate artifacts use these PCR0-addressed keys:

```text
candidates/<pcr0>/enclave.eif
candidates/<pcr0>/supervisor
```

### Commands and flags

The migration command group is:

```bash
enclave migration request
enclave migration status
enclave migration abort
enclave migration finalise
enclave migration finalise --resume
```

All four subcommands inherit these persistent flags:

| Flag | Resolution and use |
|---|---|
| `--region` | AWS region; defaults to `enclave.yaml` |
| `--profile` | AWS named profile; defaults to `enclave.yaml` |
| `--instance-id` | Remote EC2 instance; defaults to Tofu `instance_id` |
| `--supervisor-url` | Direct supervisor URL for local request, abort, or finalise |
| `--enclave-url` | Direct enclave URL for local status |
| `--target-pcr0` | Candidate PCR0; defaults to Tofu `candidate_pcr0`, with local `pcr.json` fallback for request and finalise |
| `--artifact-bucket` | Defaults to Tofu `candidate_artifact_bucket` |
| `--eif-key` | Defaults to Tofu `candidate_eif_key` |
| `--supervisor-key` | Defaults to Tofu `candidate_supervisor_key` |

Remote transport is AWS Systems Manager Session Manager port forwarding using
`AWS-StartPortForwardingSession`, not Run Command. Mutation commands forward to
host port `8443`; status forwards to enclave HTTPS port `443`. Install AWS CLI
v2 and the Session Manager plugin.

### Request, status, and abort

Publish a request for the resolved candidate:

```bash
enclave migration request
```

The host forwards the mutation over parent-only vsock port `8003` to
`POST /request-migration`. The source enclave attests and appends a new
`requested` version to the public S3 migration-intent log.

Observe derived status:

```bash
enclave migration status
```

States are exactly `none`, `cooling_down`, `eligible`, and `aborted`.

| Field | Public JSON applicability |
|---|---|
| `state` | Always |
| `source_pcr0` | Always after NSM PCR0 can be read, including `none` |
| `target_pcr0` | A valid request or abort head exists |
| `sequence` | A valid head exists |
| `action` | A valid head exists; `requested` or `aborted` |
| `published_at` | A valid head exists; exact version's S3 `LastModified` |
| `eligible_at` | Requested head only |
| `remaining_seconds` | `cooling_down` only, rounded up |

The CLI prints every label, rendering omitted strings as `<unset>` and omitted
numbers as `0`. Public status is derived; the S3 log is authoritative.

A zero cooldown still requires a matching published request. That request is
immediately `eligible`.

Abort before finalisation if needed:

```bash
enclave migration abort
```

Abort appends `action=aborted` at the next sequence and retains the current
target PCR0. It does not erase history. A later request can append another
sequence. Do not use abort as rollback after enclave finalisation changes active
KMS state.

### Finalise and activate

After status is `eligible` for the intended target:

```bash
enclave migration finalise
```

The source enclave validates the authoritative request, commits the target PCR0
to PCR31, creates a migration KMS key admitting source and target PCR0,
re-encrypts static secrets and the storage DEK, writes transition evidence, and
updates active `KMSKeyID`. The host then backs up the current EIF, downloads the
PCR0-addressed candidate, stops the source, swaps the EIF, and starts the
candidate.

If candidate start or the current post-start probe fails, the host restores the
EIF backup and restarts the source. The migration key admits both PCR0s and the
transition receipt supports that rollback path.

> **Current activation limitation: steps 10/11 are not implemented.** After the
> EIF swap, the supervisor treats `GET /v1/enclave-info` HTTP 200 as sufficient
> readiness. It does not obtain fresh attestation and prove that PCR0 equals the
> requested target, it does not require runtime `GET /health` readiness, and it
> does not implement the intended verified cleanup ordering. Current code then
> removes the EIF backup and may update the supervisor, but that sequence is not
> a verified activation/cleanup protocol. Migration completion must not be read
> as evidence that those checks occurred.

Independently verify the live candidate after the operation:

```bash
enclave verify \
  --base-url https://<enclave-address> \
  --expected-pcr0 <candidate-pcr0>
```

This live-enclave check is not automatically part of migration activation and
does not verify migration-log history.

### Narrow resume

Use `--resume` only when enclave finalisation definitely succeeded and a later
host staging, swap, start, or orchestration step failed, with the same target and
artifacts still intended:

```bash
enclave migration finalise --resume
```

`--resume` skips `POST /finalise-migration` and retries host activation. It does
not bypass a missing, cooling, mismatched, or aborted request, and it is not safe
when finalisation success is uncertain.

### Authoritative S3 log

Object keys have this exact form:

```text
migration-intent/<96 lowercase source PCR0>/<20 digit sequence>
```

The object is strict JSON with exactly these fields:

```json
{
  "schema": "enclave.migration_intent.v1",
  "sequence": 1,
  "action": "requested",
  "target_pcr0": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "attestation": "<base64 Nitro COSE_Sign1 document>"
}
```

The attestation `UserData` is deterministic canonical CBOR containing exactly
`schema`, `bucket_name`, `sequence`, `action`, and `target_pcr0`. The source PCR0
comes from the attestation and object key. The exact S3 version's `LastModified`
is publication time.

Canonical selection verifies all versions, ignores invalid versions, chooses the
highest valid sequence, and then the earliest `LastModified` at that sequence.
An exact earliest-timestamp tie fails closed. The maximum sequence is retained
through ambiguity so a later request can append past it.

Discover the bucket and anonymously inspect every version:

```bash
REGION=us-east-1
BUCKET="$(tofu -chdir=tofu output -raw migration_intent_bucket)"
printf 'migration intent bucket: %s\n' "$BUCKET"

SOURCE_PCR0=<96-lowercase-source-pcr0>
PREFIX="migration-intent/${SOURCE_PCR0}/"

aws s3api list-object-versions \
  --bucket "$BUCKET" \
  --prefix "$PREFIX" \
  --region "$REGION" \
  --no-sign-request \
  --query 'Versions[].{Key:Key,VersionId:VersionId,LastModified:LastModified,IsLatest:IsLatest}' \
  --output json
```

Fetch one exact version using the returned version ID:

```bash
KEY="migration-intent/${SOURCE_PCR0}/00000000000000000001"
VERSION_ID='<exact VersionId from list-object-versions>'

aws s3api get-object \
  --bucket "$BUCKET" \
  --key "$KEY" \
  --version-id "$VERSION_ID" \
  --region "$REGION" \
  --no-sign-request \
  ./migration-intent.json
```

No migration-log verifier CLI is shipped. A conceptual verifier must enforce the
key and strict JSON schema, verify the Nitro certificate chain and COSE
signature, match source PCR0 plus sequence/action/target, reconstruct canonical
CBOR including bucket identity, and apply exact-version `LastModified` canonical
selection. Existing `enclave verify` checks a live enclave and is different.

Public version history makes hidden forks detectable, not prevented. A retained
clone with the same source PCR0 and valid state can append competing valid
entries; the protocol does not prove enclave uniqueness.

## Deployment

### Deploy

```bash
enclave tofu
cd tofu && tofu init && tofu apply
```

`enclave tofu` scaffolds the OpenTofu module from the configuration in
`enclave.yaml`. On first deployment, `tofu apply` provisions infrastructure,
uploads the selected candidate, and creates the host. On an existing deployment,
an apply publishes candidate artifacts but migration activation remains manual.

### Destroy

```bash
cd tofu && tofu destroy
```

**Warning**: this deletes all infrastructure including the KMS key and S3 bucket. Secrets and storage data will be permanently lost.

### Status

```bash
enclave status
```

Shows the current enclave state, instance ID, and tofu outputs.


## Wire-format notes

- `GET /v1/enclave-info` is externally readable and includes the derived
  `migration` object described above.
- Parent-only migration mutations use vsock port `8003` routes
  `POST /request-migration` and `POST /finalise-migration`.
- The S3 migration-intent log, not the public status object, is authoritative.
