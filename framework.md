# Introspector Enclave Framework — Technical Report

## Executive Summary

Introspector Enclave is a **CLI framework and runtime SDK** for deploying applications inside **AWS Nitro Enclaves** with hardware-backed secret management, cryptographic attestation, and reproducible builds. It enables any Go HTTP server to run inside a Nitro Enclave with zero enclave-specific application code — the framework handles all infrastructure concerns (secret lifecycle, attestation, TLS, networking, upgrades).

KMS plaintext is recipient-attestation wrapped to the enclave, so the EC2 host
has no direct decrypt path in either policy mode. Account-root policy-rewrite
resistance applies only with `is_kms_key_locked: true`; in the default mode root
can rewrite policy but never has direct `kms:Decrypt`.

[ARCHITECTURE.md](ARCHITECTURE.md) is the authoritative technical reference and
[OPERATIONS.md](OPERATIONS.md) is the authoritative operator runbook.

---

## Architecture Overview

```
                        Internet (HTTPS :443)
                              │
┌─────────────────────────────▼────────────────────────────────┐
│                   AWS EC2 Instance (Host)                     │
│                                                              │
│  ┌───────────────────────────────────────────────────────┐   │
│  │          enclave-supervisor.service (single binary)   │   │
│  │   • gvproxy (in-process, vsock:1024)                  │   │
│  │   • IMDS AF_VSOCK forwarder (vsock:2:8002 → IMDS:80)  │   │
│  │   • Watchdog (nitro-cli run/terminate + restart loop) │   │
│  │   • Management API (127.0.0.1:8443)                   │   │
│  └───────────────────────────┬───────────────────────────┘   │
│                              │ vsock                         │
└──────────────────────────────┼───────────────────────────────┘
                               │
┌───────▼────────────────▼────────────────────────────────────┐
│              AWS Nitro Enclave (Isolated VM)                  │
│                                                              │
│  ┌──────────────────────────────────────────────┐            │
│  │  nitriding (TLS terminator + attestation)    │            │
│  │  :443 external  →  :7073 internal            │            │
│  └──────────────────┬───────────────────────────┘            │
│                     │                                        │
│  ┌──────────────────▼───────────────────────────┐            │
│  │  runtime             │            │
│  │  • Secret loading (KMS + attestation)         │            │
│  │  • Response signing (Schnorr BIP-340)         │            │
│  │  • PCR management                            │            │
│  │  • Management API (/v1/*)                    │            │
│  │  • Reverse proxy → user app                  │            │
│  └──────────────────┬───────────────────────────┘            │
│                     │                                        │
│  ┌──────────────────▼───────────────────────────┐            │
│  │  User Application (plain HTTP server :7074)   │            │
│  │  • No enclave-specific code needed           │            │
│  │  • Secrets available as env vars             │            │
│  └──────────────────────────────────────────────┘            │
│                                                              │
│  ┌────────────┐                                              │
│  │  viproxy   │ → IMDS credentials via vsock                 │
│  └────────────┘                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## CLI Commands

### Lifecycle Workflow

```
enclave init  →  enclave setup  →  enclave tofu  →  enclave build  →  tofu apply
                                                                    →  enclave verify
                                                                    →  enclave status
                                                                    →  enclave migration ...
                                                                    →  tofu destroy
```

### 1. `enclave init` — Project Scaffolding

Generates the build-time files needed to compile an EIF:

| File | Purpose |
|------|---------|
| `enclave/enclave.yaml` | Configuration (secrets, app source, region, etc.) |
| `enclave/flake.nix` | Language-specific Nix build definition |
| `.github/workflows/*.yml` | CI templates (build-eif, deploy-enclave, verify-enclave, destroy-enclave) |

On subsequent runs, validates the configuration and reports errors. The
OpenTofu deployment scaffold is **not** generated here — run
`enclave tofu` separately when you're ready to deploy.

### 1a. `enclave tofu` — Deployment Scaffold

Writes a consolidated OpenTofu module tree to `./tofu/` at the repo root —
one `main.tf` per module, plus the `user_data.sh.tftpl` cloud-init
template. Merge-only-new: existing files are preserved so local
customizations to any merged `main.tf` survive re-runs. Also rewrites
`tofu/terraform.tfvars.json` from the current `enclave.yaml` on every
invocation.

| File | Purpose |
|------|---------|
| `tofu/main.tf` | Root module — provider, module call into `./modules/enclave`, variables, outputs |
| `tofu/modules/backend/main.tf` | S3 state bucket + DynamoDB lock table bootstrap (run separately) |
| `tofu/modules/enclave/main.tf` | Merged resources: KMS, IAM, S3, SSM, VPC, EC2, with section banners |
| `tofu/modules/enclave/templates/user_data.sh.tftpl` | EC2 cloud-init — inlines the `enclave-supervisor.service` systemd unit, which runs the supervisor binary owning gvproxy, the IMDS forwarder, the enclave lifecycle watchdog, and the management API in one process |

**Artifact source.** By default `terraform.tfvars.json` points at
`.enclave/artifacts/{image.eif,supervisor}` so tofu uploads what
`enclave build` produced. With `--remote`, those paths are left empty
and the module's bundled `null_resource.download_artifacts` curls
`image.eif` and `supervisor` from
`github.com/{app.nix_owner}/{app.nix_repo}/releases/download/{app.release_tag}/`
at apply time before uploading to S3. The `release_tag` field in
`enclave.yaml` (default `"eif-latest"`) selects which release to pull.

**KMS lock recovery (`is_kms_key_locked`).** The KMS key the runtime
locks at first boot grants the AWS account principal (root + any IAM
admin in the account) `kms:PutKeyPolicy`, `kms:GetKeyPolicy`, and
`kms:DescribeKey` by default. **Root never has direct Decrypt** —
recovery means rewriting the policy to add a new PCR0 condition that
a freshly-deployed enclave can attest to, so plaintext stays inside
an attested enclave even during recovery. Set `is_kms_key_locked:
true` in `enclave.yaml` for strict mode where the locked policy is
permanently frozen and only the attested enclave can decrypt; this
is permanent at first lock and cannot be modified after.

### 2. `enclave setup` — Auto-Populate Nix Hashes

Detects the GitHub remote, computes Nix source and vendor hashes for the user's app, and writes them to `enclave.yaml`.

### 3. `enclave build` — Reproducible EIF Build

Builds the Enclave Image File (EIF) using **Nix inside Docker** for full reproducibility:

1. Generates `build-config.json` from `enclave.yaml`
2. Runs `nix build .#eif` (fetches user app + SDK from GitHub, pins all dependencies)
3. Outputs `.enclave/artifacts/image.eif` + `.enclave/artifacts/pcr.json` (PCR0/1/2 measurements)

Anyone can rebuild the same EIF and get identical PCR values, proving the binary hasn't been tampered with.

### 4. `enclave tofu` + `tofu apply` — AWS Deployment

Publishes infrastructure and candidates:

**Fresh deploy:**
- `enclave tofu` scaffolds the OpenTofu module, then `tofu apply` provisions the infrastructure (VPC, EC2, KMS, SSM, IAM, EIP)
- The first enclave boot creates the primary key with a PCR0 attestation condition
- Waits for instance readiness

**Candidate update:**
- Uploads `candidates/<pcr0>/enclave.eif` and
  `candidates/<pcr0>/supervisor`
- Exports `candidate_pcr0`, `candidate_artifact_bucket`, `candidate_eif_key`,
  `candidate_supervisor_key`, and `migration_intent_bucket`
- Does not automatically migrate or activate an existing deployment

### 5. `enclave verify` — Attestation Verification

Three independent verification checks:

1. **NSM attestation** — Fetches hardware-signed attestation document, validates nonce and PCR0
2. **Attestation key binding** — Verifies the supervisor's signing key is registered in the attestation document (SHA256 of pubkey in UserData)
3. **PCR0 chain** — Verifies the upgrade history (each enclave records its predecessor's PCR0 + attestation)

### 6. `enclave status` — Instance Health

Shows instance state, KMS key state, lock status, and enclave version.

### 7. `enclave migration request|status|abort|finalise`

Runs the explicit candidate migration protocol. `request` and `abort` publish
attested S3 intent versions, `status` derives the canonical public state, and
`finalise` transfers state and asks the host to activate the candidate.
`finalise --resume` is only for retrying host orchestration after enclave
finalisation definitely succeeded. Persistent flags and the complete procedure
are in [OPERATIONS.md](OPERATIONS.md#commands-and-flags).

### 8. `tofu destroy` — Teardown

Destroys all AWS infrastructure via `tofu destroy`.

---

## Secret Management

### Lifecycle

```
┌─ First Boot ─────────────────────────────────────┐
│  1. Generate 32 cryptographically random bytes     │
│  2. Encrypt with KMS (RSA-OAEP via attestation)    │
│  3. Store ciphertext in AWS SSM Parameter Store    │
│  4. Extend PCR16+i with SHA256(secret_pubkey)      │
└────────────────────────────────────────────────────┘

┌─ Subsequent Boots ───────────────────────────────┐
│  1. Read ciphertext from SSM                       │
│  2. Generate ephemeral 2048-bit RSA keypair (NSM)  │
│  3. Request NSM attestation document               │
│  4. KMS.Decrypt() with attestation + RSA pubkey    │
│  5. KMS validates PCR0 → wraps plaintext to RSA    │
│  6. Decrypt locally with ephemeral RSA key         │
│  7. Set as environment variable (hex-encoded)      │
└────────────────────────────────────────────────────┘
```

### Key Properties

- **Secrets never leave the enclave in plaintext** — KMS wraps the response to a one-time RSA key generated inside the enclave's NSM hardware
- **PCR0-gated decryption** — KMS policy condition `kms:RecipientAttestation:PCR0` ensures only the correct enclave binary can decrypt
- **Configurable secret list** — Defined in `enclave.yaml`, each with a `name` and `env_var`
- **SSM path convention**: lock- and key-scoped under
  `/{deployment}/{appName}/{locked|unlocked}/.../Ciphertext/{kmsKeyID}`

---

## Attestation System

### Three Layers of Attestation

| Layer | What It Proves | Mechanism |
|-------|---------------|-----------|
| **NSM Hardware Attestation** | Enclave binary identity (PCR0) | AWS Nitro hardware signs CBOR COSE_Sign1 document |
| **Attestation Key Binding** | Response authenticity | Ephemeral secp256k1 key hash embedded in NSM attestation UserData |
| **Response Signing** | Per-request integrity | BIP-340 Schnorr signature on every HTTP response |

### PCR Register Usage

| PCR | Content |
|-----|---------|
| PCR0 | Enclave image measurements (firmware, kernel, rootfs) |
| PCR1 | CPU microcode |
| PCR2 | Kernel parameters |
| PCR16 | SHA256(secret_0_pubkey) |
| PCR17 | SHA256(secret_1_pubkey) |
| ... | Additional secrets |
| PCR16-31 | User-extensible via `POST /v1/extend-pcr` |

### PCR0 Upgrade Chain

Each enclave records its predecessor's PCR0 and hardware-signed attestation. The
public versioned migration-intent log separately exposes request history and
competing forks. `enclave verify` checks the live enclave chain; no
migration-log verifier CLI is shipped.

---

## Runtime

The supervisor is the main process inside the enclave. It:

1. **Boots non-blocking** — HTTP server starts immediately (health checks available)
2. **Loads secrets** — Retries KMS decryption until all secrets are available
3. **Generates attestation key** — Ephemeral secp256k1, registered with nitriding
4. **Extends PCRs** — Commits secret public keys to user PCR registers
5. **Spawns user app** — Runs the user's binary as a child process with secrets as env vars
6. **Reverse proxies** — Routes all non-management traffic to the user app
7. **Signs responses** — Schnorr BIP-340 signature on every response
8. **Handles migration control** — parent-only vsock port `8003` routes
   `/request-migration` and `/finalise-migration`

### Management Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/enclave-info` | GET | Version, PCR0 history, attestation pubkey, init status |
| `/v1/extend-pcr` | POST | Extend user PCR (16-31) with custom data |
| `/v1/lock-pcr` | POST | Lock a user PCR against further extension |
| `/health` | GET | Readiness probe (200 ready, 503 initializing) |

Migration mutation is not public HTTP. The EC2 parent reaches
`POST /request-migration` and `POST /finalise-migration` over AF_VSOCK port
`8003`. `GET /v1/enclave-info` remains externally readable and includes status
derived from the authoritative S3 log.

---

## OpenTofu Infrastructure

Deployed via the OpenTofu module scaffolded by `enclave tofu`:

| Resource | Purpose |
|----------|---------|
| **VPC** | Public + private subnets, NAT gateway |
| **EC2 Instance** | Nitro Enclave-enabled, configurable instance type |
| **Elastic IP** | Static public address surviving reboots |
| **KMS Key** | Runtime-created, attestation-gated encryption |
| **SSM Parameters** | Lock/key-scoped ciphertexts, state receipts, predecessor state, and bucket discovery |
| **S3 Candidate Assets** | PCR0-addressed EIF and supervisor objects |
| **S3 Migration Intent** | Public version history with Object Lock and exact-version reads |
| **IAM Role** | Instance profile with SSM, KMS, ECR, S3 access |
| **VPC Endpoints** | KMS, SSM, ECR (private connectivity) |
| **Security Group** | HTTPS ingress, all egress |

---

## Build System

### Reproducibility

The Nix flake (`flake.nix`) pins every dependency:

| Component | Source |
|-----------|--------|
| **User app** | Fetched from GitHub at pinned commit + Nix hash |
| **runtime** | Fetched from GitHub at pinned runtime rev + hash |
| **nitriding** | Brave's TLS terminator at pinned commit |
| **viproxy** | Brave's vsock proxy at pinned version |
| **Base image** | busybox + CA certificates |

The EIF is built deterministically — same inputs always produce the same PCR0/1/2 values. This enables **third-party verification**: anyone can run `enclave build` and confirm the deployed enclave matches the source code.

### SDK Hash Distribution

SDK coordinates (rev, source hash, vendor hash) are:

- Computed via `make sdk-hashes REV=<tag>` and stored in `sdk-hashes.json`
- Injected into the CLI binary at build time via Go ldflags
- Automatically populated into `enclave.yaml` during `enclave init`
- Verified by CI on every tagged release

---

## Security Properties

| Property | How It's Achieved |
|----------|------------------|
| **Secret confidentiality** | KMS decryption gated by hardware-attested PCR0 |
| **Binary integrity** | Reproducible Nix builds → verifiable PCR0 |
| **Response authenticity** | BIP-340 Schnorr signature on every HTTP response |
| **Migration auditability** | Public versioned intent objects with Nitro-attested canonical CBOR |
| **Host resistance** | Recipient-attestation KMS wrapping in both policy modes |
| **Account-root resistance** | Only strict `is_kms_key_locked=true` removes all `PutKeyPolicy` grants |
| **No operator access** | Enclave memory is inaccessible from host, even to root |
| **Network isolation** | Enclave has no direct network — vsock only |

Public history makes hidden migration forks detectable, not prevented. A
retained clone with the same source PCR0 and valid state can append competing
valid entries; the protocol does not prove enclave uniqueness.

> **Current activation limitation:** steps 10/11 are not implemented. The host
> currently accepts `GET /v1/enclave-info` HTTP 200 after the EIF swap; it does
> not perform fresh exact-target attestation, require runtime `/health`
> readiness, or implement the intended verified cleanup ordering.

---

## User Experience

A developer using this framework:

1. Writes a standard Go HTTP server (no enclave code)
2. Runs `enclave init` to scaffold the project
3. Configures secrets and app source in `enclave.yaml`
4. Runs `enclave build` → `enclave tofu` → `tofu apply` → `enclave verify`
5. For a later PCR0, runs `enclave migration request` → `status` → `finalise`
6. Their app runs inside a Nitro Enclave with hardware-attested secrets and signed responses

The framework abstracts away NSM sessions, vsock networking, attestation
documents, KMS recipient attestation, PCR management, and migration state
transfer while keeping candidate activation an explicit operator action.
