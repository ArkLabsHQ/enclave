# Introspector Enclave Framework — Technical Report

## Executive Summary

Introspector Enclave is a **CLI framework and runtime SDK** for deploying applications inside **AWS Nitro Enclaves** with hardware-backed secret management, cryptographic attestation, and reproducible builds. It enables any Go HTTP server to run inside a Nitro Enclave with zero enclave-specific application code — the framework handles all infrastructure concerns (secret lifecycle, attestation, TLS, networking, upgrades).

The framework provides an **irreversible security guarantee**: once a KMS key is locked, only an enclave with the exact same binary measurements (PCR0) can decrypt its secrets — not even the AWS root account can override this.

---

## Architecture Overview

```
                        Internet (HTTPS :443)
                              │
┌─────────────────────────────▼────────────────────────────────┐
│                   AWS EC2 Instance (Host)                     │
│                                                              │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ gvproxy  │  │ IMDS vsock   │  │  enclave-watchdog.svc  │ │
│  │ (Docker) │  │ proxy :8002  │  │  (manages EIF)         │ │
│  └────┬─────┘  └──────┬───────┘  └────────────────────────┘ │
│       │ vsock:1024     │ vsock:3:8002                        │
└───────┼────────────────┼────────────────────────────────────┘
        │                │
┌───────▼────────────────▼────────────────────────────────────┐
│              AWS Nitro Enclave (Isolated VM)                  │
│                                                              │
│  ┌──────────────────────────────────────────────┐            │
│  │  nitriding (TLS terminator + attestation)    │            │
│  │  :443 external  →  :7073 internal            │            │
│  └──────────────────┬───────────────────────────┘            │
│                     │                                        │
│  ┌──────────────────▼───────────────────────────┐            │
│  │  enclave-supervisor (SDK runtime)             │            │
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

## CLI Commands (8 total)

### Lifecycle Workflow

```
enclave init   →  enclave setup  →  enclave build  →  enclave deploy  →  enclave verify
                                                    →  enclave status
                                                    →  enclave lock
                                                    →  enclave destroy
```

### 1. `enclave init` — Project Scaffolding

Generates the `enclave/` directory with all framework files needed to build and deploy:

| File | Purpose |
|------|---------|
| `enclave.yaml` | Configuration (secrets, app source, region, etc.) |
| `start.sh` | Enclave boot sequence |
| `gvproxy/Dockerfile` | Outbound networking proxy |
| `gvproxy/start.sh` | gvproxy startup |
| `scripts/enclave_init.sh` | Host-side enclave launcher |
| `systemd/enclave-watchdog.service` | Enclave lifecycle management |
| `systemd/enclave-imds-proxy.service` | AWS credential forwarding |
| `systemd/gvproxy.service` | Network proxy service |
| `user_data/user_data` | EC2 cloud-init script |

On subsequent runs, validates the configuration and reports errors.

### 2. `enclave setup` — Auto-Populate Nix Hashes

Detects the GitHub remote, computes Nix source and vendor hashes for the user's app, and writes them to `enclave.yaml`. Runs via Docker by default or locally with `--local`.

### 3. `enclave build` — Reproducible EIF Build

Builds the Enclave Image File (EIF) using **Nix inside Docker** for full reproducibility:

1. Generates `build-config.json` from `enclave.yaml`
2. Runs `nix build .#eif` (fetches user app + SDK from GitHub, pins all dependencies)
3. Outputs `enclave/artifacts/image.eif` + `enclave/artifacts/pcr.json` (PCR0/1/2 measurements)

Anyone can rebuild the same EIF and get identical PCR values, proving the binary hasn't been tampered with.

### 4. `enclave deploy` — AWS Deployment

Handles both fresh deployments and upgrades:

**Fresh deploy:**
- Synthesizes and deploys a CDK stack (VPC, EC2, KMS, SSM, IAM, EIP)
- Applies KMS key policy with PCR0 attestation condition
- Waits for instance readiness

**Upgrade (unlocked KMS):**
- Calls old enclave's `/v1/prepare-upgrade` to record PCR0 attestation
- Updates KMS policy with new PCR0
- Hot-swaps the EIF on the running instance

**Upgrade (locked KMS — irreversible key):**
- Creates temporary KMS key bound to new PCR0
- Old enclave re-encrypts all secrets with temporary key via `/v1/export-key`
- New enclave boots with migrated secrets
- Old KMS key scheduled for deletion

### 5. `enclave verify` — Attestation Verification

Three independent verification checks:

1. **NSM attestation** — Fetches hardware-signed attestation document, validates nonce and PCR0
2. **Attestation key binding** — Verifies the supervisor's signing key is registered in the attestation document (SHA256 of pubkey in UserData)
3. **PCR0 chain** — Verifies the upgrade history (each enclave records its predecessor's PCR0 + attestation)

### 6. `enclave status` — Instance Health

Shows instance state, KMS key state, lock status, and enclave version.

### 7. `enclave lock` — Irreversible KMS Lock

Removes `kms:PutKeyPolicy` and `kms:ScheduleKeyDeletion` from the admin, making the KMS policy **permanent and irrevocable**. After locking, only an enclave with the correct PCR0 can decrypt secrets — even the AWS root account cannot override this.

### 8. `enclave destroy` — Teardown

Destroys all AWS infrastructure via `cdk destroy`.

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
- **SSM path convention**: `/{deployment}/{appName}/{secretName}/Ciphertext`

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

Each enclave records its predecessor's PCR0 and the hardware-signed attestation proving it. This creates an immutable chain from genesis to the current version, verifiable by any external party via `enclave verify`.

---

## SDK Runtime (enclave-supervisor)

The supervisor is the main process inside the enclave. It:

1. **Boots non-blocking** — HTTP server starts immediately (health checks available)
2. **Loads secrets** — Retries KMS decryption until all secrets are available
3. **Generates attestation key** — Ephemeral secp256k1, registered with nitriding
4. **Extends PCRs** — Commits secret public keys to user PCR registers
5. **Spawns user app** — Runs the user's binary as a child process with secrets as env vars
6. **Reverse proxies** — Routes all non-management traffic to the user app
7. **Signs responses** — Schnorr BIP-340 signature on every response
8. **Handles upgrades** — `/v1/export-key` and `/v1/prepare-upgrade` endpoints

### Management Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/enclave-info` | GET | Version, PCR0 history, attestation pubkey, init status |
| `/v1/extend-pcr` | POST | Extend user PCR (16-31) with custom data |
| `/v1/lock-pcr` | POST | Lock a user PCR against further extension |
| `/v1/export-key` | POST | Re-encrypt secrets for migration (upgrade) |
| `/v1/prepare-upgrade` | POST | Store PCR0 + attestation for upgrade chain |
| `/health` | GET | Readiness probe (200 ready, 503 initializing) |

---

## CDK Infrastructure Stack

Deployed via Go CDK (`cdk.go`):

| Resource | Purpose |
|----------|---------|
| **VPC** | Public + private subnets, NAT gateway |
| **EC2 Instance** | Nitro Enclave-enabled, configurable instance type |
| **Elastic IP** | Static public address surviving reboots |
| **KMS Key** | Attestation-gated encryption, auto-rotation |
| **SSM Parameters** | Secret ciphertext storage + migration state |
| **IAM Role** | Instance profile with SSM, KMS, ECR, S3 access |
| **VPC Endpoints** | KMS, SSM, ECR (private connectivity) |
| **Security Group** | HTTPS ingress, all egress |
| **ECR Image** | gvproxy Docker image for outbound networking |

---

## Build System

### Reproducibility

The Nix flake (`flake.nix`) pins every dependency:

| Component | Source |
|-----------|--------|
| **User app** | Fetched from GitHub at pinned commit + Nix hash |
| **enclave-supervisor** | Fetched from GitHub at pinned SDK rev + hash |
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
| **Upgrade auditability** | PCR0 chain with hardware-signed attestation documents |
| **Irreversible lockdown** | KMS policy removes admin's own PutKeyPolicy permission |
| **No operator access** | Enclave memory is inaccessible from host, even to root |
| **Network isolation** | Enclave has no direct network — vsock only |

---

## User Experience

A developer using this framework:

1. Writes a standard Go HTTP server (no enclave code)
2. Runs `enclave init` to scaffold the project
3. Configures secrets and app source in `enclave.yaml`
4. Runs `enclave build` → `enclave deploy` → `enclave verify`
5. Their app runs inside a Nitro Enclave with hardware-attested secrets, signed responses, and an immutable upgrade chain

The framework abstracts away all Nitro Enclave complexity — NSM sessions, vsock networking, attestation documents, KMS recipient attestation, PCR management, and upgrade key migration.
