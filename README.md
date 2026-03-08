# Introspector Enclave

A framework for running applications inside [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) with zero SDK imports. Supports **Go** and **Node.js**. The enclave supervisor handles attestation, KMS secret management, PCR extension, and BIP-340 Schnorr response signing automatically. You write a plain HTTP server.

## Architecture

```
Client                                  AWS Services (KMS, SSM)
  |                                              ^
  | HTTPS (port 443)                             |
  v                                              |
EC2 Instance (m6i.xlarge, Amazon Linux 2023)     |
  |                                              |
  |  vsock:1024                          gvproxy (Docker)
  v                                       192.168.127.1
Nitro Enclave ---------------------------------->+
  ├── nitriding             (TLS :443 -> :7073)
  ├── enclave-supervisor    (reverse proxy :7073 -> :7074)
  │     ├── attestation key + Schnorr signing
  │     ├── KMS secret decryption
  │     ├── PCR extension endpoints
  │     └── management API (/health, /v1/enclave-info, ...)
  ├── your-app              (plain HTTP server :7074)
  └── viproxy               (IMDS forwarding -> vsock CID 3:8002)
```

### Boot Sequence

1. **nitriding** starts, sets up the TAP network interface via gvproxy, and terminates TLS on port 443
2. **enclave-supervisor** initializes:
   - Decrypts secrets from KMS using a Nitro attestation document (PCR0-bound)
   - Sets decrypted secrets as environment variables
   - Generates an ephemeral secp256k1 attestation key
   - Registers `SHA256(attestationPubkey)` with nitriding (embedded as `appKeyHash` in attestation UserData)
   - Starts the reverse proxy on port 7073 with Schnorr response signing
3. **your-app** is launched as a child process on port 7074, inheriting secret env vars

### Networking

The enclave uses [gvproxy](https://github.com/containers/gvisor-tap-vsock) for outbound connectivity:

- `192.168.127.1` - Gateway/DNS server (gvproxy)
- `192.168.127.2` - Enclave's virtual IP
- `127.0.0.1:80` - IMDS endpoint (via viproxy -> vsock CID 3:8002)

## Supported Languages

| Language | App Template | Build System | Dependency Hash |
|----------|-------------|-------------|----------------|
| **Go** | `enclave generate template --golang` | `buildGoModule` | `vendorHash` (from `go.sum`) |
| **Node.js** | `enclave generate template --nodejs` | `buildNpmPackage` | `npmDepsHash` (from `package-lock.json`) |

## Prerequisites

- Docker (for reproducible EIF builds via pinned NixOS container)
- [Nix](https://nixos.org/) (for hash computation and local builds)
- AWS CLI v2 with appropriate credentials
- AWS CDK CLI (`npm install -g aws-cdk`)
- `jq`
- **Go apps:** Go 1.22+
- **Node.js apps:** Node.js 22+

## Quick Start

### 1. Install the CLI

```sh
go install github.com/ArkLabsHQ/introspector-enclave/cmd/enclave@latest
```

Or build from source with SDK hashes baked in:

```sh
make sdk-hashes REV=v1.0.0   # compute source hash
make vendor-hash              # compute vendor hash
make build                    # build CLI with hashes baked in
```

### 2. Initialize your project

**Option A:** Generate a complete template (recommended for new projects):

```sh
enclave generate template --golang my-app    # Go project
enclave generate template --nodejs my-app    # Node.js project
```

**Option B:** Add enclave support to an existing repo:

```sh
enclave init
```

Both create:
- `enclave/enclave.yaml` — main config file
- `flake.nix` — Nix build definition (language-specific)
- `enclave/start.sh` — enclave boot script
- `enclave/gvproxy/` — network proxy config
- `enclave/scripts/` — initialization scripts
- `enclave/systemd/` — service unit files
- `enclave/user_data/` — EC2 user data

If built with `make build`, the `sdk:` section is auto-populated with the correct hashes.

### 3. Set up app hashes

The `setup` command auto-detects your GitHub remote and computes all nix hashes:

```sh
enclave setup                          # Go app (default), runs in Docker
enclave setup --language nodejs        # Node.js app (writes correct flake.nix)
enclave setup --local                  # uses local nix installation
```

This populates `nix_owner`, `nix_repo`, `nix_rev`, `nix_hash`, and `nix_vendor_hash` in `enclave/enclave.yaml` from your local git state.

> **Node.js:** `package-lock.json` must be committed to your repo. Nix requires it to compute reproducible dependency hashes.

### 4. Configure `enclave/enclave.yaml`

After `enclave setup`, review and fill in remaining fields:

```yaml
name: my-app                     # app name
region: us-east-1                # AWS region
account: "123456789012"          # your AWS account ID

sdk:
  rev: "v1.0.0"                  # auto-populated by 'make build'
  hash: "sha256-..."
  vendor_hash: "sha256-..."

app:
  language: go                   # "go" or "nodejs"
  nix_owner: my-org              # auto-populated by 'enclave setup'
  nix_repo: my-app
  nix_rev: "abc123..."
  nix_hash: "sha256-..."
  nix_vendor_hash: "sha256-..."  # Go vendor hash or npm deps hash
  nix_sub_packages:
    - "cmd"                      # Go sub-package with main() (Go only)
  binary_name: my-app

  env:
    MY_APP_PORT: "7074"
    MY_APP_DATADIR: "/app/data"

secrets:
  - name: signing_key
    env_var: APP_SIGNING_KEY
```

Your app is a plain HTTP server — no SDK imports needed:

**Go:**
```go
package main

import (
    "net/http"
    "os"
)

func main() {
    port := os.Getenv("ENCLAVE_APP_PORT") // default 7074
    signingKey := os.Getenv("APP_SIGNING_KEY") // decrypted by supervisor

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello from the enclave"))
    })
    http.ListenAndServe(":"+port, nil)
}
```

**Node.js:**
```js
const http = require("http");
const port = process.env.ENCLAVE_APP_PORT || "7074";
const signingKey = process.env.APP_SIGNING_KEY; // decrypted by supervisor

http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("Hello from the enclave\n");
}).listen(port, () => console.log(`listening on :${port}`));
```

### 5. Validate config

```sh
enclave init
```

Running `init` again when `enclave.yaml` already exists validates all fields and prints a summary.

### 6. Build the enclave image

```sh
enclave build              # build EIF via Docker + Nix (reproducible)
enclave build --local      # build EIF using local Nix installation
```

Outputs `artifacts/image.eif` and `artifacts/pcr.json` with PCR0, PCR1, PCR2 measurements.

### 7. Deploy

```sh
enclave deploy             # deploy CDK stack (VPC, EC2, KMS, IAM, secrets)
```

### 8. Verify

```sh
enclave verify             # verify attestation document + PCR0 match
```

## Updating Your App

The enclave build fetches your app source from GitHub at the exact commit specified in `enclave.yaml`. Code must be committed and pushed before building.

**Code-only changes (no new dependencies):**

```sh
git add . && git commit -m "update" && git push
enclave update     # fast: updates nix_rev + nix_hash only (~1 second)
enclave build
enclave deploy
```

**Dependency changes (go.mod/go.sum or package.json/package-lock.json):**

```sh
git add . && git commit -m "update deps" && git push
enclave setup      # full: recomputes all hashes including vendor/deps hash
enclave build
enclave deploy
```

## SDK Release Workflow

SDK hashes are computed per release tag and baked into CLI builds via ldflags. This lets `enclave init` auto-populate the `sdk:` section.

```sh
# 1. Tag the release
git tag v1.0.0

# 2. Compute source hash (from local git tree, no network auth needed)
make sdk-hashes REV=v1.0.0

# 3. Compute vendor hash (runs a test Nix build to get the expected hash)
make vendor-hash

# 4. Commit the hashes and push
git add sdk-hashes.json
git commit -m "sdk hashes for v1.0.0"
git push && git push --tags
```

> **Note:** The tag points to the commit *before* `sdk-hashes.json` is added. This is correct — the tag identifies the source code being hashed, and `sdk-hashes.json` is a build artifact that references it.

### Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Build `enclave-cli` with SDK hashes from `sdk-hashes.json` baked in via ldflags |
| `make sdk-hashes REV=<tag>` | Compute Nix source hash for a git ref and write `sdk-hashes.json` |
| `make vendor-hash` | Compute Go vendor hash via test Nix build and update `sdk-hashes.json` |
| `make help` | Show all targets |

### CI Verification

The `.github/workflows/sdk-hashes.yml` workflow runs on tag push (`v*`) to verify that `sdk-hashes.json` matches the computed hashes and that `enclave-supervisor` builds successfully.

## CLI Commands

| Command | Description |
|---------|-------------|
| `enclave init` | Scaffold enclave project or validate existing config |
| `enclave generate template --golang` | Generate a complete Go enclave app template |
| `enclave generate template --nodejs` | Generate a complete Node.js enclave app template |
| `enclave setup` | Auto-populate app nix hashes from git remote |
| `enclave setup --language nodejs` | Set language and rewrite flake.nix for Node.js |
| `enclave setup --local` | Use local Nix instead of Docker for hash computation |
| `enclave update` | Fast update: only nix_rev + nix_hash (code changes, no dep changes) |
| `enclave build` | Build EIF image (reproducible, via Docker + Nix) |
| `enclave build --local` | Build EIF using local Nix instead of Docker |
| `enclave deploy` | Deploy CDK stack (VPC, EC2, KMS, IAM, secrets) |
| `enclave verify` | Verify attestation document and PCR0 against local build |
| `enclave status` | Show deployment status |
| `enclave destroy` | Tear down the CDK stack |

## API Endpoints

The supervisor exposes management endpoints alongside proxied requests to your app. All responses include Schnorr signature headers.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Supervisor health check (ready/degraded) |
| GET | `/v1/enclave-info` | Build + runtime metadata (version, attestation key, previous PCR0) |
| POST | `/v1/export-key` | Re-encrypt secrets for locked-key migration |
| POST | `/v1/prepare-upgrade` | Store PCR0 + attestation proof in SSM before upgrade |
| POST | `/v1/extend-pcr` | Extend a PCR register (16-31) with custom data |
| POST | `/v1/lock-pcr` | Lock a PCR register (16-31) to prevent further extension |
| GET | `/enclave/attestation` | Nitro attestation document (served by nitriding) |
| `*` | `/*` | All other requests proxied to your app on port 7074 |

### Response Signing

Every response includes:
- `X-Attestation-Signature`: BIP-340 Schnorr signature over `SHA256(response_body)`
- `X-Attestation-Pubkey`: compressed public key of the ephemeral attestation key

Clients verify the signature, then confirm the pubkey hash matches `appKeyHash` in the attestation document's UserData.

### PCR Extension

Your app can extend PCR registers 16-31 via HTTP without importing the SDK:

```sh
# Extend PCR 16 with custom data (base64-encoded)
curl -X POST http://127.0.0.1:7073/v1/extend-pcr \
  -d '{"pcr": 16, "data": "base64encodeddata"}'

# Lock PCR 16 to prevent further extension
curl -X POST http://127.0.0.1:7073/v1/lock-pcr \
  -d '{"pcr": 16}'
```

## Security Model

### Secret Lifecycle

1. On first deploy, the CLI generates 32 random bytes per secret, encrypts them with KMS (attaching a Nitro attestation document), and stores the ciphertext in SSM Parameter Store
2. On boot, the supervisor loads ciphertexts from SSM and decrypts via KMS (which validates PCR0)
3. Decrypted values are set as environment variables — plaintext only exists in enclave memory
4. SSM parameter path: `/{prefix}/{appName}/{secretName}/Ciphertext`

### KMS Policy

The deploy command applies a KMS key policy where:
- The **admin statement** explicitly excludes `kms:Decrypt` and `kms:CreateGrant` — nobody outside the enclave can decrypt
- The **enclave statement** allows `kms:Decrypt` only when `kms:RecipientAttestation:PCR0` matches the enclave measurement

### Irreversible KMS Lockdown

For maximum security, the `lock` command applies an **irreversible** policy using `--bypass-policy-lockout-safety-check`:

- Removes all admin access (no `kms:PutKeyPolicy`, no `kms:ScheduleKeyDeletion`)
- Only the enclave with the exact PCR0 can call `kms:Decrypt`
- **This cannot be undone.** Not even the AWS root account can modify the policy afterward.

```sh
enclave lock
```

### Upgrade Paths

When deploying a new enclave version (different PCR0), the upgrade path depends on whether the KMS key is locked.

#### Unlocked KMS Key

The KMS key policy still allows `kms:PutKeyPolicy`, so the CLI can update it with the new PCR0:

1. CLI calls `POST /v1/prepare-upgrade` on the old enclave
2. The old enclave generates an NSM attestation document (signed by AWS Nitro hardware, unforgeable) and stores both the plain PCR0 and the attestation proof in SSM
3. CLI updates the KMS key policy with the new PCR0
4. CLI stops the old enclave, uploads the new EIF, and restarts

#### Locked KMS Key (Migration)

The KMS key policy is irreversible — only the old PCR0 can decrypt. Secrets must be re-encrypted to a new KMS key:

1. CLI creates a **new KMS key** with a policy allowing the new PCR0 to decrypt
2. CLI stores the new key ID (`MigrationKMSKeyID`) and old key ID (`MigrationOldKMSKeyID`) in SSM
3. CLI calls `POST /v1/export-key` on the old enclave. The old enclave:
   - Reads `MigrationKMSKeyID` from SSM (this is the only gate — if the param is unset, the endpoint returns an error)
   - Decrypts each secret using the old KMS key (which only this enclave can do)
   - Re-encrypts each secret with the new KMS key
   - Stores the migration ciphertexts in SSM under `Migration/{secretName}/Ciphertext`
   - Stores its PCR0 and an NSM attestation proof in SSM
4. CLI copies migration ciphertexts to permanent locations, updates `KMSKeyID` in SSM
5. CLI stops the old enclave, uploads the new EIF, and restarts
6. The new enclave boots, decrypts secrets using the new KMS key (PCR0 matches), and schedules the old KMS key for deletion (7-day pending window via `MigrationOldKMSKeyID`)

### PCR0 Attestation Chain

Each enclave version records its predecessor's PCR0, creating a verifiable upgrade chain:

```
Genesis -> PCR0_v1 (previous_pcr0=genesis)
        -> PCR0_v2 (previous_pcr0=PCR0_v1, attestation=<signed proof>)
        -> PCR0_v3 (previous_pcr0=PCR0_v2, attestation=<signed proof>)
```

The attestation proof is an NSM attestation document — a COSE Sign1 structure signed by AWS Nitro hardware. It contains the enclave's PCR values, proving the reported `previous_pcr0` came from a real enclave (not a compromised host).

`GET /v1/enclave-info` returns both `previous_pcr0` and `previous_pcr0_attestation`. The `enclave verify` command automatically verifies the attestation document against the AWS Nitro root certificate and confirms the PCR0 inside matches the reported value.

## Reproducible Build

The enclave image is built entirely with [Nix](https://nixos.org/) using [monzo/aws-nitro-util](https://github.com/monzo/aws-nitro-util) inside a pinned Docker container, producing a byte-identical EIF on every build. This guarantees identical PCR0 measurements, enabling anyone to verify that the running enclave matches the published source code.

## Project Structure

```
.
├── cmd/enclave/main.go          # CLI entry point
├── config.go                    # Config loading + validation
├── build.go                     # EIF build orchestration
├── setup.go                     # Auto-populate app nix hashes
├── update.go                    # Fast update (rev + source hash only)
├── template.go                  # Template generation (Go, Node.js)
├── deploy.go                    # CDK deploy + secret provisioning
├── verify.go                    # Attestation verification
├── cdk.go                       # AWS CDK stack definition (Go)
├── init.go                      # Scaffold command + config template
├── framework_files.go           # Framework files as Go string constants
├── version.go                   # SDK hash vars (set via ldflags)
├── Makefile                     # Build + hash computation targets
├── sdk-hashes.json              # Cached SDK Nix hashes
├── sdk/                         # SDK module (built as enclave-supervisor)
│   ├── enclave.go               # Init, attestation key, signing middleware, routes
│   ├── kms_ssm.go               # KMS encrypt/decrypt, SSM storage
│   ├── imds.go                  # IMDS credential fetching
│   ├── migrate.go               # Key migration via vsock
│   └── cmd/enclave-supervisor/
│       └── main.go              # Standalone supervisor binary
└── .github/workflows/
    └── sdk-hashes.yml           # CI: verify SDK hashes on tag push
```

## Configuration Reference

### `enclave/enclave.yaml`

| Field | Description | Default |
|-------|-------------|---------|
| `name` | App name (used in stack name, EIF) | (required) |
| `version` | Build version | `dev` |
| `region` | AWS region | (required) |
| `account` | AWS account ID | (required for deploy) |
| `prefix` | Deployment prefix (stack = `{prefix}Nitro{name}`) | `dev` |
| `instance_type` | EC2 instance type | `m6i.xlarge` |
| `nix_image` | Docker image for builds | `nixos/nix:2.24.9` |
| `sdk.rev` | SDK git commit SHA or tag | (required for build) |
| `sdk.hash` | Nix source hash (SRI) | (required for build) |
| `sdk.vendor_hash` | Go vendor hash (SRI) | (required for build) |
| `app.language` | App language (`go`, `nodejs`) | `go` |
| `app.source` | Build source type | `nix` |
| `app.nix_owner` | GitHub owner | (auto by `setup`) |
| `app.nix_repo` | GitHub repo | (auto by `setup`) |
| `app.nix_rev` | Git commit SHA | (auto by `setup`) |
| `app.nix_hash` | Nix source hash (SRI) | (auto by `setup`) |
| `app.nix_vendor_hash` | Go vendor hash or npm deps hash (SRI) | (auto by `setup`) |
| `app.nix_sub_packages` | Go sub-packages to build (Go only) | `["."]` |
| `app.binary_name` | Output binary name | `{name}` |
| `app.env` | Environment variables baked into EIF | `{}` |
| `secrets[].name` | Secret name (SSM path component) | (required) |
| `secrets[].env_var` | Env var for decrypted value | (required) |

### Environment Variables (Runtime)

| Variable | Description | Default |
|----------|-------------|---------|
| `ENCLAVE_APP_PORT` | Port your app listens on | `7074` |
| `ENCLAVE_PROXY_PORT` | Supervisor proxy port | `7073` |
| `APP_BINARY_NAME` | User app binary name | `app` |
| `ENCLAVE_DEPLOYMENT` | Deployment name for SSM paths | `dev` |
| `ENCLAVE_KMS_KEY_ID` | KMS key ID override | (auto from SSM) |
| `ENCLAVE_AWS_REGION` | AWS region for KMS/SSM | `us-east-1` |
