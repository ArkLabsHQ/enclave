# Introspector Enclave — Complete Architecture & Flow

This is the authoritative technical reference. See
[OPERATIONS.md](OPERATIONS.md) for the authoritative operator runbook.

## Table of Contents

1. [High-Level Architecture](#1-high-level-architecture)
2. [Build Flow](#2-build-flow)
3. [OpenTofu Deployment](#3-opentofu-deployment)
4. [EC2 Host Bootstrap](#4-ec2-host-bootstrap)
5. [Host Systemd Services](#5-host-systemd-services)
6. [Enclave Boot](#6-enclave-boot-startsh)
7. [Supervisor Initialization](#7-supervisor-initialization-detailed)
8. [KMS Policy and Trust Modes](#8-kms-policy-and-trust-modes)
9. [Secret Lifecycle](#9-secret-lifecycle)
10. [Storage System](#10-storage-system-s3--aes-256-gcm)
11. [Dynamic Secrets](#11-dynamic-secrets)
12. [Management API](#12-management-api-inside-enclave)
13. [Host Supervisor](#13-host-supervisor)
14. [Admin Access](#14-admin-access-flow)
15. [Migration Flow](#15-migration-flow)
16. [External Client Verification](#16-external-client-verification)
17. [Response Signing](#17-response-signing-schnorr-middleware)
18. [Networking Deep Dive](#18-networking-deep-dive)

---

## 1. High-Level Architecture

```
                                    ┌─────────────────────────────────────────┐
                                    │              DEVELOPER                  │
                                    │                                         │
                                    │  enclave init → enclave build → deploy  │
                                    └──────────────────┬──────────────────────┘
                                                       │
                              ┌─────────────────────────────────────────────────┐
                              │                   AWS CLOUD                     │
                              │                                                 │
                              │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
                              │  │   KMS    │  │   SSM    │  │  S3 Bucket   │  │
                              │  │ (PCR0-   │  │ (Secret  │  │ (Encrypted   │  │
                              │  │  locked) │  │  Store)  │  │  Storage)    │  │
                              │  └────┬─────┘  └────┬─────┘  └──────┬───────┘  │
                              │       │             │               │           │
                              │  ┌────┴─────────────┴───────────────┴────────┐  │
                              │  │              EC2 INSTANCE (Nitro)         │  │
                              │  │                                           │  │
                              │  │  ┌─────────────────────────────────────┐  │  │
                              │  │  │   enclave-supervisor.service        │  │  │
                              │  │  │   (single host-side process)        │  │  │
                              │  │  │                                     │  │  │
                              │  │  │   • Management API 127.0.0.1:8443  │  │  │
                              │  │  │   • gvproxy (in-process, vsock:1024)│  │  │
                              │  │  │   • IMDS AF_VSOCK fwd (vsock:8002) │  │  │
                              │  │  │   • Watchdog (nitro-cli run/term)   │  │  │
                              │  │  └──────────────┬──────────────────────┘  │  │
                              │  │                 │ vsock                    │  │
                              │  │  ┌──────────────┴──────────────────────┐  │  │
                              │  │  │      AWS NITRO ENCLAVE (EIF)       │  │  │
                              │  │  │                                     │  │  │
                              │  │  │  viproxy ──→ IMDS (127.0.0.1:80)  │  │  │
                              │  │  │  nitriding (TLS on :443)           │  │  │
                              │  │  │    └─→ runtime (:7073)  │  │  │
                              │  │  │          └─→ user-app (:7074)     │  │  │
                              │  │  │                                     │  │  │
                              │  │  │  NSM (Hardware Attestation)         │  │  │
                              │  │  └─────────────────────────────────────┘  │  │
                              │  └───────────────────────────────────────────┘  │
                              └─────────────────────────────────────────────────┘
                                                       │
                              ┌─────────────────────────────────────────────────┐
                              │              EXTERNAL CLIENTS                   │
                              │                                                 │
                              │  1. Fetch attestation (nonce challenge)         │
                              │  2. Verify PCR0 + certificate chain             │
                              │  3. Make request                                │
                              │  4. Verify Schnorr response signature           │
                              └─────────────────────────────────────────────────┘
```

### Component Summary

| Component | Location | Purpose |
|-----------|----------|---------|
| **CLI** | Root Go module (`cli/`) | Build, deployment, verification, lifecycle, and `migration request|status|abort|finalise` commands |
| **Nix Flake** | `flake.nix` | Deterministic EIF build (supervisor + app + nitriding + viproxy) |
| **OpenTofu module** | `cli/tofu_files.go` (scaffolded into `tofu/`) | AWS infrastructure (KMS, SSM, EC2, VPC, S3, IAM) |
| **supervisor** | `supervisor/` | Host-side all-in-one: management API, in-process gvproxy, in-process IMDS AF_VSOCK forwarder, and enclave lifecycle watchdog. Replaces the former `enclave-watchdog`, `enclave-imds-proxy`, and standalone `gvproxy.service`. |
| **Runtime** | `runtime/` | In-enclave orchestrator (secrets, attestation, storage, HTTP) |
| **Nitriding** | Third-party (Brave) | TLS termination, attestation document serving |
| **Viproxy** | Third-party (Brave) | In-enclave IMDS endpoint (127.0.0.1:80 → vsock:2:8002) |
| **gvproxy** | Linked as Go library (`github.com/containers/gvisor-tap-vsock`) | TAP networking over vsock, now in-process inside supervisor |
| **Client Library** | `client/` | Verified HTTP client with attestation checking |

---

## 2. Build Flow

### 2.1 Initialization (`enclave init` + `enclave tofu`)

```
enclave init (build-time scaffold only)
    │
    ├─ First time (no enclave.yaml exists):
    │   ├─ Create enclave/ directory
    │   ├─ Write enclave/enclave.yaml from template
    │   │   └─ Substitute SDK coordinates (rev, hash, vendor_hash) from ldflags
    │   └─ Write build-time framework files via getInitFiles():
    │       ├─ enclave/flake.nix (language-specific: Go / Node.js / .NET / Rust)
    │       └─ .github/workflows/ (CI/CD workflows)
    │
    └─ Existing config:
        ├─ Load and validate all required fields
        ├─ Validate app coordinates (nix_owner, nix_repo, nix_rev, nix_hash)
        ├─ Validate SDK coordinates (rev, hash, vendor_hash)
        └─ Print summary with secret count

enclave tofu (deployment scaffold, run before first deploy)
    └─ Write OpenTofu tree via getTofuFiles() with merge-only-new
       (one main.tf per module, sectioned by banner comments):
        ├─ tofu/main.tf            (root: provider + module call + vars + outputs)
        ├─ tofu/modules/enclave/main.tf
        │   └─ KMS, IAM, S3, SSM, VPC, EC2, vars, outputs
        ├─ tofu/modules/enclave/templates/user_data.sh.tftpl
        ├─ tofu/modules/backend/main.tf  (state bucket + lock table bootstrap)
        └─ tofu/.gitignore
    └─ Always rewrite tofu/terraform.tfvars.json from enclave.yaml.
```

### 2.2 Configuration (`enclave/enclave.yaml`)

```yaml
name: my-app
version: "1.0.0"
region: us-east-1
account: "123456789012"    # 12-digit AWS account ID (validated)
deployment: dev            # deployment name (e.g., dev, staging, prod)

app:
  language: go
  source: ./               # relative path to app source
  nix_owner: org           # GitHub owner for app Nix fetch
  nix_repo: repo           # GitHub repo
  nix_rev: abc123          # Git commit hash
  nix_hash: sha256-...     # Nix source hash
  nix_vendor_hash: sha256-... # Go vendor hash
  binary_name: myapp       # Output binary name
  env:                     # Baked into EIF at build time
    - MY_VAR=value

secrets:                   # KMS-encrypted secrets
  - name: signing_key
    env_var: APP_SIGNING_KEY
  - name: api_secret
    env_var: APP_API_SECRET

sdk:
  rev: v0.0.53             # SDK Git commit/tag
  hash: sha256-...         # SDK source hash
  vendor_hash: sha256-...  # SDK Go vendor hash

instance_type: m6i.xlarge
migration_cooldown: 30m
migration_intent_retention: 87600h
is_kms_key_locked: false
```

### 2.3 Build (`enclave build`)

```
enclave build
    │
    ├─ 1. Load enclave.yaml, validate SDK fields (rev, hash, vendor_hash)
    │
    ├─ 2. Generate .enclave/build-config.json from enclave.yaml
    │      Template substitution: {{region}}, {{deployment}}, {{version}}
    │      Includes: APP_BINARY_NAME, secrets config, env vars
    │
    ├─ 3. git add --intent-to-add (make files visible to Nix flakes)
    │      Files: enclave/flake.nix, enclave/enclave.yaml (build-config.json is a CLI-generated intermediate in .enclave/)
    │
    ├─ 4. Build EIF
    │   │
    │   ├─ [Default: Docker build]
    │   │   docker run --rm -v {root}:/src nixos/nix:2.24.9 sh -c "
    │   │     nix build --impure \
    │   │       --extra-experimental-features 'nix-command flakes' \
    │   │       --out-link flake_result .#eif
    │   │     cp .enclave/result/image.eif /src/.enclave/artifacts/image.eif
    │   │     cp .enclave/result/pcr.json  /src/.enclave/artifacts/pcr.json
    │   │   "
    │   │
    │   └─  BUILD_CONFIG_PATH=./.enclave/build-config.json \
    │       nix build --impure ... --out-link flake_result .#eif
    │
    ├─ 5. Nix Flake Execution (inside Docker or locally)
    │   │
    │   ├─ Read BUILD_CONFIG_PATH → parse build-config.json
    │   │
    │   ├─ Build runtime
    │   │   └─ Fetch SDK from GitHub at sdk.rev
    │   │   └─ buildGoModule → runtime/cmd/runtime binary
    │   │   └─ ldflags: -X sdk.Version={version}
    │   │
    │   ├─ Build upstream app (user's application)
    │   │   └─ Fetch from GitHub at app.nix_rev
    │   │   └─ buildGoModule (or Node.js/dotnet equivalent)
    │   │   └─ Rename output to app.binary_name
    │   │
    │   ├─ Build nitriding (Brave) — TLS termination + attestation
    │   │
    │   ├─ (nitriding + viproxy are vendored into runtime/nitriding/ and
    │   │   runtime/viproxy/ — linked into the runtime binary, no separate
    │   │   /app/nitriding or /app/proxy in the EIF.)
    │   │
    │   ├─ Assemble /app directory (enclaveRootfs)
    │   │   ├─ /app/runtime           ← runtime + nitriding + viproxy, all-in-one
    │   │   ├─ /app/{binary_name}     ← user's app
    │   │   ├─ /app/data/
    │   │   ├─ busybox, cacert
    │   │   └─ Environment variables baked in:
    │   │       ├─ ENCLAVE_SECRETS_CONFIG=<JSON of secrets list>
    │   │       ├─ AWS_REGION, ENCLAVE_APP_NAME, ENCLAVE_DEPLOYMENT
    │   │       ├─ ENCLAVE_MIGRATION_COOLDOWN
    │   │       ├─ ENCLAVE_MIGRATION_INTENT_RETENTION
    │   │       ├─ ENCLAVE_KMS_KEY_LOCKED
    │   │       └─ User-provided env vars from config
    │   │
    │   └─ Build EIF via monzo/aws-nitro-util
    │       ├─ Kernel + kernel config + NSM kernel object (AWS blobs)
    │       ├─ Rootfs from assembled /app
    │       ├─ Entrypoint: /app/runtime
    │       └─ Output: image.eif + pcr.json
    │
    ├─ 6. Parse PCR values from .enclave/artifacts/pcr.json
    │      PCR0 = SHA384(EIF content)  — code identity
    │      PCR1 = SHA384(kernel + boot) — kernel identity
    │      PCR2 = SHA384(app binary)    — application identity
    │
    └─ 7. Build management binary
           go install github.com/ArkLabsHQ/introspector-enclave/supervisor/cmd/supervisor@{Runtime.Rev}
           GOOS=linux GOARCH=amd64 CGO_ENABLED=0
           Output: .enclave/artifacts/supervisor
```

**Key insight**: `ENCLAVE_SECRETS_CONFIG` is a JSON string baked into the EIF at build time. It tells the supervisor which secrets to fetch at runtime:
```json
[{"name":"signing_key","env_var":"APP_SIGNING_KEY"},{"name":"api_secret","env_var":"APP_API_SECRET"}]
```

---

## 3. OpenTofu Deployment

### 3.1 Deploy Flow (`enclave tofu` + `tofu apply`)

```
enclave tofu
    │
    ├─ Load config, validate SDK
    ├─ Scaffold the OpenTofu module into tofu/ (from cli/tofu_files.go)
    └─ Write tofu/terraform.tfvars.json (EIF + supervisor paths, PCR0)

tofu init && tofu apply
    │
    ├─ Upload PCR0-addressed candidate EIF and supervisor
    ├─ Provision VPC, EC2, EIP, S3, SSM, DynamoDB, and IAM
    ├─ Export candidate and migration-intent outputs
    └─ On an existing deployment: publish only; migration activation is manual
```

Candidate artifacts and root outputs are:

```text
candidates/<pcr0>/enclave.eif
candidates/<pcr0>/supervisor

candidate_pcr0
candidate_artifact_bucket
candidate_eif_key
candidate_supervisor_key
migration_intent_bucket
```

### 3.2 AWS Resources Created

```
Resource prefix: ${deployment}-${app_name}
│
├─ KMS
│   └─ EncryptionKey
│       ├─ Automatic key rotation: enabled
│       ├─ Retention: retain on deletion (managed separately)
│       └─ Used for: secret encryption/decryption, storage DEK wrapping
│
├─ SSM Parameters
│   ├─ /{deployment}/{appName}/{locked|unlocked}/KMSKeyID
│   ├─ /{deployment}/{appName}/{locked|unlocked}/{secretName}/Ciphertext/{kmsKeyID}
│   ├─ /{deployment}/{appName}/{locked|unlocked}/StorageDEK/Ciphertext/{kmsKeyID}
│   ├─ /{deployment}/{appName}/MigrationPreviousPCR0
│   ├─ /{deployment}/{appName}/MigrationPreviousPCR0Attestation
│   ├─ /{deployment}/{appName}/MigrationIntentBucketName
│   ├─ /{deployment}/{appName}/StorageBucketName
│   ├─ /{deployment}/{appName}/StateOriginReceipt/{kmsKeyID}/{pcr0}
│   └─ /{deployment}/{appName}/MigrationStateOriginReceipt/{kmsKeyID}
│
├─ VPC (not in local mode)
│   ├─ Public + private subnets (NAT gateway enabled)
│   ├─ VPC Interface Endpoints (PrivateDnsEnabled):
│   │   ├─ com.amazonaws.{region}.kms
│   │   ├─ com.amazonaws.{region}.ssm
│   │   └─ com.amazonaws.{region}.ecr.dkr
│   └─ VPC Gateway Endpoint:
│       └─ com.amazonaws.{region}.s3
│
├─ Security Group
│   ├─ Inbound: HTTPS (443) from 0.0.0.0/0
│   └─ Self-referencing: TCP/443 + ICMP
│
├─ ECR Repository
│   └─ gvproxy Docker image (built from enclave/gvproxy/Dockerfile)
│       └─ gvisor-tap-vsock v0.7.4
│
├─ S3 Bucket (Encrypted Storage)
│   ├─ Block all public access
│   ├─ Enforce SSL
│   └─ Used for: encrypted key-value storage (/v1/storage API)
│
├─ S3 Assets (uploaded during deploy)
│   ├─ candidates/<pcr0>/enclave.eif
│   └─ candidates/<pcr0>/supervisor
│
├─ S3 Migration-Intent Log
│   ├─ Versioning + Object Lock
│   ├─ Public version listing and exact-version reads
│   └─ COMPLIANCE retention set by the enclave on each write
│
├─ EC2 Instance
│   ├─ Amazon Linux 2023
│   ├─ Instance type: configurable (default m6i.xlarge)
│   ├─ Nitro Enclaves: ENABLED
│   ├─ EBS: 32GB (encrypted, gp3)
│   └─ Elastic IP: static public address
│
└─ IAM Role (EC2 instance profile)
    ├─ AmazonSSMManagedInstanceCore (SSM Session Manager access)
    ├─ S3: Read for all uploaded assets
    ├─ KMS: attestation-gated key operations
    ├─ SSM: scoped state, ciphertext, and discovery parameters
    ├─ S3: append/read exact migration-intent versions, without delete/bypass
    └─ STS: GetCallerIdentity (for KMS policy construction)
```

---

## 4. EC2 Host Bootstrap

The `user_data` script executes on first boot:

```
EC2 Instance Launch
    │
    ├─ 1. SYSTEM PREPARATION
    │   ├─ Install packages: aws-nitro-enclaves-cli, jq, git
    │   └─ Configure nitro-enclaves-allocator:
    │       ├─ Memory: 6144 MB (6 GB reserved for enclave)
    │       └─ CPUs: 2 (dedicated to enclave)
    │
    ├─ 2. DOWNLOAD ASSETS FROM S3
    │   ├─ /home/ec2-user/app/server/enclave.eif           ← pre-built EIF
    │   ├─ /home/ec2-user/app/supervisor                   ← host supervisor binary
    │   └─ /etc/systemd/system/enclave-supervisor.service  ← sole systemd unit
    │
    ├─ 3. WRITE ENVIRONMENT (/etc/environment)
    │   ├─ ENCLAVE_APP_NAME={appName}
    │   ├─ EIF_PATH=/home/ec2-user/app/server/enclave.eif
    │   ├─ ENCLAVE_KMS_KEY_ID={kmsKeyArn}
    │   ├─ ENCLAVE_DEPLOYMENT={prefix}
    │   ├─ ENCLAVE_AWS_REGION={region}
    │   ├─ ENCLAVE_NITRIDING_ENABLED=true
    │   ├─ ENCLAVE_NITRIDING_FQDN={domain}
    │   └─ ENCLAVE_MIGRATION_COOLDOWN={cooldown}
    │
    └─ 4. ENABLE & START SERVICES
        ├─ systemctl enable --now docker
        ├─ systemctl enable --now nitro-enclaves-allocator
        ├─ systemctl enable --now nitro-enclaves-vsock-proxy
        ├─ systemctl enable --now enclave-watchdog
        ├─ systemctl enable --now enclave-imds-proxy
        ├─ systemctl enable --now gvproxy
        └─ systemctl enable --now supervisor
```

---

## 5. Host Systemd Services

The host runs exactly **one** systemd unit: `enclave-supervisor.service`, which
execs the `supervisor` binary. The supervisor owns every host-side
responsibility in-process via a single errgroup:

### enclave-supervisor.service
```
Purpose:   All host-side enclave infrastructure in one process
Restart:   always (systemd restarts the supervisor itself)
Requires:  nitro-enclaves-allocator.service
After:     nitro-enclaves-allocator.service, network-online.target

Subsystems (one errgroup, shared context):

  1. gvproxy (gvisor-tap-vsock linked as a Go library)
     • vsock listen: vsock://:1024
     • Gateway 192.168.127.1, VM 192.168.127.2, NAT to 127.0.0.1
     • Pre-populated Forwards from GVPROXY_FORWARD_PORTS (default: 443 7073)

  2. IMDS AF_VSOCK forwarder (pure-Go, github.com/mdlayher/vsock)
     • vsock listen: :8002 on CID_HOST
     • Per-connection bidirectional copy to 169.254.169.254:80
     • Replaces the external `vsock-proxy` binary

  3. Watchdog (nitro-cli subprocess, in-process poll loop)
     • Startup: nitro-cli run-enclave --eif-path $EIF_PATH
                --cpu-count $CPU_COUNT --memory $MEMORY_MIB
                --enclave-cid $ENCLAVE_CID --enclave-name $ENCLAVE_NAME
     • Poll every POLL_INTERVAL_SECONDS (default 5s)
     • On unexpected exit: backoff 1s → 30s, relaunch
     • On ctx.Done: nitro-cli terminate-enclave

  4. Management HTTP server
     • 127.0.0.1:8443 — /health, /metrics, /migrate,
       /migrate/request, /migrate/abort, /start, /stop, …
     • /start and /stop now drive the in-process watchdog directly
```

### supervisor.service
```
Purpose: Host-side management API for admin operations
Command: /home/ec2-user/app/supervisor
Listen: 127.0.0.1:8443 (localhost only)
Access: Only via SSM Session Manager (IAM-gated)
```

---

## 6. Enclave Boot

`nitro-cli run-enclave` launches the EIF with entrypoint `/app/runtime`. No
shell entrypoint, no exec chain — the runtime is process 1 and handles
everything in-process:

```
/app/runtime (process 1)
    │
    ├─ 1. NITRIDING init() seeds /dev/random from NSM via ioctl
    │      (vendored from nitriding/package_init.go; runs before main())
    │
    ├─ 2. runtime.StartViproxy()
    │      AF_INET listen 127.0.0.1:80 → AF_VSOCK dial 3:8002
    │      Sets AWS_EC2_METADATA_SERVICE_ENDPOINT=http://127.0.0.1:80
    │
    ├─ 3. nitriding.NewEnclave(cfg) + .Start()
    │      a. configureLoIface() — brings up lo with 127.0.0.1/8
    │      b. configureTapIface() — brings up tap0 with 192.168.127.2/24
    │      c. writeResolvconf() — nameserver 192.168.127.1 (gvproxy)
    │      d. Generates self-signed TLS certificate
    │      e. Starts HTTPS listener on :443 (tap0)
    │      f. Starts internal HTTP listener on :8080 (loopback)
    │      g. Reverse-proxies HTTPS → runtime's proxy on 127.0.0.1:7073
    │
    ├─ 4. runtime.Init(ctx)
    │      Generates ephemeral secp256k1 attestation key, calls
    │      nitEnc.SetSigningKeyHash(hash) directly (no HTTP).
    │      Loads KMS secrets, extends PCRs, etc.
    │
    └─ 5. exec user app as child process (/app/{binary_name})
           Serves on ENCLAVE_APP_PORT=7074; runtime reverse-proxies to it.
```

---

## 7. Supervisor Initialization (Detailed)

This is the core of the enclave runtime. The supervisor (`sdk/cmd/enclave-supervisor/main.go`) orchestrates everything.

### Step 1: Create Enclave Object

```go
enc := sdk.New()
```
- Generates random 32-byte management token (hex-encoded, 64 chars)
- Initializes atomic flags: `initDone = false`, `initError = ""`
- Initializes runtime state and public/private HTTP muxes

### Step 2: Set Up HTTP Server

```go
mux := http.NewServeMux()
// Reverse proxy: forward non-management requests to user app on :7074
proxy := httputil.NewSingleHostReverseProxy(appURL)
mux.Handle("/", proxy)
// Register management routes
enc.RegisterRoutes(mux)
```

### Step 3: Bind and Start HTTP Servers

```go
private, err := net.Listen("tcp", ":7073")
public, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.ExtPort))
go internalServer.Serve(private)
go externalServer.ServeTLS(public, "", "")
```
- The private and public listeners bind synchronously. Either initial bind
  failure aborts startup, and serving goroutines start only after both binds
  succeed.
- Management endpoints are available **before** initialization completes.
- `/health` returns `{"status": "initializing"}` with 503
- `/v1/enclave-info` returns partial info with error field

### Step 4: Background Init (`enc.Init(ctx)`)

This is where the magic happens. Each sub-step is detailed below:

#### Step 4a: Parse Secrets Config

```go
secretsJSON := os.Getenv("ENCLAVE_SECRETS_CONFIG")
// Parse: [{"name":"signing_key","env_var":"APP_SIGNING_KEY"}, ...]
var secrets []SecretConfig
json.Unmarshal([]byte(secretsJSON), &secrets)
```

#### Step 4b: Generate Attestation Key

```go
func (e *Enclave) generateAttestationKey() error {
    // 1. Open NSM (Nitro Security Module) session
    session, _ := nsm.OpenDefaultSession()

    // 2. Get 32 bytes of hardware-generated randomness
    resp, _ := session.Send(&request.GenerateRandom{Size: 32})
    randomBytes := resp.GenerateRandom.RandomData

    // 3. Derive secp256k1 private key
    privKey, _ := btcec.PrivKeyFromBytes(randomBytes)
    e.attestationKey = privKey

    // 4. Register public key hash with nitriding
    pubkey := privKey.PubKey().SerializeCompressed()  // 33 bytes
    hash := sha256.Sum256(pubkey)
    body := base64.StdEncoding.EncodeToString(hash[:])
    http.Post("http://127.0.0.1:8080/enclave/hash", "text/plain", body)
    // Nitriding includes this hash in its attestation documents
    // so clients can verify response signatures trace back to this enclave
}
```

#### Step 4c: Load AWS Credentials via IMDS

```go
func loadAWSConfigWithIMDS() (aws.Config, error) {
    // 1. Get IMDS token
    //    PUT http://127.0.0.1:80/latest/api/token
    //    Header: X-aws-ec2-metadata-token-ttl-seconds: 21600  (6 hours)

    // 2. Get IAM role name
    //    GET http://127.0.0.1:80/latest/meta-data/iam/security-credentials/
    //    Returns: "EnclaveInstanceRole"

    // 3. Get temporary credentials
    //    GET http://127.0.0.1:80/latest/meta-data/iam/security-credentials/EnclaveInstanceRole
    //    Returns: { AccessKeyId, SecretAccessKey, Token, Expiration }

    // 4. Build AWS config with these credentials
    //    Region: AWS_DEFAULT_REGION → AWS_REGION → ENCLAVE_AWS_REGION → us-east-1

    // Fallback: If IMDS unavailable, use AWS SDK default credential chain
}
```

**IMDS traffic path**:
```
enclave-supervisor → 127.0.0.1:80 (viproxy)
    → vsock CID 3 port 8002 (host vsock-proxy)
    → 169.254.169.254:80 (EC2 IMDS)
```

#### Step 4d: Self-Apply KMS Policy

See [Section 8](#8-kms-policy-and-trust-modes) for full detail.

#### Step 4e: Wait for Secrets from KMS

```
waitForSecretsFromKMS()  ← 5-minute timeout, 5-second polling interval
    │
    └─ For EACH secret in ENCLAVE_SECRETS_CONFIG:
        │
        ├─ getKMSKeyID()
        │   └─ Check SSM:
        │      /{deployment}/{appName}/{locked|unlocked}/KMSKeyID
        │
        ├─ Check key-scoped SSM ciphertext:
        │   /{deployment}/{appName}/{locked|unlocked}/{secretName}/Ciphertext/{kmsKeyID}
        │
        ├─ [NOT FOUND — First Boot] generateAndStoreSecret()
        │   │
        │   ├─ kms.GenerateDataKey({
        │   │     KeyId: kmsKeyId,
        │   │     KeySpec: "AES_256"  // 32 bytes
        │   │   })
        │   │   Returns: { Plaintext: <32 bytes>, CiphertextBlob: <encrypted> }
        │   │
        │   ├─ ssm.PutParameter({
        │   │     Name: "/{deployment}/{appName}/{secretName}/Ciphertext",
        │   │     Value: base64(CiphertextBlob),
        │   │     Type: "SecureString"
        │   │   })
        │   │
        │   └─ os.Setenv(secret.EnvVar, hex.EncodeToString(Plaintext))
        │       // e.g., APP_SIGNING_KEY=a1b2c3d4...  (64 hex chars = 32 bytes)
        │
        └─ [FOUND — Subsequent Boot] decryptExistingSecret()
            │
            ├─ 1. Open NSM session
            │      session, _ := nsm.OpenDefaultSession()
            │
            ├─ 2. Generate RSA-2048 key via NSM hardware
            │      privKey, _ := rsa.GenerateKey(session, 2048)
            │      // Private key generated IN the NSM, never exposed outside enclave
            │
            ├─ 3. Get 32-byte nonce from NSM hardware RNG
            │      resp, _ := session.Send(&request.GenerateRandom{Size: 32})
            │      nonce := resp.GenerateRandom.RandomData
            │
            ├─ 4. Request attestation document from NSM
            │      resp, _ := session.Send(&request.Attestation{
            │          Nonce:     nonce,
            │          UserData:  nil,
            │          PublicKey: marshalRSAPublicKey(privKey.PublicKey),
            │      })
            │      attestationDoc := resp.Attestation.Document
            │      // This is a COSE Sign1 structure (CBOR-encoded)
            │      // Signed by the NSM hardware (unforgeable)
            │      // Contains: PCR0, PCR1, PCR2, nonce, public key
            │
            ├─ 5. Call KMS Decrypt
            │      kms.Decrypt({
            │          CiphertextBlob:        base64Decode(ssmValue),
            │          Recipient: {
            │              KeyEncryptionAlgorithm: "RSAES_OAEP_SHA_256",
            │              AttestationDocument:    attestationDoc,
            │          },
            │      })
            │      //
            │      // AWS KMS performs these checks:
            │      //   a. Verify COSE Sign1 signature against AWS Nitro root CA
            │      //   b. Extract PCR0 from attestation document
            │      //   c. Compare PCR0 against key policy condition:
            │      //      kms:RecipientAttestation:PCR0 == expected_pcr0
            │      //   d. If match: decrypt ciphertext, re-encrypt plaintext
            │      //      using the RSA public key from the attestation doc
            │      //   e. Return CiphertextForRecipient (RSA-encrypted plaintext)
            │      //
            │      // If PCR0 doesn't match → AccessDeniedException
            │
            ├─ 6. Decrypt RSA envelope
            │      result.CiphertextForRecipient  // RSA-OAEP encrypted
            │      plaintext := rsaDecryptOAEP(privKey, ciphertextForRecipient)
            │      // Only this enclave's RSA private key can decrypt
            │      // Key was generated in NSM, never left the enclave
            │
            └─ 7. Set environment variable
                   os.Setenv(secret.EnvVar, hex.EncodeToString(plaintext))
```

#### Step 4f: Extend PCRs with Secret Public Keys

```
extendPCRsWithSecretPubkeys()
    │
    └─ For EACH secret (index i = 0, 1, 2, ...):
        │
        ├─ PCR index = 16 + i  (PCRs 16-31 are user-controllable)
        │
        ├─ Derive secp256k1 key from secret plaintext:
        │   secretBytes := hex.DecodeString(os.Getenv(secret.EnvVar))
        │   privKey, _ := btcec.PrivKeyFromBytes(secretBytes)
        │   pubkey := privKey.PubKey().SerializeCompressed()  // 33 bytes
        │
        ├─ Hash the public key:
        │   hash := sha256.Sum256(pubkey)
        │
        ├─ Extend PCR:
        │   session.Send(&request.ExtendPCR{
        │       Index: uint16(16 + i),
        │       Data:  hash[:],
        │   })
        │   // PCR_new = SHA384(PCR_old || data)
        │   // This cryptographically binds the secret to the enclave's identity
        │
        └─ Lock PCR (immutable for this boot):
            session.Send(&request.LockPCR{
                Index: uint16(16 + i),
            })
            // After locking, no further extensions possible
            // Clients can verify PCR16+ to confirm the enclave holds specific secrets
```

#### Step 4g: Initialize Storage

```
initStorage()
    │
    ├─ 1. Read bucket name from SSM
    │      /{deployment}/{appName}/StorageBucketName
    │      If NOT FOUND → storage silently disabled (not an error)
    │
    ├─ 2. Initialize S3 client
    │      Respects AWS_ENDPOINT_URL_S3 for localstack testing
    │
    ├─ 3. Verify state-origin or migration-transition receipt
    │      The receipt binds the persisted state root and expected PCRs.
    │
    ├─ 4. Load or generate primary DEK
    │      SSM key-scoped ciphertext:
    │      /{deployment}/{appName}/{locked|unlocked}/StorageDEK/Ciphertext/{kmsKeyID}
    │      │
    │      ├─ [NOT FOUND — First Boot]:
    │      │   kms.GenerateDataKey({ KeySpec: "AES_256" })  → 32 bytes
    │      │   Store ciphertext in SSM
    │      │
    │      └─ [FOUND — Subsequent Boot]:
    │          Decrypt via NSM attestation + RSA (same as secret decrypt)
    │          3 retries with exponential backoff (100ms, 200ms, 400ms)
    │
    └─ 5. Store plaintext DEK in memory
           e.dek = plaintext  // 32 bytes, AES-256
           // NEVER written to disk or persistent storage unencrypted
           // Lost on enclave restart (re-decrypted from SSM)
```

#### Step 4h–4k: Final Init Steps

```
    ├─ 4h. Load predecessor state from SSM
    │      ├─ /{deployment}/{appName}/MigrationPreviousPCR0 → e.previousPCR0
    │      └─ /{deployment}/{appName}/MigrationPreviousPCR0Attestation → e.previousPCR0Attestation
    │      (If no migration history, previousPCR0 = "genesis")
    │
    ├─ 4i. Initialize migration intent
    │      ├─ Use the established MigrationIntentBucketName state value
    │      ├─ Register externally readable GET /v1/enclave-info status
    │      └─ Start parent-only vsock:8003 mutation server
    │
    ├─ 4j. Complete required runtime initialization
    │      ├─ Configure TLS and the freshness anchor
    │      ├─ Initialize the K/V store and its RESP listener
    │      ├─ Apply permitted environment overrides
    │      └─ Set verified static-secret environment variables last
    │
    └─ 4k. Keep runtime readiness false
           // /health remains {"status": "initializing"} with 503
```

State establishment in these steps includes the exact current KMS policy
posture, actual KMS access, state provenance, migrated-state materialization,
and state-root verification. Readiness also remains false until freshness,
required listeners, environment setup, and secret initialization have
succeeded.

### Step 5: Spawn User App

```go
cmd := exec.Command("/app/" + binaryName)
cmd.Env = append(os.Environ(),
    "ENCLAVE_APP_PORT=" + appPort,            // port the app should listen on (default 7074)
    "PORT=" + appPort,                         // convenience alias
    "ENCLAVE_RUNTIME_TOKEN=" + enc.RuntimeToken(),  // bearer token for supervisor API calls
)
cmd.Stdout = os.Stdout
cmd.Stderr = os.Stderr
cmd.Start()
rt.NotifyReady()
```

`NotifyReady` runs only after `child.Start()` succeeds. `/health` then returns
HTTP 200 with `{"status":"ready"}`. This is a one-way startup signal: later
child exit does not clear it, and it does not claim ongoing application health.

### Step 6: Supervise

```go
select {
case <-ctx.Done():
    // Shutdown signal received
    cmd.Process.Signal(syscall.SIGTERM)
    // Wait with timeout, then SIGKILL
case err := <-waitCh:
    // Child process exited
    // Log exit code, trigger graceful shutdown
}
```

---

### User App ↔ Supervisor Communication (ENCLAVE_RUNTIME_TOKEN)

The user app runs as a child process of the supervisor, both inside the same enclave. The supervisor exposes management APIs (storage, dynamic secrets) that the user app needs to call. Access is gated by a **bearer token** that is auto-generated at boot and passed to the app via environment variable.

#### Token Lifecycle

```
Supervisor boot (sdk.New())
    │
    ├─ 1. Generate 32 random bytes (crypto/rand)
    │      token := hex.EncodeToString(randomBytes)  // 64 hex chars
    │      Stored in: e.runtimeToken (in-memory only, never persisted)
    │
    ├─ 2. Supervisor starts HTTP server on :7073
    │      Management endpoints check this token on every request
    │
    └─ 3. Spawn user app with token in environment
           child.Env = append(os.Environ(),
               "ENCLAVE_RUNTIME_TOKEN=" + enc.RuntimeToken(),
           )
           // Only the user app (child process) receives this token
           // It never leaves the enclave
```

#### How the User App Uses the Token

The user app reads `ENCLAVE_RUNTIME_TOKEN` from its environment and includes it as a Bearer token in HTTP requests to the supervisor (localhost:7073):

```
User App                                    Supervisor (:7073)
   │                                              │
   │  PUT /v1/secrets/my-key                      │
   │  Authorization: Bearer <ENCLAVE_RUNTIME_TOKEN>  │
   │  {"env_var":"MY_KEY","value":"secret123"}     │
   │ ────────────────────────────────────────────→ │
   │                                              │
   │  ← 201 {"name":"my-key","status":"stored"}   │
   │                                              │
   │  GET /v1/storage/cache/user/42               │
   │  Authorization: Bearer <ENCLAVE_RUNTIME_TOKEN>  │
   │ ────────────────────────────────────────────→ │
   │                                              │
   │  ← 200 <decrypted bytes>                     │
   │                                              │
```

Example from the test app (`test/app/cmd/main.go`):

```go
token := os.Getenv("ENCLAVE_RUNTIME_TOKEN")
if token == "" {
    http.Error(w, `{"error":"ENCLAVE_RUNTIME_TOKEN not set"}`, 500)
    return
}

req, _ := http.NewRequest("PUT", "http://127.0.0.1:7073/v1/secrets/my-key", body)
req.Header.Set("Authorization", "Bearer "+token)
resp, _ := http.DefaultClient.Do(req)
```

#### Token Authentication Logic

The supervisor validates the token on every protected request:

```
checkRuntimeToken(request)
    │
    ├─ If e.runtimeToken == "" → ALLOW (backwards compat, no token configured)
    │
    ├─ If Authorization header missing → 401 Unauthorized
    │
    ├─ If not "Bearer " prefix → 401 Unauthorized
    │
    ├─ If token != e.runtimeToken → 403 Forbidden
    │
    └─ Token matches → ALLOW
```

#### Which Endpoints Require the Token

| Endpoint | Token Required | Purpose |
|----------|---------------|---------|
| `PUT /v1/secrets/{name}` | Yes | Create/update dynamic secret |
| `GET /v1/secrets/{name}` | Yes | Read dynamic secret (with value) |
| `DELETE /v1/secrets/{name}` | Yes | Delete dynamic secret |
| `GET /v1/secrets` | Yes | List dynamic secrets (metadata only) |
| `PUT /v1/storage/{key}` | Yes | Write encrypted storage |
| `GET /v1/storage/{key}` | Yes | Read encrypted storage |
| `DELETE /v1/storage/{key}` | Yes | Delete from storage |
| `GET /v1/storage?prefix=` | Yes | List storage keys |
| `GET /v1/enclave-info` | No | Public enclave metadata |
| `GET /health` | No | Public health check |
| `GET /v1/metrics` | No | Public Prometheus metrics |
| Migration mutations | N/A | Not on public HTTP; parent-only vsock port 8003 |

#### Security Properties

```
1. EPHEMERAL: Token is randomly generated each boot — no static credentials
2. IN-MEMORY ONLY: Never written to disk, SSM, or any persistent store
3. ENCLAVE-SCOPED: Only exists inside the enclave process memory
4. CHILD-ONLY: Passed only to the user app child process via env var
5. NOT EXTERNALLY ACCESSIBLE: External clients reach the app through
   nitriding (TLS) → supervisor reverse proxy → app on :7074
   They never interact with management endpoints directly
6. DEFENSE IN DEPTH: Even if an attacker reaches :7073 from outside,
   they cannot call storage/secrets endpoints without the token
```

---

## 8. KMS Policy and Trust Modes

The runtime reads its own PCR0 from the NSM. At genesis, if the lock-scoped
`KMSKeyID` is unset, the runtime creates the primary KMS key and writes its ID to
SSM. On later boots it fetches the existing policy and verifies that every
Decrypt grant is recipient-attestation gated and that the admitted PCR0 set and
policy-mutation posture match the expected state.

The enclave role receives:

- `kms:Decrypt` and `kms:GenerateDataKey` only with
  `kms:RecipientAttestation:PCR0` matching the admitted PCR0 set.
- `kms:Encrypt` and `kms:GetKeyPolicy` without a recipient condition.
- `kms:ScheduleKeyDeletion` for lifecycle operations.

KMS returns plaintext wrapped to an ephemeral RSA key whose private half remains
inside the enclave. The EC2 host therefore has no direct decrypt path in either
mode.

| `is_kms_key_locked` | Policy posture |
|---|---|
| `false` (default) | Account root receives `kms:PutKeyPolicy`, `kms:GetKeyPolicy`, and `kms:DescribeKey`. Root can rewrite the policy to admit another attested PCR0, but root never has direct `kms:Decrypt`. |
| `true` | No principal receives `kms:PutKeyPolicy`; the policy is frozen after creation, including against account root. |

Host resistance applies in all modes. Account-root resistance applies only when
`is_kms_key_locked=true`. The mode also selects the `locked` or `unlocked` SSM
namespace and is intended to be permanent from first key creation.

During migration, the source enclave creates a migration KMS key admitting both
the source and requested target PCR0. This dual-PCR policy permits the target to
materialize transferred state and permits a transition-receipt-verified rollback
to the source if host activation fails.

---

## 9. Secret Lifecycle

### First Boot (Secret Generation)

```
┌─────────────┐    GenerateDataKey     ┌─────────┐
│   Enclave   │ ─────────────────────→ │   KMS   │
│  Supervisor │ ←───────────────────── │         │
│             │  Plaintext + Ciphertext│         │
└──────┬──────┘                        └─────────┘
       │
       ├─ Plaintext → hex encode → set env var
       │   APP_SIGNING_KEY=a1b2c3d4e5f6...  (64 hex chars)
       │
       └─ Ciphertext → base64 → store in SSM
           /{deployment}/{appName}/signing_key/Ciphertext
```

### Subsequent Boot (Secret Decryption)

```
┌─────────────┐   1. Read ciphertext   ┌─────────┐
│   Enclave   │ ─────────────────────→ │   SSM   │
│  Supervisor │ ←───────────────────── │         │
│             │                        └─────────┘
│             │
│             │   2. Get attestation    ┌─────────┐
│             │ ─────────────────────→ │   NSM   │
│             │ ←───────────────────── │(Hardware)│
│             │  COSE Sign1 doc +      └─────────┘
│             │  RSA-2048 keypair
│             │
│             │   3. Decrypt with       ┌─────────┐
│             │      attestation        │   KMS   │
│             │ ─────────────────────→ │         │
│             │                        │ Verify: │
│             │                        │ PCR0 == │
│             │                        │ policy  │
│             │ ←───────────────────── │         │
│             │  CiphertextForRecipient└─────────┘
│             │  (RSA-encrypted)
│             │
│             │   4. RSA decrypt locally
│             │      (private key never left enclave)
│             │
│             │   5. hex(plaintext) → env var
└─────────────┘
```

### PCR Extension (Cryptographic Binding)

After each secret is loaded:

```
Secret plaintext (32 bytes)
    → derive secp256k1 private key
    → extract compressed public key (33 bytes)
    → SHA256(pubkey) → 32 bytes
    → NSM ExtendPCR(index=16+i, data=hash)
    → NSM LockPCR(index=16+i)

Result: PCR16 = SHA384(zeros || SHA256(pubkey_of_secret_0))
        PCR17 = SHA384(zeros || SHA256(pubkey_of_secret_1))
        etc.

These PCRs are included in attestation documents.
Clients can verify that the enclave holds specific secrets
by checking PCR16+ against known public keys.
```

---

## 10. Storage System (S3 + AES-256-GCM)

### Data Encryption Key (DEK) Lifecycle

```
DEK = 32-byte AES-256 key
    │
    ├─ Generated: KMS GenerateDataKey(AES_256)
    ├─ Stored encrypted: SSM /{deploy}/{app}/StorageDEK/Ciphertext
    ├─ Decrypted at boot: via NSM attestation (same as secrets)
    ├─ Held in memory: e.dek (plaintext, never persisted unencrypted)
    └─ Lost on restart: re-decrypted from SSM on next boot
```

### Write Operation (`PUT /v1/storage/{key}`)

```
Request body (max 10MB)
    │
    ├─ Generate 12-byte nonce from NSM hardware RNG
    │
    ├─ AES-256-GCM encrypt:
    │   cipher := aes.NewCipher(e.dek)          // 32-byte key
    │   gcm := cipher.NewGCM(cipher)
    │   ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
    │   // ciphertext includes 16-byte auth tag
    │
    ├─ Concatenate: nonce (12 bytes) || ciphertext+tag
    │
    └─ Upload to S3:
        s3://bucket/data/{key}

Response: 201 {"key": "...", "status": "stored"}
```

### Read Operation (`GET /v1/storage/{key}`)

```
S3 download: s3://bucket/data/{key}
    │
    ├─ Split: nonce = data[:12], ciphertext = data[12:]
    │
    ├─ AES-256-GCM decrypt:
    │   plaintext := gcm.Open(nil, nonce, ciphertext, nil)
    │   // Verifies auth tag (integrity + authenticity)
    │
    └─ Return: raw bytes (application/octet-stream)

404 if key not found
```

### Delete & List

```
DELETE /v1/storage/{key}  → S3 DeleteObject → 200 {"status": "deleted"}
GET /v1/storage?prefix=x  → S3 ListObjectsV2(prefix="data/x") → ["key1", "key2"]
```

---

## 11. Dynamic Secrets

Dynamic secrets are runtime-configurable secrets stored in the encrypted S3 storage system (under the `secrets/` prefix). Unlike static secrets (from `enclave.yaml`), these can be created, updated, and deleted at runtime.

### Storage Format

Each dynamic secret is stored as an encrypted JSON blob in S3:

```
S3 key: data/secrets/{name}

Encrypted content (DynamicSecret):
{
    "name": "my-api-key",
    "env_var": "MY_API_KEY",        // optional
    "value": "supersecretvalue",     // the actual secret
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
}
```

### API Endpoints

#### Create/Update: `PUT /v1/secrets/{name}`

```
Authorization: Bearer {ENCLAVE_RUNTIME_TOKEN}  (required if token is set)

Request body:
{
    "env_var": "MY_API_KEY",    // optional, for env injection
    "value": "supersecretvalue" // max 64KB
}

Validation:
  - name: alphanumeric + [-_.], no slashes, max 256 chars
  - value: max 65536 bytes

Flow:
  1. Validate name and value
  2. Build DynamicSecret{name, env_var, value, created_at, updated_at}
  3. JSON marshal
  4. Encrypt with AES-256-GCM (using DEK)
  5. Store in S3: data/secrets/{name}
  6. If new: atomically increment dynamicSecretsCount

Response: 201 {"name": "my-api-key", "status": "stored"}
```

#### Read: `GET /v1/secrets/{name}`

```
Flow:
  1. Fetch from S3: data/secrets/{name}
  2. Decrypt with AES-256-GCM
  3. JSON unmarshal → DynamicSecret

Response: 200
{
    "name": "my-api-key",
    "env_var": "MY_API_KEY",
    "value": "supersecretvalue",
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
}

404 if not found
```

#### Delete: `DELETE /v1/secrets/{name}`

```
Flow:
  1. Delete from S3: data/secrets/{name}
  2. Atomically decrement dynamicSecretsCount

Response: 200 {"name": "my-api-key", "status": "deleted"}
```

#### List: `GET /v1/secrets`

```
Flow:
  1. List S3 keys with prefix "data/secrets/"
  2. For each: fetch, decrypt, unmarshal
  3. Strip values (metadata only)

Response: 200
[
    {
        "name": "my-api-key",
        "env_var": "MY_API_KEY",
        "created_at": "2024-01-15T10:30:00Z",
        "updated_at": "2024-01-15T10:30:00Z"
    },
    ...
]
```

### Init-Time Loading (Step 4j)

On supervisor init, all dynamic secrets are loaded from storage:
```
1. List all keys under "secrets/" prefix in S3
2. Count them → set dynamicSecretsCount
3. (Values are NOT loaded into env vars automatically at boot)
4. The user app must call GET /v1/secrets/{name} to retrieve values
   using the ENCLAVE_RUNTIME_TOKEN for authentication
```

---

## 12. Management API (Inside Enclave)

All endpoints below run inside the enclave on the supervisor's HTTP server (port 7073).

### GET /v1/enclave-info

Returns comprehensive enclave state:

```json
{
    "version": "0.0.53",
    "previous_pcr0": "abc123...",
    "previous_pcr0_attestation": "base64...",
    "attestation_pubkey": "02abc123...",
    "metrics": {
        "http_requests_total": 142
    },
    "migration_cooldown_seconds": 1800,
    "migration": {
        "state": "none",
        "source_pcr0": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "upstream_app": {
        "exited": false
    },
    "kms_key_locked": false
}
```

The `migration` object is derived from the authoritative S3 log. Its exact
states and field applicability are defined in [Section 15](#15-migration-flow).

### GET /health

```json
{"status": "ready"}        // 200 — required startup completed and child spawned
{"status": "initializing"} // 503 — Init() still running
```

Readiness is one-way for the lifetime of the runtime. It is not an ongoing
health check for the child application.

### GET /v1/metrics

Prometheus text exposition format:

```
# HELP enclave_http_requests_total Total HTTP requests
# TYPE enclave_http_requests_total counter
enclave_http_requests_total 142

enclave_http_errors_total 3
enclave_kms_operations_total 8
enclave_kms_errors_total 0
enclave_storage_reads_total 50
enclave_storage_writes_total 12
enclave_storage_deletes_total 2
enclave_storage_errors_total 0
enclave_secret_reads_total 30
enclave_secret_writes_total 5
enclave_secret_deletes_total 1
```

Migration mutation is deliberately absent from public HTTP. The parent reaches
`POST /request-migration` and `POST /finalise-migration` on parent-only AF_VSOCK
port `8003`.

### PUT/GET/DELETE /v1/storage/{key}

Encrypted S3 storage. See [Section 10](#10-storage-system-s3--aes-256-gcm).

### PUT/GET/DELETE/GET /v1/secrets/{name}

Dynamic secrets CRUD. See [Section 11](#11-dynamic-secrets).

---

## 13. Host Supervisor

The `supervisor` binary runs on the EC2 host (NOT inside the enclave). It provides administrative operations.

```
Listen: 127.0.0.1:8443 (localhost only)
Access: AWS SSM Session Manager → port forwarding or shell
Binary: /home/ec2-user/app/supervisor
```

### Endpoints

#### GET /health
```json
{"enclave_status": "running", "uptime": "2h30m"}
```
Calls `nitro-cli describe-enclaves` to check enclave state.

#### GET /metrics
Proxies Prometheus metrics from nitriding (port 9090 via gvproxy).

#### POST /start
```
1. watchdog.StartOnce(ctx) — in-process call into supervisor/watchdog.go
2. exec.Command("nitro-cli", "run-enclave", ...) with env-derived args
3. Returns JSON action response
```

#### POST /stop
```
1. watchdog.StopOnce(ctx) — latches the poll loop off so it won't auto-restart
2. exec.Command("nitro-cli", "terminate-enclave", "--enclave-name", ...)
3. Returns JSON action response
```

#### POST /schedule-key-deletion
```
1. Reads KMS key ID from environment/SSM
2. Calls kms.ScheduleKeyDeletion({ PendingWindowInDays: 7 })
3. Key enters "pending deletion" state (recoverable for 7 days)
```

#### POST /migrate
Full migration orchestration. See [Section 15](#15-migration-flow). Returns streaming NDJSON status updates.

#### POST /migrate/request
Proxies a `requested` intent to the source enclave's parent-only control port.

#### POST /migrate/abort
Proxies an `aborted` intent. The enclave appends a new public log sequence; it
does not delete the prior request or clear SSM transit parameters.

---

## 14. Admin Access Flow

```
┌─────────────────┐
│     ADMIN       │
│  (IAM-authed)   │
└────────┬────────┘
         │
         │  AWS SSM Session Manager
         │  (No SSH keys, no inbound ports, IAM-authenticated)
         │
         ▼
┌─────────────────────────────────────────────┐
│              EC2 INSTANCE                    │
│                                             │
│  Option A: Shell access                     │
│    aws ssm start-session --target i-abc123  │
│    $ curl http://127.0.0.1:8443/health      │
│                                             │
│  Option B: CLI-managed port forwarding      │
│    AWS-StartPortForwardingSession           │
│    host port 8443 or enclave port 443       │
│    enclave migration request|status|...     │
│                                             │
│  supervisor (127.0.0.1:8443)             │
│       │                                     │
│       ├─ systemctl start/stop enclave       │
│       ├─ nitro-cli describe-enclaves        │
│       ├─ KMS API calls (key management)     │
│       └─ Migration mutation via vsock:8003  │
└─────────────────────────────────────────────┘
```

**Security model**: No SSH and no public management port. Remote CLI transport
uses Session Manager port forwarding, not Run Command. `GET /v1/enclave-info`
remains externally readable through enclave HTTPS.

---

## 15. Migration Flow

Migration is an explicit operator protocol. OpenTofu publishes candidates but
does not automatically request, finalise, or activate one on an existing host.

```text
enclave build -> enclave tofu -> tofu apply
                                      |
                                      v
                         enclave migration request
                                      |
                         enclave migration status
                             |                 |
                           abort            finalise
```

The supported commands are `enclave migration request|status|abort|finalise`.
`enclave migration finalise --resume` has the narrow retry role described below.
All persistent flags and the complete procedure are in
[OPERATIONS.md](OPERATIONS.md#migration).

### Control Surfaces and Transport

| Surface | Route | Access |
|---|---|---|
| Enclave public HTTPS | `GET /v1/enclave-info` | Externally readable derived status |
| Host management HTTP | `POST /migrate/request` | Localhost `8443`, normally through Session Manager |
| Host management HTTP | `POST /migrate/abort` | Localhost `8443`, normally through Session Manager |
| Host management HTTP | `POST /migrate` | Localhost `8443`, finalisation and activation |
| Enclave mutation control | `POST /request-migration` | Parent-only AF_VSOCK port `8003` |
| Enclave mutation control | `POST /finalise-migration` | Parent-only AF_VSOCK port `8003` |

Remote CLI transport is Session Manager port forwarding through
`AWS-StartPortForwardingSession`, not Run Command. Mutations forward to host port
`8443`; status forwards to enclave HTTPS port `443`.

### Public Migration-Intent Log

The public, versioned S3 log is authoritative. `GET /v1/enclave-info` rescans it
to derive status. The runtime writes each entry with COMPLIANCE Object Lock; the
retention comes from `migration_intent_retention`, default `87600h`.

Every valid object key has this exact form:

```text
migration-intent/<96 lowercase source PCR0>/<20 digit sequence>
```

The sequence is greater than zero and encoded as exactly 20 decimal digits. The
source PCR0 comes from the Nitro attestation and must match the object key; it is
not a JSON field.

The public object is strict JSON with exactly five fields:

```json
{
  "schema": "enclave.migration_intent.v1",
  "sequence": 1,
  "action": "requested",
  "target_pcr0": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "attestation": "<base64 Nitro COSE_Sign1 document>"
}
```

`action` is exactly `requested` or `aborted`; abort retains the request's target.
`target_pcr0` is exactly 96 lowercase hexadecimal characters. Missing,
duplicate, unknown, incorrectly typed, or trailing JSON values invalidate the
version.

The attestation `UserData` is Core Deterministic Encoding canonical CBOR with
these exact logical fields and types:

```text
schema:      text "enclave.migration_intent.v1"
bucket_name: text, exact S3 bucket name
sequence:    unsigned integer
action:      text "requested" or "aborted"
target_pcr0: text, 96 lowercase hexadecimal characters
```

The Nitro certificate chain and COSE signature bind this payload to the source
PCR0. A verifier must rebuild the canonical CBOR and require byte equality,
including the exact bucket identity. Publication time is the exact S3 object
version's `LastModified`, not a host clock, body field, or attestation timestamp.

### Canonical Head Selection

For the current source PCR0, the runtime:

1. Lists all versions under the exact source prefix, following pagination.
2. Fetches each candidate by exact key and exact version ID.
3. Strictly validates the key, JSON, schema, sequence, action, target, Nitro
   chain and COSE signature, source PCR0, canonical CBOR, and bucket identity.
4. Ignores invalid versions.
5. Selects the highest valid sequence.
6. At that sequence, selects the earliest exact-version `LastModified`.
7. Fails closed if valid versions tie at the exact earliest timestamp.

An ambiguous scan retains its maximum sequence internally, allowing a later
request to append past the ambiguity. S3 listing or read failure is store
unavailability, not an empty log.

### Derived Status

States are exactly `none`, `cooling_down`, `eligible`, and `aborted`.

| Field | Applicability |
|---|---|
| `state` | Always |
| `source_pcr0` | Always after NSM PCR0 can be read, including `none` |
| `target_pcr0` | A valid head exists |
| `sequence` | A valid head exists |
| `action` | A valid head exists; `requested` or `aborted` |
| `published_at` | A valid head exists; selected version's `LastModified` |
| `eligible_at` | Requested head only; `published_at + migration_cooldown` |
| `remaining_seconds` | Always; positive seconds rounded up while `cooling_down`, otherwise `0` |

Inapplicable fields are omitted from public JSON. Cooldown is derived from S3
publication time, not a host timer. A zero cooldown still requires a matching
published request; that request is immediately eligible.

### State-Origin Receipts and Boot Selection

Regular state-origin receipts are scoped by the active KMS key ID and the
lowercase current PCR0:

```text
/<deployment>/<app>/StateOriginReceipt/<kms-key-id>/<lowercase-current-pcr0>
```

Migration transition receipts remain scoped only by successor KMS key ID:

```text
/<deployment>/<app>/MigrationStateOriginReceipt/<kms-key-id>
```

Both values are base64-encoded NSM attestation documents whose `UserData`
binds the receipt purpose and canonical state root. There is no fallback to the
legacy unscoped `StateOriginReceipt/<kms-key-id>` path and no inspection of
sibling PCR0 receipt paths.

At boot the runtime reads its current PCR0 and active lock-scoped `KMSKeyID`,
then applies this fail-closed selection:

1. Load only the exact regular receipt for the active key and current PCR0.
2. If it exists, verify its Nitro signature, purpose, state root, and PCR0. Any
   verification failure is fatal; a transition receipt is not a fallback.
3. If it is absent, load the key-scoped transition receipt and require the
   predecessor PCR0 and predecessor attestation artifacts.
4. A successor verifies the predecessor PCR0, its PCR31 commitment to the
   current PCR0, the exact two-PCR KMS policy, and the transition receipt over
   the state root.
5. A rollback-to-self verifies that the current PCR0 is the predecessor,
   derives the one other PCR0 from the exact two-PCR KMS policy, verifies the
   predecessor's PCR31 commitment to that PCR0, and verifies the same transition
   receipt and state root.

Only after the selected receipt and state root verify does the runtime
materialize the DEK and static secrets. During genesis or transition adoption,
it writes the current PCR0-specific regular receipt as part of state
establishment. That regular receipt proves state adoption, not runtime
readiness; freshness, listeners, environment and secret setup, and successful
`child.Start()` still have to complete.

Receipts for both PCR0s under one migration key therefore coexist and are
selected independently:

```text
StateOriginReceipt/K-AB/A
StateOriginReceipt/K-AB/B
MigrationStateOriginReceipt/K-AB
```

For a non-genesis A, B can adopt A's state and write its B receipt; a failed B
activation can then restore A, which uses its own A receipt if present or the
A-to-B transition for rollback-to-self if absent. A and B can subsequently
restart from their own receipts while K-AB remains active. If restored A later
migrates to C, it must publish a fresh A-scoped intent and observe the full new
cooldown. K-AC then admits only A and C; stale K-AB receipts and transition
evidence remain retained but are ignored for active state, and B cannot boot
against K-AC.

The separately tracked genesis rollback-to-self defect is not fixed by this
flow. Rollback after a failed first-generation activation may not restore a
genesis A correctly; the rollback behavior above is the supported non-genesis
case.

### Runtime Readiness

The runtime remains not ready while it establishes and materializes state,
checks exact KMS policy posture and actual access, verifies provenance and
freshness, starts all required listeners, applies environment overrides and
verified secrets, and spawns the application child. The public and private HTTP
listeners perform their initial binds synchronously and fail startup if either
bind fails. HTTP serving begins only after both binds succeed.

Successful `child.Start()` sets the one-way ready signal. A later child or
listener exit continues through the runtime's existing lifecycle handling but
does not clear readiness. `/health` therefore reports completion of required
startup, not ongoing application health.

### Finalisation, Activation, and Rollback

The source runtime finalises only an `eligible` request with an exact target
match. It commits the target PCR0 into PCR31, creates a migration KMS key
admitting source and target PCR0, re-encrypts static secrets and the storage DEK,
writes predecessor attestation and a transition receipt, and changes the active
lock-scoped `KMSKeyID` to the migration key.

The host backs up the current EIF and downloads the PCR0-addressed candidate
without claiming to derive or verify the EIF's PCR0 locally. It stops the source
enclave, swaps the EIF, starts the candidate, and only then constructs a fresh
raw `http.Client`, rather than a verified enclave client, for candidate
verification. That client requires both:

1. `GET /health` returns HTTP 200 with runtime status `ready`.
2. `GET /v1/enclave-info` returns a canonical lowercase 96-hex
   `migration.source_pcr0` exactly equal to the requested target.

Transport failures and HTTP 503 during startup are retried within the bounded
readiness window. A wrong or malformed PCR0, malformed or non-ready response,
other HTTP failure, or readiness timeout prevents cleanup and invokes the
existing EIF rollback, which restores the backup and restarts the source. The
dual-PCR key and transition receipt support this rollback path, subject to the
non-genesis limitation above.

These are operational activation signals, not cryptographic candidate
authentication. The supervisor does not obtain or verify a nonce-bound Nitro
attestation, validate the Nitro certificate chain, pin TLS, or locally derive
and compare the downloaded EIF's PCR measurements.

Only after both operational checks succeed does the supervisor remove temporary
local download and EIF-backup files, optionally promote the candidate
supervisor, and report completion. Host cleanup does not remove PCR-scoped
regular receipts, transition receipts, dual-PCR KMS authorization, or
PCR0-addressed source artifacts needed for deliberate rollback. Candidate
publication is append-only across applies; PCR0-addressed candidates remain in
the deployment asset bucket until that bucket is torn down.

`finalise --resume` sends `finalize=false`: it skips enclave finalisation and
retries host activation. It is valid only after enclave finalisation definitely
succeeded and a later host orchestration step failed. It is not a cooldown or
intent bypass and is unsafe when finalisation success is uncertain.

### Independent Verification and Forks

A conceptual migration-log verifier must enumerate and fetch all exact versions,
enforce strict JSON, verify the AWS Nitro chain and COSE signature, match source
PCR0 plus sequence/action/target, reconstruct canonical CBOR including bucket
identity, and apply `LastModified` canonical selection.

No migration-log verifier CLI is shipped. Existing `enclave verify` verifies a
live enclave's attestation and response-signing bindings; it is different and
does not verify migration-log history. It is also independent of the
supervisor's operational activation checks: the supervisor does not invoke or
reimplement its nonce, Nitro-chain, or expected-PCR verification.

Public versions make hidden forks detectable, not prevented. A retained clone
with the same source PCR0 and valid state can append competing valid entries.
The history and ambiguity remain public, but the protocol does not prove enclave
uniqueness or prevent a retained clone from acting.

---

## 16. External Client Verification

The client library (`client/client.go`) performs full attestation verification before trusting any enclave response.

### Verification Flow

```
┌──────────────┐                           ┌──────────────────┐
│    CLIENT    │                           │     ENCLAVE      │
│              │                           │  (via Elastic IP) │
└──────┬───────┘                           └────────┬─────────┘
       │                                            │
       │  1. Generate random 32-byte nonce          │
       │                                            │
       │  2. GET /enclave/attestation?nonce={nonce}  │
       │ ─────────────────────────────────────────→ │
       │                                            │
       │     (nitriding creates NSM attestation     │
       │      with client's nonce embedded)         │
       │                                            │
       │  ← ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
       │  Base64(COSE Sign1 attestation document)   │
       │                                            │
       │  3. VERIFY ATTESTATION DOCUMENT            │
       │     a. Decode COSE Sign1 (CBOR)            │
       │     b. Verify signature against            │
       │        AWS Nitro root CA certificate chain  │
       │     c. Extract PCRs from payload            │
       │     d. Verify nonce matches (replay prot.)  │
       │     e. Verify PCR0 matches expected value   │
       │        (from config or GitHub Release)      │
       │                                            │
       │  4. GET /v1/enclave-info                   │
       │ ─────────────────────────────────────────→ │
       │  ← ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
       │  { attestation_pubkey: "02abc...", ... }   │
       │                                            │
       │  5. VERIFY ATTESTATION KEY BINDING         │
       │     a. Get signingKeyHash from attestation │
       │        document UserData bytes [36:68]     │
       │        (nitriding bakes SHA256(pubkey)     │
       │         into attestation UserData)         │
       │     b. Parse attestation_pubkey from       │
       │        /v1/enclave-info response           │
       │     c. Compute SHA256(pubkey)              │
       │     d. Assert: SHA256(pk) == signingKeyHash│
       │        (proves the signing key belongs     │
       │         to this specific attested enclave) │
       │                                            │
       │  6. EXECUTE ACTUAL REQUEST                 │
       │     GET /v1/my-api-endpoint                │
       │ ─────────────────────────────────────────→ │
       │  ← ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
       │  Response body + headers:                  │
       │    X-Attestation-Signature: deadbeef...    │
       │    X-Attestation-Pubkey: 02abc123...       │
       │                                            │
       │  7. VERIFY RESPONSE SIGNATURE              │
       │     a. Read response body                  │
       │     b. SHA256(body) → message hash         │
       │     c. Decode X-Attestation-Signature      │
       │     d. Schnorr verify (BIP-340):           │
       │        verify(pubkey, hash, signature)     │
       │     e. If valid: response is authentic     │
       │        (came from this enclave instance)   │
       │                                            │
       │  8. Return verified response to caller     │
       │                                            │
```

### PCR0 Chain Verification (Optional)

```
If --verify-pcr0-chain is enabled:

1. GET /v1/enclave-info → { previous_pcr0, previous_pcr0_attestation }
2. Decode previous_pcr0_attestation (COSE Sign1)
3. Verify against AWS Nitro root CA
4. Extract PCR0 from attestation → should match previous_pcr0
5. Walk chain backwards until "genesis"

This proves the enclave's lineage through every code upgrade.
```

---

## 17. Response Signing (Schnorr Middleware)

Every HTTP response from the enclave supervisor is cryptographically signed after init completes.

```
┌─────────────────────────────────────────────────────────┐
│                   Middleware(handler)                     │
│                                                          │
│  1. Incoming request arrives                             │
│                                                          │
│  2. Call handler, capture response body in buffer        │
│     responseWriter → bufferWriter                        │
│                                                          │
│  3. After handler completes:                             │
│     body := buffer.Bytes()                               │
│                                                          │
│  4. Compute message hash:                                │
│     hash := SHA256(body)                                 │
│                                                          │
│  5. Sign with attestation key (BIP-340 Schnorr):        │
│     signature := schnorr.Sign(e.attestationKey, hash)    │
│     // 64-byte Schnorr signature (R || s)                │
│     // secp256k1 curve, BIP-340 standard                 │
│                                                          │
│  6. Set response headers:                                │
│     X-Attestation-Signature: {hex(signature)}  (128 hex) │
│     X-Attestation-Pubkey: {hex(compressed_pubkey)} (66)  │
│                                                          │
│  7. If signing fails:                                    │
│     X-Attestation-Error: signing-failed                  │
│     (response still sent, just unsigned)                 │
│                                                          │
│  8. Write buffered body to actual response writer        │
└─────────────────────────────────────────────────────────┘

Before initDone: responses pass through UNSIGNED
After initDone:  ALL responses are signed
```

**Why Schnorr?** BIP-340 Schnorr signatures on secp256k1 provide:
- Compact signatures (64 bytes vs 71-72 for ECDSA)
- Provable security in the random oracle model
- Compatible with Bitcoin/Lightning ecosystem (attestation key can serve double duty)

---

## 18. Networking Deep Dive

### Complete Network Path Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         INTERNET                                     │
│                            │                                         │
│                     Elastic IP:443                                    │
│                            │                                         │
├────────────────────────────┼─────────────────────────────────────────┤
│                      EC2 HOST                                        │
│                            │                                         │
│  ┌─────────────────────────┼────────────────────────────────────┐    │
│  │              GVPROXY DOCKER CONTAINER                        │    │
│  │                         │                                    │    │
│  │   Host port 443 ←──→ vsock://:1024 ──→ Enclave TAP:443     │    │
│  │   Host port 7073 ←─→ vsock://:1024 ──→ Enclave TAP:7073   │    │
│  │   Host port 9090 ←─→ vsock://:1024 ──→ Enclave TAP:9090   │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │              VSOCK-PROXY (IMDS)                               │    │
│  │   vsock CID 3:8002 ←──→ 169.254.169.254:80                  │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │              VSOCK-PROXY (AWS SERVICES)                       │    │
│  │   Allowlist:                                                  │    │
│  │     kms.{region}.amazonaws.com:443                            │    │
│  │     ssm.{region}.amazonaws.com:443                            │    │
│  │     sts.{region}.amazonaws.com:443                            │    │
│  │     s3.{region}.amazonaws.com:443                             │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  supervisor ─── 127.0.0.1:8443 ←── SSM Session Manager           │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│                    NITRO ENCLAVE (CID 16)                            │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  viproxy                                                      │    │
│  │    127.0.0.1:80 ←──→ vsock://3:8002 (IMDS via host proxy)   │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  nitriding (TLS termination)                                  │    │
│  │    :443 (HTTPS) ──→ reverse proxy ──→ 127.0.0.1:7073        │    │
│  │    :8080 (internal API: /enclave/attestation, /enclave/hash) │    │
│  │    :9090 (Prometheus metrics)                                 │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  enclave-supervisor                                           │    │
│  │    :7073 (HTTP) ──→ reverse proxy ──→ 127.0.0.1:7074        │    │
│  │    Management endpoints: /v1/*, /health                       │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  user-app                                                     │    │
│  │    :7074 (HTTP) ← application logic                           │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  DNS: 192.168.127.1 (gvproxy gateway)                               │
│  TAP interface: 192.168.127.2/24 (enclave IP, via gvproxy)         │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Traffic Flows

**External client → User app**:
```
Client HTTPS → Elastic IP:443 → gvproxy:443 → vsock → nitriding:443
    → TLS termination → HTTP to supervisor:7073 → reverse proxy → app:7074
```

**Enclave → IMDS (AWS credentials)**:
```
App/Supervisor → 127.0.0.1:80 (viproxy) → vsock CID 3:8002
    → host vsock-proxy → 169.254.169.254:80 (EC2 IMDS)
```

**Enclave → AWS services (KMS, SSM, STS, S3)**:
```
SDK AWS client → DNS (192.168.127.1 gvproxy) → gvproxy TAP
    → host network → VPC endpoint → AWS service
```

**Admin → Management**:
```
Admin CLI → SSM Session Manager port forwarding → host 127.0.0.1:8443
    → supervisor → parent-only migration control on vsock:8003
```

---

## Summary: End-to-End Lifecycle

```
1. INIT        enclave init → scaffold project (17 files + enclave.yaml)
2. CONFIGURE   Edit enclave.yaml (secrets, app coordinates, SDK version)
3. BUILD       enclave build → Nix → EIF (image.eif) + PCR values + supervisor binary
4. DEPLOY      enclave tofu + tofu apply → AWS resources + EC2 instance
5. BOOTSTRAP   EC2 user_data → install packages, download assets, start services
6. BOOT        nitro-cli run-enclave → /app/runtime (links nitriding + viproxy)
7. INIT        Supervisor: generate keys → load credentials → lock KMS → decrypt secrets
8. SERVE       User app starts with secrets as env vars, all traffic signed
9. VERIFY      Clients: fetch attestation → verify PCR0 → verify signatures
10. UPDATE     Publish candidate → request → status → finalise
```
