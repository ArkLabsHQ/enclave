# Introspector Enclave — Complete Architecture & Flow

## Table of Contents

1. [High-Level Architecture](#1-high-level-architecture)
2. [Build Flow](#2-build-flow)
3. [CDK Deployment](#3-cdk-deployment)
4. [EC2 Host Bootstrap](#4-ec2-host-bootstrap)
5. [Host Systemd Services](#5-host-systemd-services)
6. [Enclave Boot](#6-enclave-boot-startsh)
7. [Supervisor Initialization](#7-supervisor-initialization-detailed)
8. [KMS Policy Self-Apply](#8-kms-policy-self-apply)
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
| **CLI** | Root Go module (`cmd/enclave/`) | `init`, `build`, `deploy`, `verify`, `start`, `stop`, `destroy` |
| **Nix Flake** | `flake.nix` | Deterministic EIF build (supervisor + app + nitriding + viproxy) |
| **CDK Stack** | `cdk.go` | AWS infrastructure (KMS, SSM, EC2, VPC, S3, IAM) |
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
prefix: dev                # deployment prefix (e.g., dev, staging, prod)

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
```

### 2.3 Build (`enclave build`)

```
enclave build
    │
    ├─ 1. Load enclave.yaml, validate SDK fields (rev, hash, vendor_hash)
    │
    ├─ 2. Generate .enclave/build-config.json from enclave.yaml
    │      Template substitution: {{region}}, {{prefix}}, {{version}}
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

## 3. CDK Deployment

### 3.1 Deploy Command (`enclave deploy`)

```
enclave deploy
    │
    ├─ Load config, validate SDK
    ├─ Read PCR0 from .enclave/artifacts/pcr.json
    ├─ Create/resolve KMS key
    ├─ Pre-create SSM parameters for secrets
    ├─ Synth CDK stack (inline, no cdk.json)
    │   └─ Inject AZ context (Go CDK has no context provider)
    ├─ cdk deploy --app enclave/cdk.out --outputs-file enclave/cdk-outputs.json
    └─ Apply KMS policy using enclave's PCR0
```

### 3.2 AWS Resources Created

```
CDK Stack: NitroIntrospectorStack
│
├─ KMS
│   └─ EncryptionKey
│       ├─ Automatic key rotation: enabled
│       ├─ Retention: retain on deletion (managed separately)
│       └─ Used for: secret encryption/decryption, storage DEK wrapping
│
├─ SSM Parameters (per secret)
│   ├─ /{deployment}/{appName}/{secretName}/Ciphertext     ← primary encrypted secret
│   ├─ /{deployment}/{appName}/Migration/{secretName}/Ciphertext  ← migration transit
│   ├─ /{deployment}/{appName}/MigrationKMSKeyID           ← new key during migration
│   ├─ /{deployment}/{appName}/MigrationOldKMSKeyID        ← old key for cleanup
│   ├─ /{deployment}/{appName}/MigrationRequestedAt        ← RFC3339 timestamp
│   ├─ /{deployment}/{appName}/MigrationPreviousPCR0       ← chain of trust
│   ├─ /{deployment}/{appName}/MigrationPreviousPCR0Attestation ← COSE Sign1 proof
│   ├─ /{deployment}/{appName}/KMSKeyID                    ← current active key ID
│   ├─ /{deployment}/{appName}/StorageBucketName           ← S3 bucket for storage
│   └─ /{deployment}/{appName}/StorageDEK/Ciphertext       ← encrypted data encryption key
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
│   ├─ .enclave/artifacts/image.eif                        ← the enclave image
│   ├─ enclave/systemd/enclave-supervisor.service         ← sole systemd unit
│   └─ .enclave/artifacts/supervisor                       ← host supervisor binary
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
    ├─ KMS: GrantEncryptDecrypt + GrantPutKeyPolicy + GrantGetKeyPolicy
    ├─ SSM: Read/Write all secret and migration parameters
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

  4. Management HTTP server (unchanged)
     • 127.0.0.1:8443 — /health, /metrics, /migrate, /start, /stop, …
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
    │      nitEnc.SetAttestationKeyHash(hash) directly (no HTTP).
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
- Creates empty migration state holders

### Step 2: Set Up HTTP Server

```go
mux := http.NewServeMux()
// Reverse proxy: forward non-management requests to user app on :7074
proxy := httputil.NewSingleHostReverseProxy(appURL)
mux.Handle("/", proxy)
// Register management routes
enc.RegisterRoutes(mux)
```

### Step 3: Start Server Immediately

```go
server := &http.Server{Addr: ":7073", Handler: enc.Middleware(mux)}
go server.ListenAndServe()
```
- Management endpoints are available **before** Init completes
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

See [Section 8](#8-kms-policy-self-apply) for full detail.

#### Step 4e: Wait for Secrets from KMS

```
waitForSecretsFromKMS()  ← 5-minute timeout, 5-second polling interval
    │
    └─ For EACH secret in ENCLAVE_SECRETS_CONFIG:
        │
        ├─ getKMSKeyID()
        │   ├─ Check SSM: /{deployment}/{appName}/KMSKeyID
        │   │   (This is updated during migration to point to the new key)
        │   └─ Fallback: env var ENCLAVE_KMS_KEY_ID (baked in at deploy time)
        │
        ├─ Check SSM: /{deployment}/{appName}/{secretName}/Ciphertext
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
    ├─ 3. Check for migrated DEK
    │      SSM: /{deployment}/{appName}/Migration/StorageDEK/Ciphertext
    │      │
    │      └─ If FOUND (post-migration):
    │          ├─ Decrypt with migration KMS key (3 retries, exponential backoff)
    │          │   Uses same NSM attestation + RSA flow as secret decryption
    │          ├─ Re-encrypt under primary KMS key
    │          ├─ Store as primary: /{deployment}/{appName}/StorageDEK/Ciphertext
    │          └─ Clear migration param
    │
    ├─ 4. Load or generate primary DEK
    │      SSM: /{deployment}/{appName}/StorageDEK/Ciphertext
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
    ├─ 4h. Load migration state from SSM
    │      ├─ /{deployment}/{appName}/MigrationPreviousPCR0 → e.previousPCR0
    │      └─ /{deployment}/{appName}/MigrationPreviousPCR0Attestation → e.previousPCR0Attestation
    │      (If no migration history, previousPCR0 = "genesis")
    │
    ├─ 4i. Cleanup old KMS key (if post-migration)
    │      Read: /{deployment}/{appName}/MigrationOldKMSKeyID
    │      If found: kms.ScheduleKeyDeletion({ PendingWindowInDays: 7 })
    │      Clear the SSM parameter
    │
    ├─ 4j. Load dynamic secrets from storage
    │      Read all keys under "secrets/" prefix in S3
    │      Parse each as DynamicSecret JSON
    │      Set dynamicSecretsCount
    │
    └─ 4k. Mark initialization complete
           atomic.StoreInt32(&e.initDone, 1)
           // /health now returns {"status": "ready"} with 200
           // Schnorr signing middleware now active
```

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
```

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
| `POST /v1/export-key` | No | Migration (verified via SSM) |

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

## 8. KMS Policy Self-Apply

This is the mechanism that **immutably locks** the KMS key to a specific enclave's code identity (PCR0).

### Flow

```
selfApplyKMSPolicy()
    │
    ├─ 1. Get KMS Key ID
    │      getKMSKeyID() → "arn:aws:kms:us-east-1:123456789012:key/abc-123"
    │
    ├─ 2. Extract own PCR0 from NSM attestation
    │      Open NSM session → request attestation → CBOR decode → PCR0
    │      PCR0 = "abc123def456..."  (96 hex chars, SHA-384)
    │
    ├─ 3. Get current key policy
    │      kms.GetKeyPolicy({ KeyId: keyId, PolicyName: "default" })
    │
    ├─ 4. Idempotent check
    │      If policy already contains this PCR0 → return (no-op, already locked)
    │
    ├─ 5. Lock check
    │      If policy exists but does NOT grant kms:PutKeyPolicy to anyone:
    │      → ERROR: key is locked to a DIFFERENT PCR0
    │      (A different enclave version owns this key)
    │
    ├─ 6. Resolve identity
    │      sts.GetCallerIdentity() → "arn:aws:sts::123456789012:assumed-role/EnclaveRole/i-abc"
    │      Convert to IAM role ARN: "arn:aws:iam::123456789012:role/EnclaveRole"
    │
    ├─ 7. Build restricted policy
    │      (see JSON below)
    │
    └─ 8. Apply policy
           kms.PutKeyPolicy({
               KeyId:     keyId,
               PolicyName: "default",
               Policy:     policyJSON,
               BypassPolicyLockoutSafetyCheck: true,
           })
           Retry: 5 attempts, backoff 0s/2s/4s/6s/8s (IAM propagation delay)
```

### KMS Key Policy (after self-apply)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnclaveDecryptWithAttestation",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/EnclaveRole"
      },
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": "abc123def456..."
        }
      }
    },
    {
      "Sid": "EnclaveOperations",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/EnclaveRole"
      },
      "Action": [
        "kms:Encrypt",
        "kms:GetKeyPolicy",
        "kms:GenerateDataKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyDeletion",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/EnclaveRole"
      },
      "Action": "kms:ScheduleKeyDeletion",
      "Resource": "*"
    }
  ]
}
```

**Critical**: Notice `kms:PutKeyPolicy` is **NOT** granted to anyone. Combined with `BypassPolicyLockoutSafetyCheck: true`, this means:

- **Only** enclaves with the exact PCR0 can decrypt
- **Nobody** (not even AWS root) can change the policy
- The key is **immutably locked** to this enclave's code identity
- To use a new code version, you must **migrate** to a new KMS key

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
    "previous_pcr0": "abc123...",              // from migration chain (or "genesis")
    "previous_pcr0_attestation": "base64...",  // COSE Sign1 proof from old enclave
    "attestation_pubkey": "02abc123...",        // compressed secp256k1 (33 bytes hex)
    "dynamic_secrets": 3,                       // count of stored dynamic secrets
    "metrics": {                                // operational counters snapshot
        "http_requests_total": 142,
        "kms_operations_total": 8,
        "storage_reads_total": 50
    },
    "migration_cooldown_seconds": 1800,         // configured cooldown (30m)
    "migration_cooldown_remaining": 0,          // seconds until migration allowed
    "migration_pending": false,                 // whether migration was requested
    "error": ""                                 // empty if healthy
}
```

Before init completes: returns 503 with `{"status": "initializing", "error": "..."}`

### GET /health

```json
{"status": "ready"}        // 200 — init complete, serving traffic
{"status": "initializing"} // 503 — Init() still running
{"status": "degraded"}     // 503 — Init() failed (error in initError)
```

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

### POST /v1/export-key

Migration export endpoint. See [Section 15](#15-migration-flow) for full detail.

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

#### POST /migrate/abort
Aborts an in-progress migration:
```
1. Clear MigrationRequestedAt from SSM
2. Clear MigrationKMSKeyID from SSM
3. Clear all Migration/* ciphertext params
4. Delete the migration KMS key (if created)
```

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
│  Option B: Port forwarding                  │
│    aws ssm start-session --target i-abc123  │
│      --document-name AWS-StartPortForward   │
│      --parameters portNumber=8443           │
│    Then: curl http://localhost:8443/migrate  │
│                                             │
│  supervisor (127.0.0.1:8443)             │
│       │                                     │
│       ├─ systemctl start/stop enclave       │
│       ├─ nitro-cli describe-enclaves        │
│       ├─ KMS API calls (key management)     │
│       └─ HTTP to enclave via gvproxy        │
│           (vsock forwarded ports)            │
└─────────────────────────────────────────────┘
```

**Security model**: No SSH, no public management ports. Only IAM-authenticated SSM sessions can reach the management API.

---

## 15. Migration Flow

Migration is required when the enclave code changes (producing a new PCR0), because the KMS key is immutably locked to the old PCR0. The old enclave must export its secrets so the new enclave can import them under a new KMS key.

### Overview

```
┌──────────────────┐         ┌──────────────────┐
│   OLD ENCLAVE    │         │   NEW ENCLAVE    │
│   (PCR0 = A)     │         │   (PCR0 = B)     │
│                  │         │                  │
│  KMS Key #1      │         │  KMS Key #2      │
│  (locked to A)   │         │  (locked to B)   │
└──────────────────┘         └──────────────────┘
         │                            ▲
         │  export secrets            │  import secrets
         │  re-encrypt with           │  re-encrypt with
         │  migration key             │  new primary key
         ▼                            │
    ┌─────────────────────────────────┐
    │        SSM (Migration/)         │
    │  Transit storage for secrets    │
    │  encrypted with migration key   │
    └─────────────────────────────────┘
```

### Detailed Phase-by-Phase Flow

#### Phase 1: Preparation (supervisor on host)

```
Admin → POST /migrate → supervisor
    │
    ├─ 1. Create NEW KMS key
    │      kms.CreateKey({ Description: "Migration key for {appName}" })
    │      Returns: new_key_arn
    │
    ├─ 2. Store migration metadata in SSM
    │      ├─ /{deploy}/{app}/MigrationKMSKeyID      = new_key_arn
    │      ├─ /{deploy}/{app}/MigrationOldKMSKeyID    = current_key_arn
    │      └─ /{deploy}/{app}/MigrationRequestedAt    = "2024-01-15T10:30:00Z"
    │
    └─ 3. Stream status: {"phase": "preparation", "status": "complete"}
```

#### Phase 2: Export (old enclave)

```
supervisor → POST /v1/export-key → old enclave (via gvproxy)
    │
    │  Request body:
    │  { "migration_key_id": "arn:aws:kms:...:key/new-key-id" }
    │
    └─ Inside old enclave:
        │
        ├─ 1. VERIFY migration key ID
        │      Read SSM: /{deploy}/{app}/MigrationKMSKeyID
        │      Assert: request.migration_key_id == SSM value
        │      (Prevents unauthorized export to arbitrary keys)
        │
        ├─ 2. For EACH secret (signing_key, api_secret, ...):
        │   │
        │   ├─ Read plaintext from env var
        │   │   plaintext := hex.DecodeString(os.Getenv("APP_SIGNING_KEY"))
        │   │
        │   ├─ Re-encrypt with migration KMS key
        │   │   kms.Encrypt({
        │   │       KeyId:     migration_key_id,
        │   │       Plaintext: plaintext,
        │   │   })
        │   │   // No attestation needed for Encrypt (policy allows it)
        │   │
        │   └─ Store in SSM migration namespace
        │       ssm.PutParameter({
        │           Name:  "/{deploy}/{app}/Migration/{secretName}/Ciphertext",
        │           Value: base64(ciphertext),
        │       })
        │
        ├─ 3. Export storage DEK (if storage initialized)
        │      Read e.dek (plaintext, in memory)
        │      Re-encrypt with migration KMS key
        │      Store: /{deploy}/{app}/Migration/StorageDEK/Ciphertext
        │
        ├─ 4. Record PCR0 chain of trust
        │      ├─ Extract own PCR0 from NSM attestation
        │      ├─ Get full attestation document (COSE Sign1)
        │      ├─ Store in SSM:
        │      │   ├─ /{deploy}/{app}/MigrationPreviousPCR0 = "abc123..."
        │      │   └─ /{deploy}/{app}/MigrationPreviousPCR0Attestation = base64(doc)
        │      └─ This creates a verifiable chain: new PCR0 → old PCR0 → older PCR0...
        │
        └─ 5. Return response
               {
                   "pcr0": "abc123...",
                   "exported": ["signing_key", "api_secret"]
               }
```

#### Phase 3: Build & Deploy (supervisor on host)

```
supervisor orchestrates:
    │
    ├─ 1. Build new EIF (with updated code)
    │      New code → different binary → different PCR0
    │
    ├─ 2. Upload new EIF to S3
    │
    ├─ 3. CDK deploy (updates EC2 instance)
    │      New EIF path, same infrastructure
    │
    ├─ 4. Stop old enclave
    │      systemctl stop enclave-watchdog
    │      nitro-cli terminate-enclave
    │
    ├─ 5. Update KMS key ID in SSM
    │      /{deploy}/{app}/KMSKeyID = new_key_arn
    │      (New enclave will read this instead of the env var)
    │
    └─ 6. Start new enclave
           systemctl start enclave-watchdog
           nitro-cli run-enclave (with new EIF)
```

#### Phase 4: Import (new enclave boot)

The new enclave goes through the normal init flow (Section 7), but with migration-aware behavior:

```
New enclave Init()
    │
    ├─ 4b. Generate NEW attestation key (secp256k1)
    │      (Completely new key, not migrated)
    │
    ├─ 4d. selfApplyKMSPolicy()
    │      ├─ getKMSKeyID() → reads /{deploy}/{app}/KMSKeyID → new_key_arn
    │      ├─ Extract NEW PCR0 (PCR0 = B)
    │      └─ Lock new KMS key to new PCR0
    │         Now: only PCR0=B can decrypt with new key
    │
    ├─ 4e. waitForSecretsFromKMS()
    │      For each secret:
    │      │
    │      ├─ Check primary SSM: /{deploy}/{app}/{secret}/Ciphertext
    │      │   This was encrypted with OLD KMS key (locked to PCR0=A)
    │      │   New enclave (PCR0=B) CANNOT decrypt this!
    │      │
    │      ├─ Check migration SSM: /{deploy}/{app}/Migration/{secret}/Ciphertext
    │      │   This was encrypted with MIGRATION KMS key (no PCR0 restriction)
    │      │   New enclave CAN decrypt this!
    │      │
    │      ├─ Decrypt migration ciphertext
    │      │   kms.Decrypt({ KeyId: new_key_arn, CiphertextBlob: migration_ciphertext })
    │      │   (Migration key allows decryption by the EC2 role)
    │      │
    │      ├─ Re-encrypt under new primary key
    │      │   kms.Encrypt({ KeyId: new_key_arn, Plaintext: decrypted_secret })
    │      │   Store in primary SSM: /{deploy}/{app}/{secret}/Ciphertext
    │      │   (Now encrypted with new key, decryptable only by PCR0=B)
    │      │
    │      ├─ Clear migration param
    │      │   Delete: /{deploy}/{app}/Migration/{secret}/Ciphertext
    │      │
    │      └─ Set env var: os.Setenv(secret.EnvVar, hex(plaintext))
    │
    ├─ 4f. Extend PCRs 16+ with secret pubkeys (same as normal boot)
    │
    ├─ 4g. initStorage()
    │      ├─ Find migration DEK: /{deploy}/{app}/Migration/StorageDEK/Ciphertext
    │      ├─ Decrypt with migration key
    │      ├─ Re-encrypt with new primary key → store as primary DEK
    │      ├─ Clear migration DEK param
    │      └─ All existing S3 data remains accessible (same DEK, just re-wrapped)
    │
    ├─ 4h. Load migration state
    │      ├─ previousPCR0 = "abc123..." (old enclave's PCR0)
    │      └─ previousPCR0Attestation = base64(COSE Sign1 from old enclave)
    │      This forms a verifiable chain of custody
    │
    ├─ 4i. Cleanup old KMS key
    │      Read: /{deploy}/{app}/MigrationOldKMSKeyID → old_key_arn
    │      kms.ScheduleKeyDeletion({ KeyId: old_key_arn, PendingWindowInDays: 7 })
    │      Delete SSM param: MigrationOldKMSKeyID
    │      // Old key enters "pending deletion" — recoverable for 7 days
    │
    └─ 4k. initDone = true
           New enclave is now fully operational with all migrated secrets
```

### Migration Cooldown

```
ENCLAVE_MIGRATION_COOLDOWN = "30m" (from enclave.yaml)

After a migration completes:
  - MigrationRequestedAt timestamp is preserved in SSM
  - On GET /v1/enclave-info:
    - migration_cooldown_remaining = max(0, cooldown - elapsed)
    - Cached for 5 seconds (avoid SSM hammering)
  - If migration_cooldown_remaining > 0:
    - POST /v1/export-key returns 429 Too Many Requests
    - Prevents rapid successive migrations

Purpose: Safety valve against accidental rapid migrations
         that could cause secret loss or key confusion
```

### Migration Chain of Trust

```
Genesis (first deploy):
  PCR0 = A, previous_pcr0 = "genesis"

After first migration:
  PCR0 = B, previous_pcr0 = A, attestation = <signed proof from A>

After second migration:
  PCR0 = C, previous_pcr0 = B, attestation = <signed proof from B>

Verification:
  Client can walk the chain: C → B → A → genesis
  Each link includes a hardware-signed attestation document
  proving the migration was from a legitimate enclave instance
```

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
       │     a. Extract appKeyHash from attestation │
       │        document UserData bytes [36:68]     │
       │        (nitriding bakes SHA256(pubkey)     │
       │         into attestation UserData)         │
       │     b. Parse attestation_pubkey from       │
       │        /v1/enclave-info response           │
       │     c. Compute SHA256(pubkey)              │
       │     d. Assert: SHA256(pubkey) == appKeyHash│
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
Admin → SSM Session Manager → EC2 shell → curl 127.0.0.1:8443
    → supervisor → (for enclave calls) gvproxy:7073 → supervisor:7073
```

---

## Summary: End-to-End Lifecycle

```
1. INIT        enclave init → scaffold project (17 files + enclave.yaml)
2. CONFIGURE   Edit enclave.yaml (secrets, app coordinates, SDK version)
3. BUILD       enclave build → Nix → EIF (image.eif) + PCR values + supervisor binary
4. DEPLOY      enclave deploy → CDK → AWS resources + EC2 instance
5. BOOTSTRAP   EC2 user_data → install packages, download assets, start services
6. BOOT        nitro-cli run-enclave → /app/runtime (links nitriding + viproxy)
7. INIT        Supervisor: generate keys → load credentials → lock KMS → decrypt secrets
8. SERVE       User app starts with secrets as env vars, all traffic signed
9. VERIFY      Clients: fetch attestation → verify PCR0 → verify signatures
10. MIGRATE    Admin: POST /migrate → export secrets → build new EIF → import → cleanup
11. REPEAT     New enclave boots with migrated secrets, chain of trust preserved
```
