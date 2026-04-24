# Local Enclave Testing with QEMU

Test your enclave application locally using QEMU's nitro-enclave emulation with mock AWS services. The supervisor runs unmodified -- all mocking is external.

## Prerequisites

- Linux with KVM support (`/dev/kvm` exists)
- Docker and Docker Compose
- Nix (for QEMU 10.x + vhost-device-vsock dev shell)
- An EIF built with `enclave build` (or use the included skeleton app)

## Quick Start

```sh
# Enter the dev shell (provides QEMU 10.x, vhost-device-vsock, gvproxy, awscli).
cd test
nix develop

# Option A: Run with the skeleton test app (builds EIF automatically).
./run.sh

# Option B: Run with your own pre-built EIF.
./run.sh ../.enclave/artifacts/image.eif
```

Or run each step manually:

```sh
# 1. Start mock services
docker compose up -d --build --wait

# 2. Seed SSM parameters and S3 bucket
./seed-ssm.sh

# 3. Boot the enclave in QEMU (interactive, Ctrl+C to stop)
./boot-qemu.sh app/.enclave/artifacts/image.eif   # or your own EIF

# 4. In another terminal: run smoke tests
./smoke-test.sh

# 5. Clean up
docker compose down -v
```

## Skeleton Test App

A minimal Go consumer app is included at `test/app/` for self-contained testing.
It's a simple HTTP server that responds with JSON on port 7074.

The app's `enclave.yaml` already has all mock endpoint overrides configured. To build:

```sh
cd test/app
enclave setup   # compute hashes
enclave build   # build the EIF
```

Or just run `./run.sh` with no arguments — it builds the skeleton automatically.

## Building a Test EIF (Your Own App)

To test your own app, add endpoint overrides to your `enclave.yaml` so the supervisor
talks to the mock services instead of real AWS:

```yaml
app:
  env:
    IMDS_ENDPOINT: "192.168.127.1:1338"
    AWS_ENDPOINT_URL_KMS: "http://192.168.127.1:4000"
    AWS_ENDPOINT_URL_SSM: "http://192.168.127.1:4566"
    AWS_ENDPOINT_URL_STS: "http://192.168.127.1:4566"
    AWS_ENDPOINT_URL_S3: "http://192.168.127.1:4566"
    ENCLAVE_KMS_KEY_ID: "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
```

Then build normally:

```sh
enclave build
```

`192.168.127.1` is the gvproxy gateway IP that routes from inside the QEMU enclave
to the host machine, where Docker is running the mock services.

## Mock Services

Started via `docker compose up -d`:

| Service | Port | Purpose |
|---------|------|---------|
| local-kms | :8080 | Mock KMS with a pre-seeded test key (seed.yaml) |
| kms-proxy | :4000 | Handles attestation-based Decrypt with RecipientInfo |
| localstack | :4566 | Mock SSM Parameter Store, STS, and S3 |
| mock-imds | :1338 | Mock EC2 instance metadata (IMDSv2) |

## Architecture

```
QEMU enclave (192.168.127.2)
  |-- start.sh: launches viproxy, nitriding, runtime
  |-- nitriding: sets up TAP via gvproxy, TLS on :443
  |-- DNS: 192.168.127.1 (gvproxy gateway)
  |-- vsock CID 3:1024 -> gvproxy on host
  |
  |-- All HTTP routes through gvproxy to host:
       |-> :1338 -> mock-imds (Docker)
       |-> :4000 -> kms-proxy -> local-kms:8080 (Docker)
       |-> :4566 -> localstack SSM/STS/S3 (Docker)
       `-> :443  -> forwarded back to enclave (nitriding TLS)
```

### How QEMU Replaces nitro-cli

In production, `nitro-cli run-enclave` boots the EIF inside the Nitro hypervisor.
For local testing, QEMU emulates the same environment:

| Component | Production | QEMU Test |
|-----------|-----------|-----------|
| Hypervisor | Nitro | QEMU `-M nitro-enclave` |
| /dev/nsm | Nitro hardware | QEMU virtio-nsm |
| vsock transport | Nitro hypervisor | vhost-device-vsock |
| Outbound networking | gvproxy (Docker) | gvproxy (native) |
| IMDS | EC2 metadata + vsock-proxy | mock-imds (Docker) |
| KMS | Real AWS KMS | local-kms + kms-proxy |
| SSM/STS/S3 | Real AWS | LocalStack |

## What's Tested

| Component | Status | Notes |
|-----------|--------|-------|
| EIF boot sequence | Real | Your actual EIF boots in QEMU |
| NSM PCR extend/lock | Real | QEMU virtio-nsm, correct PCR0 |
| Attestation key | Real | Ephemeral secp256k1, registered with nitriding |
| KMS GenerateDataKey | Mock | local-kms generates real key material |
| KMS Decrypt + RecipientInfo | Mock | Proxy handles RSA-OAEP + CMS envelope |
| SSM parameters | Mock | LocalStack, API-compatible |
| S3 encrypted storage | Mock | LocalStack, API-compatible |
| Response signing | Real | BIP-340 Schnorr |
| User app | Real | Your app on port 7074, proxied via nitriding |

## How the KMS Proxy Works

When the supervisor sends a KMS `Decrypt` request with a `Recipient` field (containing an attestation document with an RSA public key):

1. The proxy extracts the RSA public key from the COSE Sign1 attestation document.
2. It strips the `Recipient` field and forwards the request to local-kms for plaintext decryption.
3. It wraps the plaintext in a CMS EnvelopedData structure (AES-256-CBC + RSA-OAEP-SHA256).
4. It returns `CiphertextForRecipient` -- the supervisor decrypts this with its ephemeral RSA private key.

All other KMS requests (GenerateDataKey, Encrypt, etc.) pass through unmodified.

## Scripts

| Script | Purpose |
|--------|---------|
| `run.sh <eif>` | Full orchestration: mock services -> seed -> QEMU boot -> smoke tests -> cleanup |
| `boot-qemu.sh <eif>` | Start vhost-device-vsock + gvproxy + QEMU, wait for health |
| `smoke-test.sh` | Verify health, enclave-info, attestation headers, init status |
| `seed-ssm.sh` | Seed SSM parameters and create S3 bucket in LocalStack |

## Configuration

| Environment Variable | Default | Purpose |
|---------------------|---------|---------|
| `GUEST_CID` | 4 | QEMU guest vsock context ID |
| `MEMORY` | 4G | QEMU memory allocation |
| `BOOT_TIMEOUT` | 60/90 | Seconds to wait for enclave health |
| `ENCLAVE_DEPLOYMENT` | dev | SSM parameter path prefix |
| `ENCLAVE_APP_NAME` | app | SSM parameter app name |
| `LOCALSTACK_ENDPOINT` | http://localhost:4566 | LocalStack URL for seeding |

## Troubleshooting

**Enclave won't boot**: Ensure KVM is available (`ls /dev/kvm`). Check that vhost-device-vsock started successfully (socket at `/tmp/vhost4.socket`).

**KMS decrypt fails**: Check kms-proxy logs (`docker compose logs kms-proxy`). The attestation document must contain a valid RSA public key.

**SSM parameter not found**: Run `./seed-ssm.sh` before booting the enclave. Check that `ENCLAVE_DEPLOYMENT` and `ENCLAVE_APP_NAME` match your enclave.yaml.

**Credentials not found**: Ensure mock-imds is running and `IMDS_ENDPOINT` is set to `192.168.127.1:1338` in enclave.yaml env overrides.

**gvproxy networking fails**: Ensure port 1024 is in the vhost-device-vsock `forward-listen` list. Check gvproxy logs for connection errors.

**Nix dev shell missing packages**: Run `nix develop ./test` from the test directory. The flake provides QEMU, vhost-device-vsock, and gvproxy.
