# Local Enclave Testing with QEMU

Test your enclave application locally using QEMU's nitro-enclave emulation with mock AWS services. The supervisor runs unmodified -- all mocking is external.

## Prerequisites

- Linux with KVM support (or WSL2 with nested virtualization)
- Docker and Docker Compose
- QEMU 10.x with nitro-enclave support
- vhost-device-vsock (from rust-vmm crate)
- An EIF built with `enclave build`

## Quick Start

### 1. Start mock services

```sh
cd test
docker compose up -d
```

This starts:

- **local-kms** (:8080) -- Mock KMS with a pre-seeded test key
- **kms-proxy** (:4000) -- Handles attestation-based Decrypt with RecipientInfo
- **localstack** (:4566) -- Mock SSM Parameter Store and STS
- **mock-imds** (:1338) -- Mock EC2 instance metadata (IMDSv2)

### 2. Seed SSM with test parameters

```sh
aws --endpoint-url=http://localhost:4566 ssm put-parameter \
  --name "/dev/my-app/KMSKeyID" \
  --value "arn:aws:kms:us-east-1:123456789012:key/test-key-id" \
  --type String
```

### 3. Build the EIF with local endpoints

Add the following to your `enclave.yaml` app.env section:

```yaml
app:
  env:
    IMDS_ENDPOINT: "192.168.127.1:1338"
    AWS_ENDPOINT_URL_KMS: "http://192.168.127.1:4000"
    AWS_ENDPOINT_URL_SSM: "http://192.168.127.1:4566"
    AWS_ENDPOINT_URL_STS: "http://192.168.127.1:4566"
    ENCLAVE_KMS_KEY_ID: "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
```

Then build:

```sh
enclave build
```

Note: `192.168.127.1` is the gvproxy gateway IP that routes from inside the QEMU enclave to the host machine.

### 4. Start vsock bridge

```sh
vhost-device-vsock \
  --vm guest-cid=4,forward-cid=1,forward-listen=9000+443,socket=/tmp/vhost4.socket
```

### 5. Boot the enclave in QEMU

```sh
qemu-system-x86_64 \
  -M nitro-enclave,vsock=c,id=test-enclave \
  -kernel enclave/my-app-enclave.eif \
  -nographic -m 4G --enable-kvm -cpu host \
  -chardev socket,id=c,path=/tmp/vhost4.socket
```

## Architecture

```
QEMU enclave -> viproxy (vsock) -> host network
                                    |-> kms-proxy:4000 -> local-kms:8080
                                    |-> localstack:4566 (SSM, STS)
                                    +-> mock-imds:1338
```

## What's Tested

| Component | Status | Notes |
|-----------|--------|-------|
| EIF boot sequence | Real | Your actual EIF boots in QEMU |
| NSM PCR extend/lock | Real | QEMU virtio-nsm, correct PCR0 |
| Attestation key | Real | Ephemeral secp256k1, registered with nitriding |
| KMS GenerateDataKey | Mock | local-kms generates real key material |
| KMS Decrypt + RecipientInfo | Mock | Proxy handles RSA-OAEP + CMS envelope |
| SSM parameters | Mock | LocalStack, API-compatible |
| Response signing | Real | BIP-340 Schnorr |
| User app | Real | Your app on port 7074 |

## How the KMS Proxy Works

When the supervisor sends a KMS `Decrypt` request with a `Recipient` field (containing an attestation document with an RSA public key):

1. The proxy extracts the RSA public key from the COSE Sign1 attestation document.
2. It strips the `Recipient` field and forwards the request to local-kms for plaintext decryption.
3. It wraps the plaintext in a CMS EnvelopedData structure (AES-256-CBC + RSA-OAEP-SHA256).
4. It returns `CiphertextForRecipient` -- the supervisor decrypts this with its ephemeral RSA private key.

All other KMS requests pass through unmodified.

## Troubleshooting

**Enclave won't boot**: Ensure vhost-device-vsock is running and the heartbeat responder is active on vsock port 9000.

**KMS decrypt fails**: Check kms-proxy logs (`docker compose logs kms-proxy`). The attestation document must contain a valid RSA public key.

**SSM parameter not found**: Seed parameters via the aws CLI with `--endpoint-url=http://localhost:4566`.

**Credentials not found**: Ensure mock-imds is running and `IMDS_ENDPOINT` is set to `192.168.127.1:1338` in enclave.yaml.
