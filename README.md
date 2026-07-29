# enclave

A Nix toolchain and Go runtime for running an application inside an AWS Nitro
Enclave. The runtime establishes encrypted state under a KMS key whose policy is
conditioned on the enclave's PCR0 measurement, exposes an attested HTTPS
endpoint, and implements a blue/green migration protocol that transfers that
state to a successor enclave with a different measurement.

The repository provides four Nix functions that build the enclave image, the EC2
host system, and the OpenTofu stack that deploys them; a Go client library and
CLI that verify an enclave's attestation before talking to it; and a NixOS test
that exercises the entire deployment against an AWS emulator under nested KVM.

Supported systems for the runtime, enclave images, and checks are `x86_64-linux`
and `aarch64-linux`. The CLI and client library additionally build on
`aarch64-darwin` and `x86_64-darwin`.

## Contents

- [Repository layout](#repository-layout)
- [Quickstart](#quickstart)
- [Architecture](#architecture)
- [Nix API](#nix-api)
- [Runtime configuration](#runtime-configuration)
- [HTTP API](#http-api)
- [Deployment](#deployment)
- [Blue/green migration](#bluegreen-migration)
- [Verifying an enclave](#verifying-an-enclave)
- [Testing](#testing)
- [Security notes](#security-notes)

## Repository layout

| Path | Contents |
|---|---|
| `runtime/` | The Go runtime that runs as PID 1 inside the enclave. Separate Go module, `github.com/ArkLabsHQ/enclave/runtime`. |
| `client/` | Go client library for attestation-verified requests. Part of the root module. |
| `cmd/enclave/` | The `enclave` CLI. |
| `nix/` | The four exported build functions plus runtime, CLI, and dependency packaging. |
| `nix/tests/` | Flake checks, including the full blue/green NixOS test. |

## Quickstart

Add the flake as an input and build an enclave image, a host AMI, and a
deployment stack from your application derivation.

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    enclave.url = "github:ArkLabsHQ/enclave";
  };

  outputs =
    { nixpkgs, enclave, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };

      myapp = pkgs.buildGoModule {
        pname = "myapp";
        version = "1.0.0";
        src = ./.;
        vendorHash = null;
      };

      eif = enclave.lib.buildEif {
        inherit pkgs;
        app = myapp;
        env = {
          ENCLAVE_DEPLOYMENT = "prod";
          ENCLAVE_APP_NAME = "myapp";
          ENCLAVE_AWS_REGION = "eu-west-1";
          ENCLAVE_PREVIOUS_PCR0 = "genesis";
        };
      };
    in
    {
      packages.${system} = {
        inherit eif;

        ami =
          (enclave.lib.mkEnclaveAmi { inherit pkgs eif; })
          .config.system.build.images.amazon;

        tofu = enclave.lib.mkEnclaveTofu {
          inherit pkgs;
          app = "myapp";
          deployment = "prod";
        };
      };
    };
}
```

Build the image and read its measurement:

```sh
nix build .#eif
cat result/pcr.json          # {"PCR0":"...","PCR1":"...","PCR2":"..."}
```

`PCR0` is the identity of the enclave. It is what the KMS key policy is
conditioned on and what clients pin. It changes whenever the runtime, the
application, or the baked environment changes.

Once deployed, verify the running enclave from a client:

```sh
nix run github:ArkLabsHQ/enclave -- curl /v1/enclave-info \
  --base-url https://enclave.example.com \
  --expected-pcr0 "$(jq -r .PCR0 result/pcr.json)"
```

## Architecture

Four layers, each built by a separate function.

```text
┌─ OpenTofu stack ──────────────────────────────────────────┐
│  aws_instance.nitro["blue"]   aws_instance.nitro["green"] │
│                    \             /                        │
│                  aws_eip (stable public address,          │
│                           follows active_slot)            │
│  S3: tls-cache, migration-intent-log (Object Lock)        │
│  SSM: bucket-name parameters   IAM: instance role         │
└───────────────────────────────────────────────────────────┘
                            │  each instance boots
                            ▼
┌─ EC2 host AMI (mkEnclaveAmi) ─────────────────────────────┐
│  gvproxy          vsock:1024  L2 network for the enclave  │
│  imds-proxy       vsock:8002 -> 169.254.169.254:80        │
│  migration-proxy  127.0.0.1:8003 -> enclave vsock:8003    │
│  enclave-start    nitro-cli run-enclave                   │
│  enclave-watchdog restarts the enclave if it dies         │
└───────────────────────────────────────────────────────────┘
                            │  launches
                            ▼
┌─ Enclave image, EIF (buildEif) ───────────────────────────┐
│  /app/runtime   PID 1: clock, network, AWS, state, TLS    │
│  /app/<name>    your application, exec'd by the runtime   │
│                 listens on 127.0.0.1:7074                 │
└───────────────────────────────────────────────────────────┘
```

### Host services

The host services are production code shared between the real AMI and the QEMU
test host. `nix/enclave-host-module.nix` owns all five services; the two
wrappers differ only in a small launcher interface with `run`, `alive`,
`terminate`, `path`, and `requires` members. `mk-enclave-ami.nix` supplies a
`nitro-cli` launcher and the Nitro allocator; `mk-enclave-qemu-ami.nix` supplies
a `qemu-system-x86_64 -M nitro-enclave` launcher and `vhost-device-vsock`. New
host behaviour belongs in the shared module unless it is genuinely specific to
Nitro hardware or to QEMU.

### Ports

| Endpoint | Direction | Purpose |
|---|---|---|
| vsock CID 3:1024 | enclave to host | gvproxy L2 network |
| vsock CID 3:8002 | enclave to host | IMDS forwarding |
| vsock CID 3:9000 | EIF init to host | boot heartbeat |
| vsock :8003 | host to enclave | migration control HTTP |
| TCP :443 | public to enclave | TLS, runtime API, application proxy |
| TCP 127.0.0.1:8080 | inside enclave | internal runtime API |
| TCP 127.0.0.1:7074 | inside enclave | the application |

Port 8003 is bound to host loopback only. Operators reach it through SSM Session
Manager port forwarding; the instance role carries
`AmazonSSMManagedInstanceCore` for this.

### State model

The runtime does not persist anything to disk. All state lives in AWS, encrypted
under a KMS key that only the measured enclave can use.

- At genesis the runtime creates a KMS key whose policy admits exactly one PCR0:
  its own. Every subsequent `Decrypt` and `GenerateDataKey` call is attested, so
  a different enclave image cannot read the state even with the same IAM role.
- A 32-byte storage DEK and each configured static secret are generated by
  attested `GenerateDataKey` calls and stored in SSM as key-scoped ciphertexts.
- Each static secret is committed to a PCR: secret *i* extends PCR(16+i), which
  is then locked. The secrets are therefore part of the enclave's measurement
  from the point of generation onward.
- `/<deployment>/<app>/<locked|unlocked>/KMSKeyID` is written last, both at
  genesis and at migration finalisation. It is the atomic commit point: its
  value selects which generation of ciphertexts is live. It must never be
  managed by OpenTofu.

### Boot paths

On startup the runtime reads SSM and selects one of three paths.

| Condition | Path | Behaviour |
|---|---|---|
| `KMSKeyID` absent, empty, or `UNSET` | genesis | Requires `ENCLAVE_PREVIOUS_PCR0=genesis` and no predecessor artifacts. Creates the key, generates the DEK and secrets, writes a state-origin receipt, then commits `KMSKeyID`. |
| `KMSKeyID` present and a state-origin receipt exists for this PCR0 | resume | Verifies its own receipt, decrypts state, writes nothing. |
| `KMSKeyID` present, no receipt for this PCR0, but a migration transition receipt and predecessor artifacts exist | adopt | Verifies the predecessor's attestation, the PCR31 commitment to its own PCR0, the KMS key policy, and the transition receipt before decrypting. Then writes its own state-origin receipt. |

Boot order is fixed and every step is fatal: clock synchronisation against
`/dev/ptp0`, networking, AWS clients, telemetry, attestation signer, HTTP
servers, state establishment, PCR extension, migration control server, TLS, SSM
environment overlay, static secret export, then exec of the application.

## Nix API

The flake exports four functions under `lib`.

### `lib.buildEif`

Builds a measured enclave image.

Arguments:

```nix
{
  pkgs,                  # package set
  app,                   # package; executable selected with pkgs.lib.getExe
  env,                   # environment baked into the measurement
  extraPackages ? [ ],   # additional packages in the enclave rootfs
}
```

Produces a derivation containing `image.eif` and `pcr.json`.

- `buildEif` selects the executable with `pkgs.lib.getExe`. Set
  `app.meta.mainProgram` when it differs from the package name. The executable
  is copied under `/app`, and `APP_BINARY_NAME` is injected automatically.
- `env` is part of the measurement. Changing any value changes PCR0.
- The rootfs contains the system CA store and nothing else by default. The
  runtime never shells out. Applications that need `/bin/sh` or other utilities
  must request them: `extraPackages = [ pkgs.busybox ]`.

### `lib.mkEnclaveAmi`

Builds the NixOS system for the EC2 host instance.

Arguments:

```nix
{
  eif,                       # result of buildEif
  pkgs,                      # preserved as-is, including overlays
  memoryMib ? 4320,          # memory allocated to the enclave
  cpuCount ? 2,              # vCPUs allocated to the enclave
  enclaveCID ? 16,           # enclave vsock CID
  enclaveName ? "enclave",   # nitro-cli enclave name
}
```

Returns a `nixosSystem` result. Two attributes matter:

| Attribute | Purpose |
|---|---|
| `config.system.build.toplevel` | The system closure. This is what the `ami-build` check builds. |
| `config.system.build.images.amazon` | The EC2 disk image to upload and register as an AMI. |

The Nitro allocator is configured with `memoryMib + 1820` MiB to cover enclave
overhead.

### `lib.mkEnclaveQemuAmi`

Returns a NixOS **module**, not a system. It configures a NixOS test node to run
the same host services as the production AMI, launching the enclave under QEMU's
`nitro-enclave` machine instead of Nitro hardware.

Arguments:

```nix
{
  eif,                       # result of buildEif
  memoryMib ? 2048,
  cpuCount ? 2,
  enclaveCID ? 16,
  enclaveName ? "enclave",
}
```

Use it in a test node's `imports`. It requires nested KVM; see
[Testing](#testing).

### `lib.mkEnclaveTofu`

Generates the OpenTofu stack and a CLI wrapper that runs it.

Arguments:

```nix
{
  pkgs,
  app,                       # application name
  deployment,                # environment name; must match ENCLAVE_DEPLOYMENT
  local ? false,             # target an AWS emulator instead of real AWS
  region ? "us-east-1",
}
```

Returns a derivation providing a `tofunix` binary, with `.tfjson` (the generated
`main.tf.json`) and `.module` attached. `app` and `deployment` determine the
resource name prefix and the SSM parameter paths. `region` is a build-time
argument, not an OpenTofu variable; changing region means rebuilding the
derivation. Set `local = true` only for emulator use — it injects
`http://localhost:4566` endpoints and `test` credentials.

## Runtime configuration

Configuration is supplied through the EIF environment, which is part of the
measurement. A subset can be overridden at runtime from SSM.

### Identity and security

| Variable | Default | Purpose |
|---|---|---|
| `ENCLAVE_DEPLOYMENT` | `dev` | First SSM path segment. The value `dev` disables COSE signature verification of attestation documents. See [Security notes](#security-notes). |
| `ENCLAVE_APP_NAME` | `app` | Second SSM path segment. |
| `ENCLAVE_PREVIOUS_PCR0` | none | Required. Either the literal `genesis`, or the predecessor's PCR0 when adopting migrated state. Unset fails the boot. |
| `ENCLAVE_KMS_KEY_LOCKED` | `false` | When `true`, the KMS key policy omits the root recovery principal and the SSM namespace segment becomes `locked` instead of `unlocked`. |
| `ENCLAVE_SECRETS_CONFIG` | empty | JSON array of managed static secrets. Schema below. |
| `ENCLAVE_AWS_REGION` | `us-east-1` | Region for all AWS SDK clients. |

### Listeners and application

| Variable | Default | Purpose |
|---|---|---|
| `ENCLAVE_NITRIDING_EXT_PORT` | `443` | External TLS listener. |
| `ENCLAVE_NITRIDING_INT_PORT` | `8080` | Internal loopback API listener. |
| `ENCLAVE_APP_PORT` | `7074` | Port the application listens on. |
| `ENCLAVE_NITRIDING_UPSTREAM` | `auto` | Runtime-to-application HTTP version. `h1` pins HTTP/1.1, `h2c` pins HTTP/2 cleartext and is required for gRPC, `auto` matches the inbound request. |
| `ENCLAVE_NITRIDING_FQDN` | `localhost` | Hostname for the TLS certificate. |
| `ENCLAVE_NITRIDING_HOST_PROXY_PORT` | `1024` | Host vsock port where gvproxy listens. |
| `ENCLAVE_NITRIDING_DEBUG` | `false` | Reported by `GET /enclave/config`. |
| `ENCLAVE_VIPROXY_ENABLED` | `true` | Set to `false` to disable the in-process IMDS forwarder. |
| `ENCLAVE_VIPROXY_IN_ADDRS` | `127.0.0.1:80` | IMDS forwarder listen address. |
| `ENCLAVE_VIPROXY_OUT_ADDRS` | `3:8002` | IMDS forwarder target, `CID:PORT` or `host:port`. |
| `APP_BINARY_NAME` | `app` | Set by `buildEif` from the selected executable. The runtime execs `/app/<value>`. |

### Migration

| Variable | Default | Purpose |
|---|---|---|
| `ENCLAVE_MIGRATION_COOLDOWN` | `0` | Minimum interval between `/request-migration` and `/finalise-migration`. A negative or unparseable value fails the boot. |
| `ENCLAVE_MIGRATION_INTENT_RETENTION` | `87600h` (10 years) | S3 Object Lock retention applied to each migration intent record. |

### Clock

| Variable | Default | Purpose |
|---|---|---|
| `ENCLAVE_CLOCK_POLL_INTERVAL` | `5m` | Poll cadence for disciplining `CLOCK_REALTIME` against `/dev/ptp0`. |

The runtime hard-steps the clock onto the PTP hardware clock at startup, then
runs a PI servo that corrects frequency drift. Offsets above 100 ms trigger
another hard-step. `/dev/ptp0` is mandatory; the boot fails without it.

### Logging and tracing

| Variable | Default | Purpose |
|---|---|---|
| `ENCLAVE_LOG_CLOUDWATCH` | `false` | Ship logs and traces to CloudWatch Logs. |
| `ENCLAVE_LOG_BUFFER_SIZE` | `1000` | In-memory log ring buffer capacity. |
| `ENCLAVE_SPAN_BUFFER_SIZE` | `1000` | In-memory span ring buffer capacity. |
| `ENCLAVE_LOG_SHIP_INTERVAL` | `5s` | Flush cadence. Batches also flush at 100 events. |
| `ENCLAVE_LOG_RETENTION_DAYS` | `30` | Retention applied to created log groups. |

Log groups are `/enclave/<deployment>/<app>/logs` and
`/enclave/<deployment>/<app>/traces`.

### AWS endpoint overrides

`AWS_ENDPOINT_URL_KMS`, `AWS_ENDPOINT_URL_SSM`, `AWS_ENDPOINT_URL_STS`,
`AWS_ENDPOINT_URL_S3`, and `AWS_ENDPOINT_URL_LOGS` override the corresponding
service endpoints. Setting the S3 endpoint also forces path-style addressing.
These exist for testing against an emulator.

### Static secrets

`ENCLAVE_SECRETS_CONFIG` is a JSON array:

```json
[
  { "name": "signing-key", "env_var": "SIGNING_KEY" }
]
```

| Field | Meaning |
|---|---|
| `name` | SSM path segment for the ciphertext. |
| `env_var` | Environment variable set on the application process, containing 64 lowercase hex characters. |

Each secret is a 32-byte value generated by an attested KMS `GenerateDataKey`
call and must be a valid secp256k1 private key; the runtime derives a public key
to compute the PCR extension and rejects invalid values.

Constraints:

- `name` must not be `StorageDEK` and must be unique.
- Order is significant. Secret *i* is committed to PCR(16+i). PCR31 is reserved
  for migration, so at most 15 secrets are supported.
- Changing the array changes the measurement, and therefore PCR0.

### SSM environment overlay

Parameters under `/<deployment>/<app>/env/` are read at boot (non-recursively,
with decryption) and exported into the application's environment. This allows
configuration changes without rebuilding the image.

Seven names are refused, because they define the enclave's identity or security
posture and can only be changed by rebuilding: `ENCLAVE_DEPLOYMENT`,
`ENCLAVE_APP_NAME`, `ENCLAVE_KMS_KEY_LOCKED`,
`ENCLAVE_MIGRATION_COOLDOWN`, `ENCLAVE_MIGRATION_INTENT_RETENTION`,
`ENCLAVE_SECRETS_CONFIG`, `ENCLAVE_PREVIOUS_PCR0`.

Five TLS and ACME settings are read **only** from this overlay, never from the
baked environment, because TLS is configured before the overlay is applied to
the application:

| Parameter under `/<deployment>/<app>/env/` | Purpose |
|---|---|
| `ENCLAVE_NITRIDING_FQDN` | Certificate hostname. |
| `ENCLAVE_NITRIDING_USE_ACME` | `true` switches from self-signed to ACME. |
| `ENCLAVE_NITRIDING_ACME_DIRECTORY` | `letsencrypt-staging` or an `https://` directory URL. |
| `ENCLAVE_NITRIDING_ACME_EMAIL` | ACME account contact. |
| `ENCLAVE_NITRIDING_ACME_CA` | PEM CA bundle for a private ACME server. |

With ACME enabled the certificate cache is stored in the TLS cache bucket,
encrypted under the storage DEK.

### Application process environment

The runtime execs the application with the full runtime environment — including
the SSM overlay and static secrets — plus:

| Variable | Value |
|---|---|
| `PORT` | `ENCLAVE_APP_PORT`, default `7074` |
| `ENCLAVE_APP_PORT` | the same value |
| `ENCLAVE_PROXY_PORT` | the internal API port, default `8080` |
| `ENCLAVE_RUNTIME_TOKEN` | a 32-byte hex bearer token, regenerated each boot |

`ENCLAVE_RUNTIME_TOKEN` authenticates the application to the runtime's telemetry
ingest endpoints. `stdout` and `stderr` are inherited.

### SSM parameters

With `D` = deployment, `A` = app name, `L` = `locked` or `unlocked`:

| Path | Written by | Purpose |
|---|---|---|
| `/D/A/TLSCacheBucketName` | OpenTofu | ACME certificate cache bucket. |
| `/D/A/MigrationIntentBucketName` | OpenTofu | Object-Locked intent log bucket. |
| `/D/A/env/<NAME>` | operator | Environment overlay. |
| `/D/A/L/KMSKeyID` | runtime | Atomic commit point. Never manage this with OpenTofu. |
| `/D/A/L/StorageDEK/Ciphertext/<keyID>` | runtime | Encrypted storage DEK. |
| `/D/A/L/<secret>/Ciphertext/<keyID>` | runtime | Encrypted static secret. |
| `/D/A/StateOriginReceipt/<keyID>/<pcr0>` | runtime | Attested proof of which enclave established this state. |
| `/D/A/MigrationStateOriginReceipt/<keyID>` | runtime | Predecessor's attestation over the successor's state. |
| `/D/A/MigrationPreviousPCR0` | runtime | Predecessor PCR0. |
| `/D/A/MigrationPreviousPCR0Attestation` | runtime | Predecessor attestation after PCR31 commitment. |

## HTTP API

### External listener, TCP :443

TLS 1.2 minimum. Every non-gRPC response carries `X-Attestation-Signature` and
`X-Attestation-Pubkey`, a BIP-340 Schnorr signature over the SHA-256 of the
response body. `/v1/*` responses also carry permissive CORS headers.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/enclave/attestation?nonce=<40 hex>` | none | NSM attestation document, base64. The nonce is mandatory and echoed back. |
| GET | `/enclave` | none | Human-readable index. |
| GET | `/enclave/config` | none | Effective runtime configuration as JSON. |
| GET | `/v1/enclave-info` | none | Version, PCR0, predecessor PCR0 and attestation, attestation public key, migration status, application status. |
| GET | `/health` | none | `{"status":"ready"}` once the application has been started, `{"status":"initializing"}` with status 503 before. |
| GET | `/v1/enclave-metrics` | none | Metric snapshot. |
| GET | `/v1/enclave-logs` | none | Buffered logs. Accepts `since`, `level`, `limit`. |
| GET | `/v1/enclave-traces` | none | Buffered spans. Accepts `since`, `limit`, `service`. |
| POST | `/v1/metrics` | bearer | OTLP protobuf metrics ingest, 1 MiB limit. |
| POST | `/v1/logs` | bearer | OTLP protobuf logs ingest, 1 MiB limit. |
| POST | `/v1/traces` | bearer | OTLP protobuf spans ingest, 1 MiB limit. |
| any | everything else | none | Reverse-proxied to the application. |

Bearer endpoints expect `Authorization: Bearer <ENCLAVE_RUNTIME_TOKEN>`.

`/health` reports ready as soon as the application process has been started,
which is marginally before it binds its port. Readiness probes should target an
application endpoint.

### Internal listener, TCP 127.0.0.1:8080

Serves `/v1/*` and `/health` only, with the same handlers and authentication.
This is the endpoint advertised to the application through
`ENCLAVE_PROXY_PORT`. It does not serve `/v1/enclave-info`, the `/enclave/*`
endpoints, or the application proxy.

### Migration control, vsock :8003

Reached from the host through `migration-proxy` on `127.0.0.1:8003`. No
authentication; access is controlled by the fact that the port is bound to host
loopback and reachable only through SSM Session Manager.

| Method | Path | Body | Purpose |
|---|---|---|---|
| POST | `/request-migration` | `{"action":"requested"\|"aborted","target_pcr0":"<96 hex>"}` | Records an attested, Object-Locked intent in S3. Returns migration status. |
| POST | `/finalise-migration` | `{"new_pcr0":"<96 hex>"}` | Performs the handoff and flips `KMSKeyID`. |

Status codes: `425` while the cooldown is active, `409` if no matching intent
exists or it was aborted, `503` if the intent store is unavailable, `400` for a
malformed body.

## Deployment

### Variables

| Variable | Type | Default | Purpose |
|---|---|---|---|
| `instances` | `map(object({ami_id = string, instance_type = string}))` | `{}` | Slot name to instance definition. |
| `active_slot` | `string` | `"blue"` | Which slot the Elastic IP points at. Must be a key of `instances`. |
| `account` | `string` | none, required | AWS account ID, used in IAM resource ARNs. |

```json
{
  "account": "123456789012",
  "instances": {
    "blue":  { "ami_id": "ami-0123456789abcdef0", "instance_type": "m5.xlarge" },
    "green": { "ami_id": "ami-0fedcba9876543210", "instance_type": "m5.xlarge" }
  },
  "active_slot": "blue"
}
```

### Resources

Per slot, via `for_each` on `instances`:

- `aws_instance.nitro[<slot>]` — Nitro Enclaves enabled, 32 GiB encrypted gp2
  root volume, tagged with `Slot`.

Singletons:

- `aws_eip.instance` and `aws_eip_association.instance` — the stable public
  address, associated with `instances[active_slot]`.
- `aws_s3_bucket.tls_cache` — ACME certificate cache. Public access fully
  blocked.
- `aws_s3_bucket.migration_intent_log` — versioning enabled and Object Lock
  enabled at creation. Retention is set per object by the runtime.
- `aws_ssm_parameter.tls_cache_bucket_name`,
  `aws_ssm_parameter.migration_intent_bucket_name`.
- `aws_iam_role.instance`, `aws_iam_instance_profile.instance`,
  `aws_iam_role_policy.enclave`, plus an attachment of
  `AmazonSSMManagedInstanceCore`.
- `aws_security_group.nitro` with ingress on 443 and unrestricted egress.

Both buckets set `force_destroy = false`, so `tofu destroy` fails while either
is non-empty. Networking uses the account's default VPC; there is no `vpc_id` or
`subnet_id` argument.

### IAM

The instance role grants:

| Statement | Permissions |
|---|---|
| `S3TLSCacheReadWrite` | `GetObject`, `PutObject`, `DeleteObject`, `ListBucket`, `GetBucketLocation` on the TLS cache bucket. |
| `S3MigrationIntentLogObjectLock` | `PutObject`, `GetObject`, `GetObjectVersion`, `PutObjectRetention`, `ListBucket`, `ListBucketVersions`, `GetBucketLocation` on the intent log bucket. |
| `SSMParams` | `GetParameter`, `GetParametersByPath`, `PutParameter` on `/<deployment>/<app>/*`. |
| `KMSAccess` | `CreateKey`, `TagResource`. |
| `STSAccess` | `GetCallerIdentity`. |
| `CloudWatchLogsAccess` | `CreateLogGroup`, `CreateLogStream`, `PutLogEvents`, `PutRetentionPolicy`, `FilterLogEvents`, `DescribeLogStreams` on `/enclave/*`. |

`Encrypt`, `Decrypt`, and `GenerateDataKey` are deliberately absent. Those
operations are authorised by the enclave-created key's own PCR0-conditioned
policy, not by the instance role, so possessing the role is not sufficient to
read enclave state.

### Outputs

| Output | Meaning |
|---|---|
| `elastic_ip` | The stable public address. |
| `instance_ids` | Map of slot to EC2 instance ID. |
| `instance_ips` | Map of slot to auto-assigned public IP, for testing a slot before cutover. |
| `ec2_role_arn` | Instance role ARN. |
| `tls_cache_bucket` | TLS cache bucket name. |
| `migration_intent_log_bucket` | Intent log bucket name. |

### Running the stack

The generated binary is `tofunix` and is a pass-through to OpenTofu with the AWS
provider pinned and vendored, so `init` works offline. The state backend
declares only `key` and `encrypt`; the bucket, region, and lock table are
supplied at `init` time and must be created once beforehand.

```sh
aws s3api create-bucket --bucket my-tofu-state
aws dynamodb create-table --table-name my-tofu-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

cd /srv/enclave-deploy
tofunix init -input=false \
  -backend-config=bucket=my-tofu-state \
  -backend-config=region=eu-west-1 \
  -backend-config=dynamodb_table=my-tofu-lock

tofunix plan  -input=false -out=/srv/enclave-deploy/add-green.plan \
              -var-file=/srv/enclave-deploy/deploy.tfvars.json
tofunix show  -json /srv/enclave-deploy/add-green.plan
tofunix apply -input=false /srv/enclave-deploy/add-green.plan
```

`tofunix` runs OpenTofu against a temporary root module containing a symlink to
the generated, immutable `main.tf.json`. Two consequences:

- **All file paths passed on the command line must be absolute.** A relative
  `-var-file`, `-out`, or plan argument resolves inside the temporary directory.
- `terraform.tfvars` and `*.auto.tfvars` in the working directory are not
  loaded. Pass `-var-file` explicitly.

`.terraform`, `.terraform.lock.hcl`, and `terraform.tfstate` are linked from and
written back to the working directory, so run every command from the same
directory.

## Blue/green migration

Migration transfers state from a running enclave to a successor with a different
PCR0. The successor must not boot before the predecessor has finalised: it would
find `KMSKeyID` pointing at a key whose policy does not admit it, and fail.

The order is:

1. Build the green EIF and read its PCR0. Green's `ENCLAVE_PREVIOUS_PCR0` must
   be set to blue's PCR0, which means blue's measurement is an input to green's
   build.
2. Register the green AMI and add green to `instances`, but **do not apply yet**.
   Verify the plan first — the only change must be creation of
   `aws_instance.nitro["green"]`.
3. Request the migration against blue:
   ```sh
   curl -fsS -H 'Content-Type: application/json' \
     --data '{"action":"requested","target_pcr0":"<green PCR0>"}' \
     http://127.0.0.1:8003/request-migration
   ```
   This writes an Object-Locked record to the intent log. It cannot be deleted.
4. Wait for the cooldown. Poll `/v1/enclave-info` until
   `migration.state == "eligible"`.
5. Finalise:
   ```sh
   curl -fsS -H 'Content-Type: application/json' \
     --data '{"new_pcr0":"<green PCR0>"}' \
     http://127.0.0.1:8003/finalise-migration
   ```
   Blue commits green's PCR0 into its own PCR31, creates a KMS key admitting
   both PCR0s, re-encrypts the DEK and every static secret, writes its
   post-PCR31 attestation and the transition receipt, then writes `KMSKeyID`
   last.
6. Confirm `KMSKeyID` changed. That parameter is the commit; if it changed, the
   handoff succeeded.
7. Apply the saved plan to create green, then let it boot. Green verifies the
   predecessor attestation, the PCR31 commitment, the key policy, and the
   transition receipt before adopting the state.
8. Confirm adoption on green's `/v1/enclave-info`: `previous_pcr0` equals blue's
   PCR0, `previous_pcr0_attestation` is non-empty, and
   `migration.source_pcr0` equals green's own PCR0.
9. Cut over by setting `active_slot = "green"` and applying. The only change must
   be `aws_eip_association.instance`, and `elastic_ip` must not change.
10. Soak. Both hosts remain healthy and reachable.
11. Retire blue by removing it from `instances`. The only change must be
    deletion of `aws_instance.nitro["blue"]`.

Each of the three plans should touch exactly one resource. Anything else
indicates drift and should be investigated before applying.

## Verifying an enclave

An enclave is only meaningful if clients verify it. Both the CLI and the library
prove, before returning any response body, that they are talking to an enclave
running the expected measured image.

### CLI

```sh
nix run github:ArkLabsHQ/enclave -- curl <path> \
  --base-url <url> --expected-pcr0 <hex>
```

The Nix derivation is named `enclave-cli`; the installed binary is `enclave`.

| Flag | Default | Purpose |
|---|---|---|
| `--base-url` | required | Enclave base URL. |
| `--expected-pcr0` | required | Expected PCR0, compared case-insensitively. |
| `-X`, `--method` | `GET` | HTTP method. |
| `-d`, `--data` | none | Request body. Sets `Content-Type: application/json`. |
| `-H`, `--header` | none | `Name: value`, repeatable. |
| `--strict-tls` | `false` | Additionally require public CA and hostname validation. |
| `--insecure-skip-cose-verify` | `false` | Skip COSE Sign1 + AWS Nitro root chain verification (QEMU/local test only; prints a warning). PCR0, nonce, TLS pin, key binding, and response signature are still verified. |
| `-v`, `--verbose` | `false` | Print request and verification summary to stderr. |

```sh
# Runtime and migration status.
enclave curl /v1/enclave-info \
  --base-url https://enclave.example.com --expected-pcr0 834837d8...9ba9

# Authenticated POST.
enclave curl /v1/orders -X POST -d '{"amount":1000}' \
  -H "Authorization: Bearer $TOKEN" \
  --base-url https://enclave.example.com --expected-pcr0 834837d8...9ba9
```

The CLI exits non-zero if the response signature is missing or invalid, and if
the HTTP status is 400 or above.

### Go client

```go
import "github.com/ArkLabsHQ/enclave/client"
```

```go
c, err := client.New("https://enclave.example.com", client.Options{
    ExpectedPCR0: "834837d8fdff29f35317acc40ba4e1e505b71a3cf7374ebba016a38e05c43784a01f0c1e88bf2b6174e4dbfc6f679ba9",
})
if err != nil {
    log.Fatal(err)
}

resp, err := c.Post(ctx, "/v1/orders", strings.NewReader(`{"amount":1000}`))
if err != nil {
    log.Fatal(err)
}

// Do, Get, and Post report signature failure through this field rather than
// returning an error. Callers must check it.
if !resp.SignatureVerified {
    log.Fatal("enclave response signature missing or invalid")
}
if resp.StatusCode >= 400 {
    log.Fatalf("HTTP %d: %s", resp.StatusCode, resp.Body)
}
```

Methods: `Get`, `Post`, `Do`, `VerifyAttestation`, `GRPCConn`. Package
functions: `New`, `NewFromManifest`, `PinnedHTTPClient`, `ManifestURL`,
`FetchManifest`, `VerifyManifestProvenance`.

| Option | Default | Effect |
|---|---|---|
| `ExpectedPCR0` | required | `New` fails without it. |
| `ExpectedPCRs` | empty | Expected values for PCR16 onward, in order, matching `ENCLAVE_SECRETS_CONFIG`. |
| `CacheTTL` | `60s` | Attestation cache lifetime. |
| `StrictTLS` | `false` | Adds public CA and hostname validation on top of the attestation pin. |
| `SkipKeyBinding` | `false` | Skips signing-key binding, and therefore response signature verification. |
| `InsecureSkipCOSEVerify` | `false` | Skips COSE signature and certificate chain verification. For local testing against emulated NSM only. |
| `InsecureTLS` | unset | Removes the certificate pin entirely. |
| `VerifyProvenance` | `false` | For `NewFromManifest`, checks that a GitHub attestation is registered for the manifest digest. |

What is verified on the first request, and cached for `CacheTTL`:

| Check | Default | Relaxed by |
|---|---|---|
| Fresh 20-byte nonce echoed in the attestation document | always | nothing |
| COSE Sign1 signature and AWS Nitro root certificate chain | on | `InsecureSkipCOSEVerify` |
| PCR0 equals `ExpectedPCR0` | always | nothing |
| TLS leaf certificate SHA-256 matches the value in the attestation `user_data` | on | `InsecureTLS` |
| Public CA and hostname validation | off | enabled by `StrictTLS` |
| PCR16 onward match `ExpectedPCRs` | off | populated by `ExpectedPCRs` |
| Attestation public key hashes to the `user_data` signing key hash | on | `SkipKeyBinding` |
| Per-response Schnorr signature over the body | on | `SkipKeyBinding` |

The certificate pin is installed from the attestation document before any
request carrying data is made, so a request issued before verification completes
fails closed.

`GRPCConn` pins the leaf certificate but does not perform public CA validation
and carries no per-response signature, because gRPC bypasses the response
signing middleware. Applications serving gRPC must set
`ENCLAVE_NITRIDING_UPSTREAM=h2c`.

## Testing

```sh
nix flake check
```

| Check | Purpose |
|---|---|
| `eif-build` | Builds two EIFs, validates PCR0 shape, and proves the measurements differ. |
| `ami-build` | Builds the production host system closure. |
| `tofu-validate` | Resolves the pinned AWS provider offline and runs `tofu validate` against the generated stack. |
| `qemu-ami-boot` | Boots an EIF under the QEMU host and proves NSM and PTP clock sync work. |
| `e2e` | The complete lifecycle: AMI registration, OpenTofu blue/green, runtime genesis, clock-skew recovery, migration handshake, EIP cutover, and retirement. |

Unit tests are not flake checks. Run them with `make test`, or
`nix develop --command make test` as CI does. `make lint` and `make fmt` are also
available.

### Requirements

`qemu-ami-boot` and `e2e` are `x86_64-linux` only, because QEMU's
`nitro-enclave` machine type is x86_64 only. The remaining checks run on
`aarch64-linux` as well.

Both QEMU checks need a builder with:

- `/dev/kvm`
- nested virtualisation enabled
- Nix system features `kvm` and `nixos-test`

Nested KVM is not optional. The runtime requires `/dev/ptp0` inside the enclave,
which the guest kernel provides through `ptp_kvm`, which in turn issues the
`KVM_HC_CLOCK_PAIRING` hypercall. The intermediate VM's KVM only services that
hypercall while its own clocksource is TSC-based, so the QEMU host module forces
`clocksource=tsc` with `lib.mkAfter` — NixOS test instrumentation otherwise
appends `clocksource=acpi_pm`, and the kernel honours the last value on the
command line. Without this the enclave has no `/dev/ptp0` and the boot fails
before networking starts.

After the cache is warm the full e2e test takes roughly four minutes.

### Reading test output

`--print-build-logs` includes every test VM's kernel and systemd serial output.
Filter it to keep evaluation progress, test driver actions, failures, and the
result:

```sh
set -o pipefail
nix flake check --print-build-logs 2>&1 |
  rg --line-buffered \
    '(^evaluating |^checking |^error:|> (machine|aws|blue|green):|> !!!|> cleanup|> test script|all checks passed)'
```

`pipefail` preserves the exit status through the filter.

### What the e2e test approximates

The QEMU host differs from the production AMI in exactly these respects.
Everything else — networking, IMDS, migration proxy, enclave startup, and the
watchdog — is the same code.

| Concern | Production | QEMU test host |
|---|---|---|
| Enclave launcher | `nitro-cli run-enclave` | `qemu-system-x86_64 -M nitro-enclave` |
| Vsock backend | Nitro hardware | `vhost-device-vsock` |
| Allocator | Nitro allocator service | not present |
| Boot heartbeat | handled by Nitro tooling | `socat` responder on vsock:9000 |
| Host-to-enclave CID | enclave CID, default 16 | host loopback CID 1 |
| Host clock | EC2 host clock | forced invariant TSC |

AWS is emulated by MiniStack, with a local proxy that implements the Nitro KMS
`Recipient` flow that MiniStack lacks. MiniStack is patched in two places: to
add `RegisterImage`, and to round-trip the EC2 and EIP fields the plan
assertions depend on. Upgrading MiniStack without carrying those patches forward
causes the second plan to report spurious changes to blue.

The test EIF sets `ENCLAVE_DEPLOYMENT=dev`, because QEMU's emulated NSM produces
no AWS certificate chain, and `ENCLAVE_CLOCK_POLL_INTERVAL=2s`, so clock-skew
recovery completes within the test rather than after five minutes. Neither
changes the logic being tested.

### Troubleshooting

**The enclave does not start.** Check the host services and the enclave console:

```sh
systemctl status gvproxy imds-proxy migration-proxy enclave-start enclave-watchdog
tail -n 200 /var/log/enclave-console.log
```

**`starting clock sync failed: open /dev/ptp0`.** Nested KVM, invariant TSC
exposure, or the clocksource. Confirm the guest's kernel command line ends with
`clocksource=tsc`.

**The runtime cannot obtain credentials.** Confirm IMDS is reachable from the
host and that `imds-proxy` is running:

```sh
curl -fsS http://169.254.169.254/latest/meta-data/
systemctl status imds-proxy
```

**`/health` is ready but application routes fail.** `/health` only proves the
application process started. Check an application endpoint directly and read the
enclave console for application errors.

**A plan wants to change the inactive slot.** Do not apply. Inspect
`tofunix show -json <plan>`. Adding green should create
`aws_instance.nitro["green"]` and nothing else.

**`/request-migration` returns an empty reply under QEMU.** `vhost-device-vsock`
0.3 occasionally drops a forwarded host-to-guest connection before it reaches
the enclave. Retry. This affects the emulated transport only; production uses
Nitro AF_VSOCK. A genuine validation failure returns an HTTP status and body and
should not be retried.

## Security notes

**`ENCLAVE_DEPLOYMENT` defaults to `dev`, and `dev` disables COSE signature
verification.** In that mode the runtime decodes attestation documents but does
not verify their signature or validate the certificate chain against the AWS
Nitro root. It logs `INSECURE: skipping COSE signature verification of
attestation document` at startup. PCR comparison and `user_data` checks still
apply. Always set `ENCLAVE_DEPLOYMENT` explicitly for anything other than local
testing. The value is baked into the measurement and cannot be overridden from
SSM.

**Clients must pin PCR0.** `client.New` refuses to construct a client without
`ExpectedPCR0`. Without the pin, attestation proves only that some enclave is
running, not that it is running your code.

**Callers must check `Response.SignatureVerified`.** `Get`, `Post`, and `Do`
return successfully when the response signature is absent or invalid, and report
it through that field. The CLI treats it as a fatal error; library consumers
should do the same.

**Never manage `KMSKeyID` with OpenTofu.** Its absence selects the genesis path,
and the runtime rewrites it as the final step of every state transition. A
declaratively managed value would fight the runtime and could roll a live
deployment back to a key that no longer decrypts anything.

**The instance role cannot read enclave state.** It grants `kms:CreateKey` but
not `Decrypt`, `Encrypt`, or `GenerateDataKey`. Those are authorised by the
enclave-created key policy, which is conditioned on PCR0. Compromising the EC2
host does not yield the state.

**Static secrets are measured.** Each is committed to a PCR that is then locked,
so a successor enclave cannot silently substitute a different value; migration
carries the ciphertexts forward under a key admitting both measurements.
