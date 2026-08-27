# enclave

A Nix toolchain and Go runtime for running an application inside an AWS Nitro
Enclave. The runtime establishes encrypted state under a KMS key whose policy is
conditioned on the enclave's PCR0 measurement, exposes an attested HTTPS
endpoint, and implements a blue/green migration protocol that transfers that
state to a successor enclave with a different measurement.

The repository exports `lib.buildEif` for constructing enclave images, packages
the runtime and client CLI, provides a  development shell, and includes NixOS tests
that exercise the runtime against an AWS emulator under nested KVM.

The runtime, enclave images, and checks support `x86_64-linux`. The CLI and
development shell additionally support `aarch64-linux` and `aarch64-darwin`.

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
| `nix/` | `buildEif` function |
| `nix/tests/` | EIF construction and full blue/green runtime checks. |

## Quickstart

Add the flake as an input and build an enclave image from your application
derivation.

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
          ENCLAVE_MIGRATION_INTENT_RETENTION = "87600h";
        };
      };
    in
    {
      packages.${system} = {
        inherit eif;
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

Provide the resulting EIF to a Nitro-capable host that satisfies the
[deployment requirements](#deployment). Once it is running, verify it from a
client:

```sh
nix run github:ArkLabsHQ/enclave -- curl /v1/enclave-info \
  --base-url https://enclave.example.com \
  --expected-pcr0 "$(jq -r .PCR0 result/pcr.json)"
```

## Architecture

`buildEif` combines the packaged runtime, the application executable, and the
baked environment into one measured EIF.

```text
┌─ Enclave image, EIF ──────────────────────────────────────┐
│  /app/runtime   PID 1: clock, network, AWS, state, TLS    │
│  /app/<name>    application, exec'd by the runtime        │
│                 listens on 127.0.0.1:7074                 │
└───────────────────────────────────────────────────────────┘
          │ AWS APIs through host networking and IMDS
          │ HTTPS application and attestation endpoint
          ▼
   encrypted AWS state                 verified clients
```

The host launcher and infrastructure are external to this flake. Their required
interfaces are documented under [Deployment](#deployment).

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

The migration control API has no application-level authentication. The host must
expose vsock port 8003 only through a restricted operator control plane.

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
  managed by deployment tooling.
- Genesis is recorded in the Object-Locked migration intent log immediately
  before that commit, so the fact that a deployment exists outlives any SSM
  parameter.

### Boot paths

Whether a deployment already exists is decided by the Object-Locked migration
intent log, not by SSM. Genesis writes a `genesis` record immediately before
committing `KMSKeyID`, and it cannot be deleted for the length of the Object Lock
retention, so "this deployment has been created" is a fact no host can retract.
`KMSKeyID` is still the atomic commit point; it is no longer the thing that
decides the boot path.

| Condition | Path | Behaviour |
|---|---|---|
| intent log empty | genesis | Requires `ENCLAVE_PREVIOUS_PCR0=genesis`, no predecessor artifacts, and no committed `KMSKeyID`. Creates the key, generates the DEK and secrets, writes a state-origin receipt, records genesis in the log, then commits `KMSKeyID`. |
| `KMSKeyID` present and a state-origin receipt exists for this PCR0 | resume | Verifies its own receipt, decrypts state, writes nothing. |
| `KMSKeyID` present, no receipt for this PCR0, but a migration transition receipt and predecessor artifacts exist | adopt | Verifies the predecessor's attestation, the PCR31 commitment to its own PCR0, the KMS key policy, and the transition receipt before decrypting. Then writes its own state-origin receipt. |
| genesis recorded, `KMSKeyID` absent | fatal | Either the parameter was deleted or a genesis died between its record and the commit. The two are indistinguishable, so both fail closed: restore the parameter rather than re-creating the deployment. |
| log empty, `KMSKeyID` present | fatal | The intent log was wiped or the bucket repointed. |

Boot order is fixed and every step is fatal: clock synchronisation against
`/dev/ptp0`, networking, AWS clients, telemetry, HTTP servers, state
establishment, PCR extension, migration control server, TLS, SSM environment
overlay, static secret export, then exec of the application.

## Nix API

The flake exports one function under `lib`.

### `lib.buildEif`

Builds a measured enclave image.

Arguments:

```nix
{
  pkgs,                  # x86_64-linux package set
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
  `buildEif` does not currently validate runtime configuration; missing or invalid
  required values fail when the EIF boots.
- The rootfs contains the system CA store and nothing else by default. The
  runtime never shells out. Applications that need `/bin/sh` or other utilities
  must request them: `extraPackages = [ pkgs.busybox ]`.

### Packages

The flake also exposes these packages:

| Package | Systems | Purpose |
|---|---|---|
| `runtime` | `x86_64-linux` | The runtime executable embedded by `buildEif`. |
| `cli`, `default` | Linux and Darwin | The `enclave` client CLI. |

For example, `nix run github:ArkLabsHQ/enclave` runs the client CLI, and
`nix build github:ArkLabsHQ/enclave#runtime` builds the standalone runtime.

### Development shell

`nix develop` provides Go, `gopls`, formatting tools, and `golangci-lint` for
working on this repository.

## Runtime configuration

Configuration is supplied through the EIF environment, which is part of the
measurement. A subset can be overridden at runtime from SSM.

### Identity and security

| Variable | Default | Purpose |
|---|---|---|
| `ENCLAVE_DEPLOYMENT` | none | Required. First SSM path segment. |
| `ENCLAVE_APP_NAME` | none | Required. Second SSM path segment. |
| `ENCLAVE_DEV` | `false` | When `true`, disables COSE signature and certificate chain verification of attestation documents and shortens the clock-sync poll interval from five minutes to five seconds. For local testing against emulated NSM only. See [Security notes](#security-notes). |
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
| `ENCLAVE_MIGRATION_INTENT_RETENTION` | none | Required. Positive Go duration for the S3 Object Lock retention applied to each migration intent record. |

### Clock

| Variable | Default | Purpose |
|---|---|---|
| `ENCLAVE_VERIFY_CLOCK_SOURCE` | `false` | When `true`, fails the boot unless the system clock source is `kvm-clock`. |

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

Nine names are refused, because they define the enclave's identity or security
posture and can only be changed by rebuilding: `ENCLAVE_DEPLOYMENT`,
`ENCLAVE_APP_NAME`, `ENCLAVE_KMS_KEY_LOCKED`,
`ENCLAVE_MIGRATION_COOLDOWN`, `ENCLAVE_MIGRATION_INTENT_RETENTION`,
`ENCLAVE_SECRETS_CONFIG`, `ENCLAVE_PREVIOUS_PCR0`, `ENCLAVE_DEV`,
`ENCLAVE_VERIFY_CLOCK_SOURCE`.

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
| `/D/A/TLSCacheBucketName` | operator | ACME certificate cache bucket. |
| `/D/A/env/<NAME>` | operator | Environment overlay. |
| `/D/A/L/KMSKeyID` | runtime | Atomic commit point. Never manage this with deployment tooling. |
| `/D/A/L/StorageDEK/Ciphertext/<keyID>` | runtime | Encrypted storage DEK. |
| `/D/A/L/<secret>/Ciphertext/<keyID>` | runtime | Encrypted static secret. |
| `/D/A/StateOriginReceipt/<keyID>/<pcr0>` | runtime | Attested proof of which enclave established this state. |
| `/D/A/MigrationStateOriginReceipt/<keyID>` | runtime | Predecessor's attestation over the successor's state. |
| `/D/A/MigrationPreviousPCR0` | runtime | Predecessor PCR0. |
| `/D/A/MigrationPreviousPCR0Attestation` | runtime | Predecessor attestation after PCR31 commitment. |

## HTTP API

### External listener, TCP :443

TLS 1.2 minimum. HTTP and gRPC clients authenticate the enclave by verifying its
PCRs and pinning the live TLS leaf to the hash in the attestation document.
`/v1/*` responses also carry permissive CORS headers.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/enclave/attestation?nonce=<40 hex>` | none | NSM attestation document, base64. The nonce is mandatory and echoed back. `user_data` is exactly 39 bytes: ASCII `sha256:` followed by the raw 32-byte SHA-256 of the TLS leaf DER. |
| GET | `/enclave` | none | Human-readable index. |
| GET | `/enclave/config` | none | Effective runtime configuration as JSON. |
| GET | `/v1/enclave-info` | none | Version, PCR0, predecessor PCR0 and attestation, migration status, application status. |
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

The host must provide trusted operators with controlled access to this vsock
listener. It has no application-level authentication and must not be exposed to
untrusted networks.

| Method | Path | Body | Purpose |
|---|---|---|---|
| POST | `/request-migration` | `{"action":"requested"\|"aborted","target_pcr0":"<96 hex>"}` | Records an attested, Object-Locked intent in S3. Returns migration status. |
| POST | `/finalise-migration` | `{"new_pcr0":"<96 hex>"}` | Performs the handoff and flips `KMSKeyID`. |

Status codes: `425` while the cooldown is active, `409` if no matching intent
exists or it was aborted, `503` if the intent store is unavailable, `400` for a
malformed body.

## Deployment

This flake builds the EIF but does not provision or configure its host or AWS
resources. Any deployment system may be used if it supplies the following
interfaces.

### Host requirements

- Launch the EIF with AWS Nitro Enclaves and allocate sufficient CPU and memory.
- Make `/dev/nsm` and `/dev/ptp0` available inside the enclave.
- Run gvproxy at host CID 3, vsock port 1024, with outbound connectivity to the
  configured AWS endpoints and any application dependencies.
- Forward IMDS from host CID 3, vsock port 8002, to the host's instance metadata
  service so the runtime can obtain AWS credentials.
- Answer the EIF boot heartbeat at host CID 3, vsock port 9000.
- Expose the enclave's migration control listener on vsock port 8003 only to
  trusted operators.
- Route intended client traffic to the enclave's TLS listener, TCP port 443 by
  default.

### AWS requirements

Create a private S3 bucket for the ACME cache and write its name to
`/<deployment>/<app>/TLSCacheBucketName`.

The migration intent bucket is **not** configured. Its name is derived, so no
parameter a host can rewrite decides where the genesis record is looked for:

```text
enclave-<account-id>-<sha256(deployment \x00 app)[:8]>-migration-intents
```

Provisioning must create exactly that bucket, with versioning and Object Lock
enabled at creation, before the enclave first boots; the runtime only reads and
writes it. The digest keeps the name inside S3's 63-character limit and its
character rules whatever the deployment and application are called, and the
account ID keeps two AWS accounts off the same globally unique name. One bucket
per deployment/application falls out of the derivation, so no application's
genesis record can veto another's.

AWS credentials delivered through IMDS must allow:

| Statement | Permissions |
|---|---|
| `S3TLSCacheReadWrite` | `GetObject`, `PutObject`, `DeleteObject`, `ListBucket`, `GetBucketLocation` on the TLS cache bucket. |
| `S3MigrationIntentLogObjectLock` | `PutObject`, `GetObject`, `GetObjectVersion`, `PutObjectRetention`, `ListBucket`, `ListBucketVersions`, `GetBucketLocation` on the derived intent log bucket. Grant no `s3:CreateBucket`: the runtime must never create it, or a boot that cannot find the deployment could manufacture an empty one. |
| `SSMParams` | `GetParameter`, `GetParametersByPath`, `PutParameter` on `/<deployment>/<app>/*`. |
| `KMSAccess` | `CreateKey`, `TagResource`. |
| `STSAccess` | `GetCallerIdentity`. |
| `CloudWatchLogsAccess` | When CloudWatch logging is enabled: `CreateLogGroup`, `CreateLogStream`, `PutLogEvents`, `PutRetentionPolicy`, `FilterLogEvents`, `DescribeLogStreams` on `/enclave/*`. |

`Encrypt`, `Decrypt`, and `GenerateDataKey` are deliberately absent. Those
operations are authorised by the enclave-created key's own PCR0-conditioned
policy, not by the host credentials, so possessing those credentials is not
sufficient to read enclave state.

`/<deployment>/<app>/<locked|unlocked>/KMSKeyID` is owned exclusively by the
runtime. Do not pre-create or declaratively manage it: absence selects genesis,
and the runtime writes it last to commit genesis and migration transitions.

## Blue/green migration

Migration transfers state from a running enclave to a successor with a different
PCR0. The successor must not boot before the predecessor has finalised: it would
find `KMSKeyID` pointing at a key whose policy does not admit it, and fail.

The order is:

1. Build the successor EIF and read its PCR0. Its
   `ENCLAVE_PREVIOUS_PCR0` must be set to the predecessor's PCR0, so the
   predecessor measurement is an input to the successor build.
2. Prepare the successor host and routing, but do not boot the successor.
3. Request the migration against the predecessor:
   ```sh
     curl -fsS -H 'Content-Type: application/json' \
       --data '{"action":"requested","target_pcr0":"<successor PCR0>"}' \
     http://<migration-control-endpoint>/request-migration
   ```
   This writes an Object-Locked record to the intent log. It cannot be deleted.
4. Wait for the cooldown. Poll `/v1/enclave-info` until
   `migration.state == "eligible"`.
5. Finalise:
   ```sh
     curl -fsS -H 'Content-Type: application/json' \
       --data '{"new_pcr0":"<successor PCR0>"}' \
     http://<migration-control-endpoint>/finalise-migration
   ```
   The predecessor commits the successor's PCR0 into its own PCR31, creates a
   KMS key admitting both PCR0s, re-encrypts the DEK and every static secret,
   writes its post-PCR31 attestation and the transition receipt, then writes
   `KMSKeyID` last.
6. Confirm `KMSKeyID` changed. That parameter is the commit; if it changed, the
   handoff succeeded.
7. Boot the successor. It verifies the predecessor attestation, the PCR31
   commitment, the key policy, and the transition receipt before adopting the
   state.
8. Confirm adoption on the successor's `/v1/enclave-info`:
   `previous_pcr0` equals the predecessor PCR0,
   `previous_pcr0_attestation` is non-empty, and `migration.source_pcr0` equals
   the successor's own PCR0.
9. Shift client traffic using the deployment system's normal routing mechanism.
10. Keep both enclaves healthy for the soak period, then retire the predecessor.

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
| `--insecure-skip-cose-verify` | `false` | Skip COSE Sign1 + AWS Nitro root chain verification (QEMU/local test only; prints a warning). PCR0, nonce, the exact 39-byte TLS binding, and live certificate pinning are still checked. |
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

The CLI exits non-zero if attestation or TLS pinning fails, and if the HTTP
status is 400 or above.

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

if resp.StatusCode >= 400 {
    log.Fatalf("HTTP %d: %s", resp.StatusCode, resp.Body)
}
```

Methods: `Get`, `Post`, `Do`, `VerifyAttestation`, `GRPCConn`. Package
functions: `New`, `NewFromManifest`, `PinnedHTTPClient`, `ManifestURL`,
`FetchManifest`.

| Option | Default | Effect |
|---|---|---|
| `ExpectedPCR0` | required | `New` fails without it. |
| `ExpectedPCRs` | empty | Expected values for PCR16 onward, in order, matching `ENCLAVE_SECRETS_CONFIG`. |
| `CacheTTL` | `60s` | Attestation cache lifetime. |
| `StrictTLS` | `false` | Adds public CA and hostname validation on top of the attestation pin. |
| `InsecureSkipCOSEVerify` | `false` | Skips COSE signature and certificate chain verification. For local testing against emulated NSM only. |
| `InsecureTLS` | unset | Removes the certificate pin entirely. |

What is verified on the first request, and cached for `CacheTTL`:

| Check | Default | Relaxed by |
|---|---|---|
| Fresh 20-byte nonce echoed in the attestation document | always | nothing |
| COSE Sign1 signature and AWS Nitro root certificate chain | on | `InsecureSkipCOSEVerify` |
| PCR0 equals `ExpectedPCR0` | always | nothing |
| `user_data` is exactly `sha256:` plus the raw 32-byte TLS leaf SHA-256, and the live certificate matches it | on | `InsecureTLS` |
| Public CA and hostname validation | off | enabled by `StrictTLS` |
| PCR16 onward match `ExpectedPCRs` | off | populated by `ExpectedPCRs` |

The certificate pin is installed from the attestation document before any
request carrying data is made, so a request issued before verification completes
fails closed.

`GRPCConn` uses the same PCR verification and attested TLS pinning model as HTTP,
but does not perform public CA validation. Applications serving gRPC must set
`ENCLAVE_NITRIDING_UPSTREAM=h2c`.

## Testing

```sh
nix flake check
```

| Check | Purpose |
|---|---|
| `eif-build` | Builds predecessor and successor EIFs, validates PCR0 shape, and proves the measurements differ. |
| `e2e` | x86-only runtime lifecycle across ordinary `aws`, `blue`, and `green` NixOS nodes: direct AWS setup, genesis, clock recovery, attestation, ACME, migration, adoption, and restart recovery. |

Unit tests are not flake checks. Run them with `make test`, or
`nix develop --command make test` as CI does. `make lint` and `make fmt` are also
available.

### Requirements

Both checks run on `x86_64-linux` only. The `e2e` check uses QEMU's
x86_64-only `nitro-enclave` machine type.

The e2e check needs a builder with:

- `/dev/kvm`
- nested virtualisation enabled
- Nix system features `kvm` and `nixos-test`

Nested KVM is not optional. The runtime requires `/dev/ptp0` inside the enclave,
which the guest kernel provides through `ptp_kvm`, which in turn issues the
`KVM_HC_CLOCK_PAIRING` hypercall. The intermediate VM's KVM only services that
hypercall while its own clocksource is TSC-based. The blue and green test nodes
therefore force `clocksource=tsc`; NixOS test instrumentation otherwise appends
`clocksource=acpi_pm`, and the kernel honours the last value on the command line.
Without this the enclave has no `/dev/ptp0` and boot fails before networking.

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

### E2E boundaries

The e2e test uses three ordinary NixOS test nodes. `aws` runs the AWS emulator,
the attestation-aware KMS `Recipient` proxy, IMDS, and ACME fixtures. `blue` and
`green` launch measured EIFs with QEMU's `nitro-enclave` machine and
`vhost-device-vsock`.

The test driver creates the required buckets and SSM parameters directly through
AWS APIs, then controls node startup according to the runtime migration order.
It does not simulate a deployment system, host image lifecycle, or traffic
cutover.

The test EIF uses `ENCLAVE_DEPLOYMENT=dev` as its SSM namespace. It separately
sets `ENCLAVE_DEV=true` because QEMU's emulated NSM produces no AWS certificate
chain. This skips COSE signature and certificate chain verification and shortens
the clock-sync poll interval from five minutes to five seconds; it is only for
local testing against the emulator.

### Troubleshooting

**The enclave does not start.** Inspect the QEMU launcher and enclave console on
the affected blue or green node.

**`starting clock sync failed: open /dev/ptp0`.** Nested KVM, invariant TSC
exposure, or the clocksource. Confirm the guest's kernel command line ends with
`clocksource=tsc`.

**The runtime cannot obtain credentials.** Confirm the test IMDS endpoint and
the host's vsock port 8002 forward are reachable.

```sh
curl -fsS http://169.254.169.254/latest/meta-data/
```

**`/health` is ready but application routes fail.** `/health` only proves the
application process started. Check an application endpoint directly and read the
enclave console for application errors.

**`/request-migration` returns an empty reply under QEMU.** `vhost-device-vsock`
0.3 occasionally drops a forwarded host-to-guest connection before it reaches
the enclave. Retry. This affects the emulated transport only; production uses
Nitro AF_VSOCK. A genuine validation failure returns an HTTP status and body and
should not be retried.

## Security notes

**`ENCLAVE_DEV=true` disables COSE signature verification.** In that mode the
runtime decodes attestation documents but does not verify their signature or
validate the certificate chain against the AWS Nitro root. It logs `INSECURE:
skipping COSE signature verification of attestation document` at startup. PCR
comparison and `user_data` checks still apply. Only set `ENCLAVE_DEV=true` for
local testing against emulated NSM. `ENCLAVE_DEPLOYMENT` is required but only
selects the SSM namespace; values such as `dev` and `prod` do not control
verification. Both settings are baked into the measurement and cannot be
overridden from SSM.

**Clients must pin PCR0.** `client.New` refuses to construct a client without
`ExpectedPCR0`. Without the pin, attestation proves only that some enclave is
running, not that it is running your code.

**HTTP and gRPC trust the attested TLS channel.** The client verifies the Nitro
attestation and PCRs before sending application requests, then pins the live TLS
leaf to the exact hash carried in `user_data`.

**Never manage `KMSKeyID` with deployment tooling.** The runtime rewrites it as
the final step of every state transition. A declaratively managed value would
fight the runtime and could roll a live deployment back to a key that no longer
decrypts anything. Deleting it no longer causes a state fork — the intent log
records that the deployment exists, so the boot fails instead of creating a
second generation — but it still stops the deployment booting until it is
restored.

**Genesis is vetoed by presence, never authorised by it.** The deployment-wide
scan looks for a `genesis` record and is deliberately unverified: a forged record
can only stop a genesis — visible in the bucket, and recoverable — while treating
an unverifiable one as absent would fail open and re-create a deployment that
already exists. Permission to create a deployment comes from
*absence*, which Object Lock Compliance retention makes impossible to
manufacture. The scan reads the version listing rather than the current view,
because Object Lock stops a version being erased but does not stop a delete
marker hiding it.

**The intent bucket is on the boot path.** An unreachable or unwritable bucket
now fails the boot rather than only blocking migration. That is the intended
trade: an enclave that cannot check whether the deployment exists must not guess.

**Seed the log before adopting this on any existing deployment.** No runtime
before this change wrote a `genesis` record, so *every* deployment created
earlier lacks one — migrated or not. Create the derived bucket and write a
`genesis` record for the running PCR0 into it before upgrading. Without the
bucket the boot fails reading the log; with an empty one it reaches the genesis
path, finds its committed `KMSKeyID`, and fails there.

Existing intent records cannot be carried across. Each record's `bucket_name` is
part of its attested pre-image, so one copied into the derived bucket no longer
verifies and is skipped without an error — migration history restarts. The seeded
record is unverifiable for the same reason, since only an enclave of that PCR0
could sign one. That is enough for the genesis check, which is unverified by
design, but the record never appears as a migration head, so the first real
handoff is written at sequence 1 beside it.

**Host credentials cannot read enclave state.** They grant `kms:CreateKey` but
not `Decrypt`, `Encrypt`, or `GenerateDataKey`. Those are authorised by the
enclave-created key policy, which is conditioned on PCR0. Compromising the host
does not yield the state.

**Static secrets are measured.** Each is committed to a PCR that is then locked,
so a successor enclave cannot silently substitute a different value; migration
carries the ciphertexts forward under a key admitting both measurements.
