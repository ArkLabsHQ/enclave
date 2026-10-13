# enclave

A Nix toolchain and Go runtime for running an application inside an AWS Nitro
Enclave. The runtime establishes encrypted state under a KMS key whose policy is
conditioned on the enclave's PCR0 measurement, exposes an attested HTTPS
endpoint, and implements a blue/green migration protocol that transfers that
state to a successor enclave with a different measurement.

The repository exports `lib.buildEif` for constructing enclave images, packages
the runtime and client CLI, provides a development shell, and includes NixOS tests
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
| `.github/workflows/` | `eif-build.yml` and `eif-publish.yml`, reusable workflows an app repo calls to build and publish its EIF. |

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
          ENCLAVE_NAMESPACE = "prod";
          ENCLAVE_APP_NAME = "myapp";
          ENCLAVE_AWS_REGION = "eu-west-1";
          ENCLAVE_PREVIOUS_PCR0 = "genesis";
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
nix run github:ArkLabsHQ/enclave -- curl /enclave/v1/info \
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
| TCP :443 | public to enclave | TLS, runtime API, application proxy |
| TCP 127.0.0.1:8080 | inside enclave | internal runtime API |
| TCP 127.0.0.1:7074 | inside enclave | the application |

Migration has no control endpoint. It runs over SSM between the enclaves
themselves, so there is no inbound surface to authenticate or restrict.

### State model

The runtime keeps no state on disk. Each generation publishes one attested,
compliance-locked S3 snapshot containing its KMS-encrypted master seed and TLS
key. SSM holds configuration, inherited secrets and migration handoffs.

- Each generation's KMS key admits only its PCR0. `Decrypt` and `GenerateDataKey`
  require attestation, even for callers with the instance role.
- Genesis creates a 32-byte master seed and an independent P-256 TLS key.
  Application secrets, the storage DEK and the ACME account key derive from the
  seed. Static secret *i* extends PCR(16+i), which is then locked.
- Migration preserves the seed and TLS key, re-encrypting them for the
  successor. The predecessor keeps its own snapshot and key and can continue
  serving or restart independently.

### Boot paths

An enclave starts as **candidate**, serving `/enclave/v1/info` over an ephemeral
self-signed certificate. Application routes, `/health` and
`/enclave/attestation` return `503`. After establishing state, it moves to
**starting** while configuring PCRs and TLS, then **ready** when the application
starts. Candidates cannot be pinned through attestation.

| Condition | Behaviour |
|---|---|
| Own `snapshot/<pcr0>` verifies | Resume from it without reading generation state from SSM. |
| No snapshot; `ENCLAVE_PREVIOUS_PCR0=genesis` | Acquire the genesis lease, create keys and publish the snapshot. |
| No snapshot; `ENCLAVE_PREVIOUS_PCR0=<predecessor PCR0>` | Wait for the SSM handoff, verify its receipts, key policy and migration intent, then adopt and publish a snapshot. |
| Existing versions cannot be verified, or S3 cannot be read | Fail boot; never treat invalid or unreadable state as absent. |

**Use one independent deployment per namespace and app name.** Update an existing
deployment through [migration](#bluegreen-migration). For a fresh genesis, choose
a new `ENCLAVE_NAMESPACE` or `ENCLAVE_APP_NAME`. Different genesis images in the
same namespace/app create unrelated keys but share certificate storage; with the
same FQDN, the new image cannot decrypt the existing certificate. The runtime
has no deployment-wide guard against this configuration.

Replicas of one image share its snapshot. Concurrent publishers accept the same
state even if their receipt bytes differ; a publisher with different state fails
and can resume the winner's state on restart.

Boot synchronises the clock, starts networking and AWS clients, applies the SSM
overlay, and runs the [permission preflight](#aws-requirements) before establishing
state. A failed preflight leaves `/enclave/v1/info` available with status
`failed` and the missing grants. Other boot failures terminate the runtime.

### Generation state

The derived [state bucket](#aws-requirements) holds two kinds of locked record:

| Key | Writer | Contents |
|---|---|---|
| `snapshot/<pcr0>` | The generation's enclave | Ciphertexts, KMS key ID, deployment and predecessor identities, and attestation receipts. |
| `migration-intent/<sourcePCR0>/<sequence>` | The predecessor | Migration requests and aborts. |

Snapshots use canonical CBOR wrapped in JSON with receipts. The owner's
state-origin receipt authenticates the snapshot root and lineage. A migrated
snapshot also carries the predecessor's transition receipt, binding its PCR0
and PCR31 commitment to the successor. See [snapshot.go](runtime/snapshot.go)
for the schemas and receipt format.

**Discovery** lists object versions because newer versions and delete markers
can hide a locked version. It selects the earliest version whose encoding,
deployment identity, receipts and compliance retention all verify. Multipart
uploads are rejected to prevent backdating. Conflicting states at the earliest
timestamp, unreadable versions, or existing versions with none valid cause boot
to fail.

**Publication** uses `If-None-Match: *` with compliance retention. The writer then
verifies the stored version and requires it to match its snapshot before
serving. This read-back checks the actual lock; IAM preflight cannot check bucket
configuration. Before first adoption succeeds, the successor still needs its
SSM handoff. Keep the predecessor serving until the successor is ready.

**Retention** is ten years in production and five minutes under `ENCLAVE_DEV`.
To keep a generation beyond that period, extend the earliest valid version's
lock before it expires:

```sh
aws s3api put-object-retention --bucket <state bucket> --key snapshot/<pcr0> \
  --version-id <earliest valid version> \
  --retention 'Mode=COMPLIANCE,RetainUntilDate=<new date>'
```

**Recovery** of a published generation needs its snapshot, KMS key and image.
Restarting discovers the snapshot even if SSM handoff parameters were deleted
or changed. Configuration and inherited secrets still come from SSM. Deleting a
generation's own KMS key prevents recovery; deleting a predecessor's key does
not prevent an adopted successor from booting. See
[blue/green migration](#bluegreen-migration) before retiring keys.

If no version verifies, inspect the runtime's validation errors and list the
versions with `aws s3api list-object-versions --bucket <bucket> --prefix snapshot/<pcr0>`.

## Nix API

The flake exports one function under `lib`.

### `lib.buildEif`

Builds a measured enclave image.

Arguments:

```nix
{
  pkgs,                   # x86_64-linux package set
  app,                    # package; executable selected with pkgs.lib.getExe
  env,                    # environment baked into the measurement
  overrideAllowlist ? [ ], # application env vars that SSM may override
  extraPackages ? [ ],     # additional packages in the enclave rootfs
}
```

Produces a derivation containing `image.eif` and `pcr.json`.

- `buildEif` selects the executable with `pkgs.lib.getExe`. Set
  `app.meta.mainProgram` when it differs from the package name. The executable
  is copied under `/app`, and `APP_BINARY_NAME` is injected automatically.
- `env` is part of the measurement. Changing any value changes PCR0.
  `buildEif` does not currently validate runtime configuration; missing or invalid
  required values fail when the EIF boots.
- `overrideAllowlist = [ "VAR_FOO" "VAR_BAR" ];` allows SSM to override those
  application environment variables. It defaults to an empty list and is part of
  the measurement. `buildEif` joins the names with commas and sets
  `ENCLAVE_OVERRIDE_ALLOWLIST`; specifying that variable in `env` is an error.
  The runtime's explicit SSM configuration overrides remain available regardless
  of this list. Runtime configuration names are reserved; use separate names for
  application settings. See [SSM environment overlay](#ssm-environment-overlay).
- The rootfs contains the system CA store and nothing else by default. The
  runtime never shells out. Applications that need `/bin/sh` or other utilities
  must request them: `extraPackages = [ pkgs.busybox ]`.

### Packages

The flake also exposes these packages:

| Package | Systems | Purpose |
|---|---|---|
| `runtime` | `x86_64-linux` | The runtime executable embedded by `buildEif`. |
| `cli`, `default` | Linux and Darwin | The `enclave` client CLI. |
| `eif-blue`, `eif-green` | `x86_64-linux` | Test-app EIFs from `nix/tests/`. Exist so this repo can exercise `eif-build.yml` against a real image. |

For example, `nix run github:ArkLabsHQ/enclave` runs the client CLI, and
`nix build github:ArkLabsHQ/enclave#runtime` builds the standalone runtime.

### CI

`eif-build.yml` and `eif-publish.yml` are reusable workflows. An app repo calls
them instead of writing its own pipeline:

```yaml
jobs:
  build:
    uses: ArkLabsHQ/enclave/.github/workflows/eif-build.yml@<sha>
    with:
      environments: '["dev"]'
      app_name: myapp
```

The calling flake must expose `packages.<system>.eif-<env>` for each environment,
each producing `image.eif` and `pcr.json`. `version_flake_attr` additionally
requires an attribute carrying a `version`, asserted against a `v*` tag.

`eif-publish.yml` must run in the same workflow run as `eif-build.yml`, and the
**caller** must grant `permissions: id-token: write` — a called workflow cannot
elevate it, which matters when the repos are in different organisations.

### Development shell

`nix develop` provides Go, `gopls`, formatting tools, and `golangci-lint` for
working on this repository.

## Runtime configuration

Configuration is supplied through the EIF environment, which is part of the
measurement. A subset can be overridden at runtime from SSM.

### Identity and security

| Variable | Default | Purpose |
|---|---|---|
| `ENCLAVE_NAMESPACE` | none | Required. Leading segments of every SSM path, CloudWatch log group and S3 object key: `prod` yields `/prod/<app>/enclave/...`, `ark/prod` yields `/ark/prod/<app>/enclave/...`. Used exactly as set, never cleaned, and the enclave refuses to boot unless it is one to nine `/`-separated segments of letters, digits and `_.-` (the characters SSM parameter names accept) with no leading, trailing or doubled `/` and no `.` or `..` segment, its first segment does not start with `aws` or `ssm` in any case (SSM reserves those), and `/<namespace>/<app>/enclave` is at most 256 characters. Baked into the EIF, never read from the SSM overlay, which is itself read from under it. |
| `ENCLAVE_APP_NAME` | none | Required. The path segment after the namespace, used exactly as set: one segment of letters, digits and `_.-`, other than `.` or `..`. |
| `ENCLAVE_DEV` | `false` | Selects development retention periods, write timeout, clock-sync interval and unlocked KMS policy, as listed below. Attestation signature verification remains enabled. See [Security notes](#security-notes). |
| `ENCLAVE_INSECURE_VERIFY_SKIPPED` | `false` | Skips COSE signature and certificate chain verification of attestation documents only when `ENCLAVE_DEV=true`. Ignored entirely in production, including malformed values. For QEMU-based tests only. Baked into the EIF, never read from the SSM overlay. |
| `ENCLAVE_VERIFY_CLOCK_SOURCE` | `true` | Requires the system clock source to be `kvm-clock`. Can be enabled or disabled in either production or dev mode. Baked into the EIF, never read from the SSM overlay. |
| `ENCLAVE_PREVIOUS_PCR0` | required | Predecessor PCR0 for migration, or `genesis` for a fresh deployment. Measured and not SSM-overridable; see [Boot paths](#boot-paths). |
| `ENCLAVE_SECRETS_CONFIG` | empty | JSON array of managed static secrets. Schema below. |
| `ENCLAVE_AWS_REGION` | `us-east-1` | Region for all AWS SDK clients. |

`ENCLAVE_DEV=true` lets dev deployments use shorter timings while retaining
attestation signature verification:

| Setting | Production | Dev |
|---|---|---|
| Generation snapshot Object Lock retention | 10 years | 5 minutes |
| Migration intent Object Lock retention | 10 years | 10 minutes |
| Migration intent write timeout | 10 minutes | 2 minutes |
| Clock-sync interval | 5 minutes | 5 seconds |
| KMS key policy / SSM namespace segment | Locked / `locked` | Root recovery principal retained / `unlocked` |

Clock-source verification defaults to enabled and migration cooldown defaults
to 24 hours in both modes. Set `ENCLAVE_VERIFY_CLOCK_SOURCE` and
`ENCLAVE_MIGRATION_COOLDOWN` independently to override them.

### Listeners and application

| Variable | Default | Purpose |
|---|---|---|
| `ENCLAVE_APP_PORT` | `7074` | Port the application listens on. |
| `ENCLAVE_UPSTREAM` | `auto` | Runtime-to-application HTTP version. `h1` pins HTTP/1.1, `h2c` pins HTTP/2 cleartext and is required for gRPC, `auto` matches the inbound request. |
| `ENCLAVE_FQDN` | `localhost` | Hostname for the TLS certificate. |
| `ENCLAVE_VIPROXY_IN_ADDRS` | `127.0.0.1:80` | IMDS forwarder listen address. |
| `ENCLAVE_VIPROXY_OUT_ADDRS` | `3:8002` | IMDS forwarder target, `CID:PORT` or `host:port`. |
| `APP_BINARY_NAME` | `app` | Set by `buildEif` from the selected executable. The runtime execs `/app/<value>`. |

The runtime always starts the in-process IMDS forwarder before loading AWS
credentials. `ENCLAVE_VIPROXY_ENABLED` has been removed; setting it to `false`
has no effect. The listen and target addresses remain configurable through
`ENCLAVE_VIPROXY_IN_ADDRS` and `ENCLAVE_VIPROXY_OUT_ADDRS`.

The external TLS listener (443), the internal loopback listener (8080) and the
host vsock port gvproxy listens on (1024) are fixed. The last of those is
hardcoded on the host side too, so a value only the enclave knew about would
silently break networking.

### Migration

Object Lock retention is fixed by the measured image: ten years in production;
in development, five minutes for snapshots and ten minutes for migration
intents. Governance mode and insufficient retention are rejected. The check
allows two minutes in development and ten in production for upload delay and
clock skew; this write budget has no environment override.

The migration cooldown defaults to 24 hours in both modes. Set
`ENCLAVE_MIGRATION_COOLDOWN` in the image to change the delay between adopting a
candidate's attestation and committing its handoff.

Version reads use `PartNumber=1` and reject any response with `PartsCount`.
Multipart timestamps date from upload initiation, so accepting them could let a
host backdate a replay to bypass the cooldown or replace the earliest snapshot.
A failed read stops the scan.

### Clock

By default, both production and dev mode fail the boot unless the system clock
source is `kvm-clock`. `ENCLAVE_VERIFY_CLOCK_SOURCE=false` skips this assertion
in either mode. The QEMU harness sets it explicitly because it boots without
the required clock source.

The runtime hard-steps the clock onto the PTP hardware clock at startup, then
runs a PI servo that corrects frequency drift every five minutes in production
or every five seconds with `ENCLAVE_DEV=true`. Offsets above 100 ms trigger
another hard-step. `/dev/ptp0` is mandatory even when clock-source verification
is disabled; the boot fails without it.

### Telemetry

| Variable | Default | Purpose |
|---|---|---|
| `ENCLAVE_MIGRATION_COOLDOWN` | `24h` | Overrides the wait between a candidate's attestation being adopted and the handoff committing: the abort window. Can be set in either production or dev mode; unset defaults to 24 hours in both. Must parse as a duration and must not be negative; an explicit `0s` disables the wait. EIF-baked, never read from the SSM overlay. |
| `ENCLAVE_LOG_SHIP_INTERVAL` | `10s` | Export cadence for the runtime's own logs, spans and metrics. The application's cadence is its own exporter's. |
| `ENCLAVE_LOG_RETENTION_DAYS` | `30` | Retention applied to created log groups. |
| `ENCLAVE_TRACES` | `false` | `true` exports spans to X-Ray: the runtime's own and the application's, relayed from `/v1/traces`. Needs Transaction Search and the `XRayAccess` statement. Otherwise the application's uploads and the runtime's own spans are dropped inside the enclave with an empty success response. Takes `true`, `True`, `TRUE`, `t`, `T` or `1`, and the matching `false` forms; anything else, including mixed case such as `tRuE`, fails the boot. Baked into the EIF, never read from the SSM overlay. |
| `ENCLAVE_METRICS` | `false` | `true` exports metrics to CloudWatch: the runtime's own counters, `/proc` readings and forward-duration histograms, and the application's, relayed from `/v1/metrics`. Needs the `CloudWatchMetricsAccess` statement. Otherwise the application's uploads and the runtime's own metrics are dropped inside the enclave with an empty success response, so export failures show only on `stderr`. Takes `true`, `True`, `TRUE`, `t`, `T` or `1`, and the matching `false` forms; anything else, including mixed case such as `tRuE`, fails the boot. Baked into the EIF, never read from the SSM overlay. |

The application posts OTLP/HTTP to the internal listener. The runtime signs
each request with the instance role, forwards its body unchanged, and returns
the AWS response:

| Signal | Endpoint | Signed as | Lands in |
|---|---|---|---|
| logs | `logs.<region>.amazonaws.com/v1/logs` | `logs` | The log groups below, in the stream named for the instance. |
| traces | `xray.<region>.amazonaws.com/v1/traces` | `xray` | X-Ray, in the `aws/spans` log group Transaction Search owns. |
| metrics | `monitoring.<region>.amazonaws.com/v1/metrics` | `monitoring` | The CloudWatch OpenTelemetry metrics store, queried with PromQL. |

Logs are always forwarded. Traces and metrics are forwarded only when
`ENCLAVE_TRACES` or `ENCLAVE_METRICS` is `true`; otherwise their uploads get an
empty success response and are dropped, so the application's exporter carries on.

The relay accepts `application/x-protobuf` and `application/json`, including
`gzip`, and caps encoded request bodies at 1 MiB for logs and metrics and 5 MiB
for traces. AWS applies its decoded size, record count and timestamp limits. The
runtime does not decode or retry uploads; it returns the AWS status,
`Retry-After` and response body to the application exporter.

The runtime exports its own telemetry with the OpenTelemetry SDK and identifies
it with the `service.name=enclave-runtime` resource.

Log groups are named `/<namespace>/<app>/enclave/logs/<source>`, under the same
namespace as the [SSM parameters](#ssm-parameters), where `<namespace>` is
`ENCLAVE_NAMESPACE`:

| Log group | Holds |
|---|---|
| `/<namespace>/<app>/enclave/logs/app` | The application's OTLP log records. |
| `/<namespace>/<app>/enclave/logs/runtime` | The runtime's own records. |

At boot, the runtime creates both groups and one stream per group named after
the EC2 instance ID, applies retention, and writes a probe record to the runtime
group. Failure to read the instance ID from IMDS or write the probe aborts
startup. Restarts on the same instance reuse its streams.

**Changed:** group names used to be `<ENCLAVE_LOG_GROUP_PREFIX>/<deployment>/enclave/...`,
with no `<app>` segment, so two applications in one deployment shared groups unless the
prefix told them apart. `ENCLAVE_LOG_GROUP_PREFIX` and `ENCLAVE_DEPLOYMENT` are gone.
`ENCLAVE_NAMESPACE` replaces both: `ENCLAVE_DEPLOYMENT=prod` becomes
`ENCLAVE_NAMESPACE=prod` with S3 keys and the intent bucket name unchanged, and a former prefix
moves in front, as in `ENCLAVE_NAMESPACE=ark/prod`, which then heads the SSM paths and
S3 keys as well. It is baked rather than settable from the overlay, and with
`ENCLAVE_APP_NAME` names every log group exactly as it names every SSM parameter. Alarms, dashboards and the `CloudWatchLogsAccess`
policy keyed on the old names need updating.

When those signals are on, spans require Transaction Search to be enabled for X-Ray traces in the
CloudWatch account settings, and metrics require `cloudwatch:PutMetricData`. Export failures are counted in
`enclave_telemetry_export_errors_total`, rate limited on `stderr`, and do not
abort startup. Metrics are queried with PromQL by their OTLP attributes.

With `ENCLAVE_METRICS=true`, the runtime's counters ship as cumulative sums: `enclave_http_requests_total`,
`enclave_http_errors_total`, `enclave_app_proxied_requests_total`,
`enclave_app_proxied_errors_total`, `enclave_otlp_<logs|traces|metrics>_forwarded_total`
(uploads accepted with a `2xx`, by AWS or, for a signal that is off, by the enclave
dropping them),
`enclave_otlp_<logs|traces|metrics>_upstream_errors_total` (a transport failure, a
`429` or a `5xx` from AWS) and `enclave_telemetry_export_errors_total`. Go runtime
and `/proc` readings ship as `enclave_runtime_*` gauges and counters.

`enclave_otlp_<logs|traces|metrics>_forward_duration_seconds` is a histogram of
each upload's full exchange with AWS, from sending the request to the end of the
response body, failed ones included, whether relayed for the application or
exported by the runtime. Both leave the enclave over the vsock
proxy, so a slowing egress path shows here as rising latency long before uploads
fail at the 30-second timeout. Buckets run from 5 ms to 30 s.

**Changed:** traces and metrics are opt-in. Set `ENCLAVE_TRACES=true` and
`ENCLAVE_METRICS=true` to keep exporting them; without them only logs leave the
enclave.

**Changed:** trace and metric log groups and the local telemetry decoder were
removed. Logs remain in the two groups above; spans and metrics use their native
AWS stores. Records no longer contain the runtime-added `id`, `level` or
`source` fields. Eight counters were removed, so alarms and dashboards on them
need updating: `enclave_log_entries_total`, `enclave_supervisor_log_entries_total`,
`enclave_app_metrics_dropped_total`, and the queue-overflow counters
`enclave_telemetry_logs_app_dropped_total`,
`enclave_telemetry_logs_supervisor_dropped_total`,
`enclave_telemetry_traces_app_dropped_total`,
`enclave_telemetry_traces_supervisor_dropped_total` and
`enclave_telemetry_metrics_dropped_total`. Application uploads are no longer
queued: the relay is synchronous, so the application's exporter sees each failure
and `Retry-After` itself. The runtime's own records still pass through the
OpenTelemetry SDK's batch queues, whose overflow drops are not counted. The
forward-duration histograms show a congested egress path, not whether anything
was dropped.

`stderr` is unaffected: it still carries every runtime record, unbatched.

### AWS endpoint overrides

`AWS_ENDPOINT_URL_KMS`, `AWS_ENDPOINT_URL_SSM`, `AWS_ENDPOINT_URL_STS`,
`AWS_ENDPOINT_URL_S3`, `AWS_ENDPOINT_URL_LOGS`, `AWS_ENDPOINT_URL_XRAY`,
`AWS_ENDPOINT_URL_MONITORING`, `AWS_ENDPOINT_URL_IAM` and `AWS_ENDPOINT_URL_ROUTE53`
override the corresponding service endpoints.
`AWS_ENDPOINT_URL_LOGS` covers both the CloudWatch Logs API and its OTLP `/v1/logs`
path, since they share an endpoint in production. Setting the S3 endpoint also
forces path-style addressing. These exist for testing against an emulator.

### Static secrets

`ENCLAVE_SECRETS_CONFIG` is a JSON array:

```json
[
  { "name": "signing-key", "env_var": "SIGNING_KEY" }
]
```

| Field | Meaning |
|---|---|
| `name` | Stable derivation name, baked into the image. |
| `env_var` | Environment variable set on the application process, containing 64 lowercase hex characters. |

Each secret derives from the deployment's master seed using HKDF-SHA256 with
salt `enclave.derived-secret.v1` and the name encoded as one deterministic CBOR
text string. The runtime scans successive 32-byte blocks of one 255-block
expansion, choosing the first valid secp256k1 scalar without modular reduction.
It exports exactly 64 lowercase hex characters and commits the public key to
an application PCR. If no block is valid, boot fails.

Changing `env_var` preserves the key; changing `name` rotates it. Removing and
later restoring a name restores the same key. Removing a declaration stops its
export but does not erase the key while the master seed exists. Migration
preserves the seed, so a predecessor need not know its successor's declarations.

The storage DEK uses the first 32 HKDF bytes for `runtime/StorageDEK` directly.
The ACME account signer uses the same rejection sampling with P-256's scalar
order and the name `runtime/ACMEAccountKey`. These names, the salt and the
algorithm are protocol constants; environment variables, PCR0 and KMS IDs do
not enter derivation. Storage-key rotation requires a separate data migration
design; keep `runtime/StorageDEK` unchanged.

Master-seed compromise requires another fresh deployment with a new seed: migration and renaming
cannot restore secrecy, including for names introduced by future releases. Renaming can replace
a compromised derived key while the seed remains private, but it neither revokes
the old key nor removes it from previous releases. The release must handle any
dependent state, including account registration if the ACME derivation name changes.

The runtime keeps the seed and internal private keys out of the child's environment.
This assumes a trusted child; it does not isolate runtime memory from malicious
application code.

Constraints:

- `name` must be unique and contain only ASCII letters, digits and `_.-`.
  Application names cannot contain `/`; the entire `runtime/` namespace is
  reserved for current and future internal keys. Bare `StorageDEK` is allowed.
- `env_var` must be a valid environment identifier, unique across static and
  inherited secrets, and must not use a runtime-reserved child variable.
- Order is significant. Secret *i* is committed to PCR(16+i). PCR31 is reserved
  for migration, so at most 15 secrets are supported.
- Changing the array changes the measurement, and therefore PCR0.

### Inherited secrets

A static secret is born inside the enclave. An inherited secret already exists
in the outside world — a legacy signing key, say — and is handed to the
application for a limited time. `ENCLAVE_INHERIT_SECRETS_CONFIG` is a JSON array:

```json
[
  {
    "name": "legacy-signer",
    "env_var": "LEGACY_SIGNING_KEY",
    "type": "publicKey",
    "value": ["02…"],
    "cutoff": "2027-01-01T00:00:00Z"
  }
]
```

| Field | Meaning |
|---|---|
| `name` | The operator places the secret at `/<namespace>/<app>/enclave/inherit/<name>`, as a `String` or `SecureString`. |
| `env_var` | Environment variable set on the application process, containing the parameter value with surrounding whitespace trimmed. |
| `type` | `hash` or `publicKey`: what `value` pins. |
| `value` | Array of commitments, one per delivered entry. `hash`: hex SHA-256 of the secret; the entry is the secret hex-encoded, and the pin covers the decoded bytes. `publicKey`: hex compressed secp256k1 public key; the entry is the matching private key as 64 hex characters. Every entry is hex, so a comma or colon inside a secret cannot occur. With more than one commitment the delivered value is a comma-separated list of the same length, each entry matched against one unused commitment in any order. Any entry may carry metadata for the application after a colon, as in `<private-key>:<unix-timestamp>`: only the secret is pinned, and the entry reaches the application whole. The metadata must not contain a comma. |
| `cutoff` | Optional RFC 3339 timestamp from which the application no longer receives the secret. Without one, the value is still verified against its pin, but it is delivered on every boot for as long as its parameter exists and no restart ever withdraws it. |

The array is baked into the image, so the pins and cutoffs are part of PCR0: a
verifier knows which outside secret the enclave accepts, and until when, or
that no cutoff applies.

At boot, before the application starts:

- A secret at or past its `cutoff` is not read: its parameter is never
  fetched, so the parameter and the KMS key of a `SecureString` can be retired
  once the cutoff has passed without affecting later boots.
- A value that does not match its pin **aborts boot**.
- A missing parameter is logged and skipped. Deleting a parameter therefore
  withdraws the secret from future boots; enclaves already running keep it
  until its cutoff or their next restart.
- The cutoff is checked again just before the application is launched, so a
  slow boot cannot hand over a secret that expired in the meantime.

When a cutoff passes while the enclave is running, the runtime clears the
variable and restarts the application without it. The runtime itself, its
attestation and its TLS identity are unaffected; the application sees a
`SIGTERM` (then `SIGKILL` after ten seconds) and a fresh start. The cutoff is
checked every 30 seconds against the enclave's synchronised clock.

Constraints:

- `name` must be unique and a single path segment.
- `env_var` must be a valid identifier, unique across static and inherited
  secrets, and not one of the runtime exports listed under
  [Application process environment](#application-process-environment).
- `env_var` must not be set in the baked environment nor be in
  `overrideAllowlist`, so nothing else can stand in for a secret that is not
  delivered or is past its cutoff. Either **aborts boot**.

An inherited secret is only as private as its history: whoever can read the SSM
parameter can read it, and so could everyone who held it before. The pin
guarantees the enclave uses the intended secret, not that nobody else has it.
Inherited secrets are not extended into a PCR and are not part of the migration
snapshot — a successor reads the same parameter.

The parameter type is the operator's choice and does not change what the
enclave guarantees. A `String` is readable by anyone with `ssm:GetParameter` on
the path. A `SecureString` is encrypted at rest by SSM with a KMS key the
operator owns — the account's `aws/ssm` key or a customer-managed one, created
before the parameter is written and unrelated to the enclave's own key — so
reading it also takes `kms:Decrypt` on that key, and every read leaves a
CloudTrail record. The runtime asks SSM to decrypt when it reads the parameter;
the instance role therefore needs `kms:Decrypt` on that key, and on no other.

### SSM environment overlay

Parameters under `/<namespace>/<app>/enclave/env/` are read at boot (non-recursively,
with decryption). Application variables are exported only when named in
`buildEif.overrideAllowlist`, which defaults to an empty list. This allows
application configuration changes without rebuilding the image.

The following names update runtime configuration directly, regardless of the
allowlist. They are reserved for the runtime: adding them to the allowlist does
not export them into the application's environment. The runtime explicitly
passes the final application port to the child as described in
[Application process environment](#application-process-environment).

| Parameter under `/<namespace>/<app>/enclave/env/` | Purpose |
|---|---|
| `ENCLAVE_APP_PORT` | Application listen port and runtime proxy target port. |
| `ENCLAVE_FQDN` | Certificate hostname. |
| `ENCLAVE_USE_ACME` | `true` switches from self-signed to ACME. |
| `ENCLAVE_ACME_DIRECTORY` | `letsencrypt-staging` or an `https://` directory URL. |
| `ENCLAVE_ACME_EMAIL` | ACME account contact. |
| `ENCLAVE_ACME_CA` | PEM CA bundle for a private ACME server. |

The four ACME settings are read only from this overlay. `ENCLAVE_FQDN` starts
with the baked value (default `localhost`), which the overlay may replace.

Applications that need the same value must use a separate variable. For example,
allowlist `APP_PUBLIC_HOSTNAME` and set
`/prod/wallet/enclave/env/APP_PUBLIC_HOSTNAME` to `wallet.example.com` for the app.
Set `/prod/wallet/enclave/env/ENCLAVE_FQDN` separately for the runtime's TLS certificate.

The overlay cannot change the runtime's captured identity, lineage or security
settings: `ENCLAVE_NAMESPACE`, `ENCLAVE_APP_NAME`, `ENCLAVE_SECRETS_CONFIG`,
`ENCLAVE_INHERIT_SECRETS_CONFIG`, `ENCLAVE_DEV`, `ENCLAVE_MIGRATION_COOLDOWN`,
`ENCLAVE_VERIFY_CLOCK_SOURCE`, `ENCLAVE_INSECURE_VERIFY_SKIPPED` and
`ENCLAVE_PREVIOUS_PCR0`. Changing those runtime settings requires rebuilding the
image. `ENCLAVE_DEV` selects the KMS lock posture and Object Lock retentions;
neither has a separate environment-variable override.

The TLS key is generated at genesis, encrypted with KMS, and included in the
state root. Renewed certificates reuse it. The certificate bucket stores only
encrypted certificates; the ACME account signer derives from the master seed
and is separate from the TLS key.

### Application process environment

The runtime removes each configuration variable from the process environment
as it loads it. The application inherits the remaining environment, including
baked application variables, allowlisted SSM application overrides, static
secrets and inherited secrets, plus these explicit runtime exports:

| Variable | Value |
|---|---|
| `PORT` | `ENCLAVE_APP_PORT`, default `7074` |
| `ENCLAVE_APP_PORT` | the same value |
| `ENCLAVE_PROXY_PORT` | the internal API port, default `8080` |
| `ENCLAVE_RUNTIME_TOKEN` | a 32-byte hex bearer token, regenerated each boot |

`ENCLAVE_RUNTIME_TOKEN` authenticates the application to the runtime's OTLP
forwarders on the internal listener. `stdout` and `stderr` are inherited.

### SSM parameters

With `N` = `ENCLAVE_NAMESPACE` (one or more segments), `A` = app name, `L` = `locked`
or `unlocked`. Everything the runtime reads or writes sits under `/N/A/enclave/`; the
rest of `/N/A/` is the application's to use, and the same `/N/A/enclave` root names the
CloudWatch log groups.

**Changed:** parameters used to sit directly under `/N/A/`. The runtime reads only the
new paths, so an existing deployment moves by recreating its operator parameters under
`/N/A/enclave/` and taking a fresh genesis; a successor cannot adopt state a predecessor
wrote under the old layout, and the `SSMParams` and `CloudWatchLogsAccess` policies
must match the new root.


| Path | Written by | Purpose |
|---|---|---|
| `/N/A/enclave/CertBucketName` | operator | Shared encrypted-certificate bucket. |
| `/N/A/enclave/LeaseBucketName` | operator | Ephemeral coordination lease bucket. |
| `/N/A/enclave/env/<NAME>` | operator | Environment overlay. |
| `/N/A/enclave/inherit/<name>` | operator | Inherited secret, verified against its baked pin. |
| `/N/A/enclave/MigrationChallenge/<sourcePCR0>` | runtime | Live challenge: the predecessor's attestation over a fresh nonce, bound to the state namespace. Its attested timestamp drives rotation every minute. Advanced tier. |
| `/N/A/enclave/MigrationResponse/<sourcePCR0>/<candidatePCR0>` | runtime | A candidate's attestation answering that challenge. Advanced tier. |
| `/N/A/enclave/MigrationResponse/<sourcePCR0>/abort` | operator | Naming the pending target PCR0 cancels the handoff. The predecessor records the abort in the intent log as soon as it sees it. |
| `/N/A/enclave/L/KMSKeyID/<pcr0>` | runtime | Handoff pointer: the migration key a predecessor committed for the successor measuring `<pcr0>`. Written create-only and last. Never manage this with deployment tooling. |
| `/N/A/enclave/L/MasterSeed/Ciphertext/<keyID>` | runtime | Handoff: the master seed under the successor's migration key. |
| `/N/A/enclave/L/TLSKey/Ciphertext/<keyID>` | runtime | Handoff: the TLS key under the successor's migration key. |
| `/N/A/enclave/MigrationPreviousPCR0/<pcr0>` | runtime | Handoff: the predecessor's PCR0, in its successor's scope. |
| `/N/A/enclave/MigrationPreviousKMSKeyID/<pcr0>` | runtime | Handoff: the predecessor's KMS key ID. |
| `/N/A/enclave/MigrationStateOriginReceipt/<keyID>/<pcr0>` | runtime | Handoff: the predecessor's transition receipt over the successor's state. Written create-only. |

SSM holds no generation state. The handoff rows are transport: a predecessor
writes them for a successor it has not met, and the successor reads them once,
verifies them against the transition receipt, and publishes them as its
`snapshot/<pcr0>`. From then on nothing reads them again, so deleting, overwriting
or expiring any of them can stall an adoption still in flight but never select
other state, and never trigger a genesis. Each handoff attempt writes under a
key ID minted for it alone, so a losing or interrupted attempt leaves only
orphans.

Genesis writes no parameter at all.

## HTTP API

### External listener, TCP :443

TLS 1.2 minimum. HTTP and gRPC clients authenticate the enclave by verifying its
PCRs and pinning the live TLS public key to the PublicKey hash in the attestation document.
`/enclave/*` responses also carry permissive CORS headers, and an `OPTIONS`
preflight to any path in that namespace is answered `204` by the runtime.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/enclave/attestation?nonce=<40 hex>` | none | NSM attestation document, base64. The nonce is mandatory and echoed back. `user_data` is exactly 39 bytes: ASCII `sha256:` followed by the raw 32-byte SHA-256 of the TLS PublicKey. `503` until the application has been started, so always on a candidate. |
| GET | `/enclave/v1/info` | none | Version, `status` (`candidate` until state is obtained, `starting` until the application has been started, then `ready`; `failed` with status 503 and an `error` naming the missing grants when the permission preflight stops the boot), for a candidate the predecessor offering it a handoff, PCR0, predecessor PCR0 and attestation, migration status, application status, and the ancestor-key audit: every ancestor generation's PCR0, KMS key ID, and whether that key still exists, is pending deletion, or is gone. |
| GET | `/health` | none | `{"status":"ready"}` once the application has been started, `{"status":"initializing"}` with status 503 before. |
| any | unmatched paths outside the `/enclave` namespace | none | Reverse-proxied to the application. `503` until the application has been started, so always on a candidate. |

Telemetry is forwarded, never stored. The OTLP forwarders live on the internal
listener only, since they sign with the instance role, and nothing is read back
through the runtime, so a compromised enclave has no history to serve.

The complete `/enclave` namespace is reserved for runtime APIs. Unknown
non-preflight paths beneath it return the runtime's `404` response, and no
request in that namespace is proxied to the application. A request to the bare
`/enclave` is redirected to `/enclave/`, which then returns that `404`.

`/health` reports ready as soon as the application process has been started,
which is marginally before it binds its port. Readiness probes should target an
application endpoint.

#### Ancestor-key audit

Each generation mints its own KMS key and migration is strictly additive, so a
retired generation keeps a key that can still decrypt state until an operator
deletes it. The `ancestry` block of `/enclave/v1/info` reports what became of
those keys, newest first.

`complete` is true only when each predecessor's published `snapshot/<pcr0>`
verifies, names the KMS key the link above it recorded, and the walk reaches a
state with no predecessor. Missing, altered, malformed or cyclic state makes it
false and `reason` explains the failure without exposing the underlying AWS
error. The genesis generation is not repeated separately: it is the final
verified state in the chain. The walk reads S3 only, never SSM.

| `state` | Meaning |
|---|---|
| `exists` | `DescribeKey` reports that the key is present and not scheduled for deletion. |
| `pending_deletion` | Deletion is scheduled. |
| `deleted` | KMS no longer knows the key. This generation can no longer decrypt anything. |
| `unknown` | The state could not be read. The cause is logged, not published: the AWS error names role ARNs and account IDs, and this endpoint is unauthenticated. |

`unknown` never means deleted. Only KMS reporting the key as absent produces
`deleted`, so a permissions failure or a KMS outage can never be read as proof
that a retired generation was retired.

The block is a cached snapshot, rebuilt once at boot and then daily: `checked_at`
is when it was built, and is `null` before the first probe completes. Reading it
never calls SSM or KMS, so the endpoint cannot be made slow or unavailable by
either.

The chain has no length cap. A corrupt chain still terminates: a repeated
PCR0/key identity stops the walk and is reported through `complete` and
`reason`.

### Internal listener, TCP 127.0.0.1:8080

Serves `POST /v1/metrics`, `POST /v1/logs`, `POST /v1/traces` and `GET /health`
only. The three forwarders expect `Authorization: Bearer <ENCLAVE_RUNTIME_TOKEN>`,
accept OTLP/HTTP as `application/x-protobuf` or `application/json`, optionally
`gzip`-encoded, and answer with whatever AWS answered. When traces or metrics
are off, that forwarder answers with an empty success and forwards nothing. This is the endpoint
advertised to the application through `ENCLAVE_PROXY_PORT`. It does not serve
`/enclave/v1/info`, the `/enclave/*` endpoints, or the application proxy.

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
- Route intended client traffic to the enclave's TLS listener, TCP port 443 by
  default.

### Reaching the enclave from its instance

An enclave has no shell, and its console is unreadable in production, so its
runtime API is how an operator sees what it is doing, including why a boot
stopped. The host already routes port 443 to the enclave's TLS listener, so from
a shell on the instance (SSH or SSM Session Manager):

```sh
curl -sk --http1.1 https://127.0.0.1/enclave/v1/info | jq
```

The same request works wherever port 443 is
routed to it. `-k` is needed because, until it holds state, an enclave serves an
ephemeral self-signed certificate. That includes an
enclave stopped by the [permission preflight](#aws-requirements), which answers
`503` with (abridged):

```json
{
  "version": "0.1.0",
  "status": "failed",
  "error": "permission preflight: role arn:aws:iam::123456789012:role/enclave is missing CloudWatchLogsAccess logs:PutLogEvents on arn:aws:logs:eu-west-1:123456789012:log-group:/prod/enclave/logs/app:log-stream:i-0123456789abcdef0 (implicitDeny)"
}
```

A response read this way is not attested: whoever controls the host could have
produced it. Use it to diagnose, and once the enclave reports `ready`, verify it
with the CLI before trusting anything it says.

### AWS requirements

Create a private S3 bucket for shared certificate state and write its name to
`/<namespace>/<app>/enclave/CertBucketName`. Create a separate private S3 bucket for
ephemeral coordination leases and write its name to
`/<namespace>/<app>/enclave/LeaseBucketName`.

The state bucket, which holds every generation's state and the migration intent
log, is **not** configured. Its name is derived, so no parameter a host can
rewrite decides where deployment state is looked for:

```text
enclave-<account-id>-<sha256(namespace \x00 app)[:8]>-migration-intents
```

`namespace` is `ENCLAVE_NAMESPACE` exactly as set, such as `ark/prod`.

Provisioning must create exactly that bucket, with versioning and Object Lock
enabled at creation, before the enclave first boots; the runtime only reads and
writes it. The digest keeps its name inside S3's 63-character limit and its
character rules whatever the namespace and application are called, and the
account ID keeps two AWS accounts off the same globally unique name.

AWS credentials delivered through IMDS must allow:

| Statement | Permissions |
|---|---|
| `S3CertAndLeaseReadWrite` | `GetObject`, `PutObject`, `DeleteObject`, `ListBucket`, `GetBucketLocation` on the certificate and lease buckets. |
| `S3MigrationIntentObjectLock` | On the derived state bucket: `ListBucketVersions` on the bucket; `GetObject`, `GetObjectVersion`, `GetObjectRetention` on `<bucket>/*`; `PutObject` and `PutObjectRetention` on `<bucket>/snapshot/*` and `<bucket>/migration-intent/*` only. `PutObjectRetention` is what lets a `PutObject` carry its compliance lock. Without `GetObjectRetention`, S3 hides the lock on every object and the runtime ignores every state and intent. Grant no `s3:DeleteObject`, `s3:BypassGovernanceRetention` or `s3:CreateBucket`: the runtime never deletes a record and must never manufacture an empty authority. |
| `SSMParams` | `GetParameter`, `GetParametersByPath` on `/<namespace>/<app>/enclave/*`. |
| `SSMMigrationCoordination` | `PutParameter` on `/<namespace>/<app>/enclave/` + `MigrationChallenge/*`, `MigrationResponse/*`, `<locked\|unlocked>/KMSKeyID/*`, `<locked\|unlocked>/MasterSeed/Ciphertext/*`, `<locked\|unlocked>/TLSKey/Ciphertext/*`, `MigrationPreviousPCR0/*`, `MigrationPreviousKMSKeyID/*` and `MigrationStateOriginReceipt/*`. Nothing else: the runtime never writes configuration, the environment overlay or inherited secrets. |
| `KMSAccess` | `CreateKey`, `TagResource`. `DescribeKey` is optional; see below. |
| `STSAccess` | `GetCallerIdentity`. |
| `PermissionPreflight` | `iam:SimulatePrincipalPolicy` on the enclave role's own ARN, and nothing else, so the enclave can ask what it may do but not what any other principal may. |
| `Route53AcmeChallenge` | Only with `ENCLAVE_USE_ACME=true`: `ChangeResourceRecordSets` on the hosted zone named in `/<namespace>/<app>/enclave/Route53ZoneID`, and `GetChange`. |
| `CloudWatchLogsAccess` | Required, and write-only: `CreateLogGroup`, `CreateLogStream`, `PutLogEvents` on `/<namespace>/<app>/enclave/*`. The OTLP `/v1/logs` endpoint authorises as `PutLogEvents` on the same group ARNs. `PutRetentionPolicy` is optional but recommended — without it the boot still succeeds and log groups never expire. Nothing more — the runtime never reads its own telemetry back, and granting `FilterLogEvents` or `DescribeLogStreams` would hand a compromised enclave the history it was designed not to hold. Read the logs with operator or CI credentials instead. Without this statement the enclave does not boot. |
| `XRayAccess` | Only with `ENCLAVE_TRACES=true`. `xray:PutSpans`, `xray:PutSpansForIndexing` and `xray:PutTraceSegments` on `*`, plus Transaction Search enabled on the account. Without them every span export is refused; the enclave still boots and counts the refusals. |
| `CloudWatchMetricsAccess` | Only with `ENCLAVE_METRICS=true`. `cloudwatch:PutMetricData` on `*`. Without it every metric export is refused; the enclave still boots and counts the refusals. |

`Encrypt`, `Decrypt`, and `GenerateDataKey` are deliberately absent. Those
operations are authorised by the enclave-created key's own PCR0-conditioned
policy, not by the host credentials, so possessing those credentials is not
sufficient to read enclave state.

`DescribeKey` is read-only and only reports whether ancestor keys were deleted.
Each key's `EnclaveOperations` statement already grants it to the role that
created the key, so this grant only matters for unlocked ancestor keys created
under another role, which otherwise read `unknown`.

`/<namespace>/<app>/enclave/<locked|unlocked>/KMSKeyID/<pcr0>` is owned exclusively by
the runtime. Do not pre-create or declaratively manage it. Migration finalisation
writes it last, create-only, to elect one finaliser among predecessor replicas;
a pre-existing value makes the runtime refuse to finalise a handoff onto that
PCR0. Genesis never writes it.

Before telemetry starts and before its first durable write, every boot asks IAM,
through `SimulatePrincipalPolicy`, whether the role holds the S3, SSM, KMS,
CloudWatch Logs and (with ACME) Route53 grants above. A denied or incomplete
simulation stops the boot before durable writes. The enclave stays up and
`/enclave/v1/info` answers `503` with `status: "failed"` and an `error` naming every
missing statement, action and resource, since the
console is unreadable in production and telemetry has not started. Read it
[from the instance](#reaching-the-enclave-from-its-instance), fix the policy,
then restart the enclave.

A check AWS leaves unanswered, because it throttled, failed server-side or was
unreachable after the SDK's own retries, is repeated up to five times over about
a minute before the boot stops on it, so a burst of enclaves booting together
does not park on a momentary IAM limit. A denial, or any other error AWS
answered with, such as a missing `iam:SimulatePrincipalPolicy` grant or bucket
parameter, stops the boot at once.

Known resources, including this enclave's `snapshot/<pcr0>`, its migration
challenge and response, certificate objects and leases, are checked by their
exact names. Future key IDs,
migration objects and Route53 change IDs are checked at namespace scope; those
checks cannot rule out denials on specific future resources or later policy changes.

The simulation includes the region, caller ARN, KMS creation tags and DNS-01
record context. Missing context reported by IAM is named in the error. It reads
the role's policies, permissions boundary and service control policies, but not
bucket policies or configuration. Object Lock is verified separately, on the
objects themselves: every state the runtime publishes is read back and adopted
only if S3 reports it compliance-locked for the full retention, so a state bucket
without versioning and Object Lock still fails at genesis, before anything is
served. The role is derived from the STS session, so a role
created with a path other than `/` is not found.

`PermissionPreflight` must name the role itself, so whoever holds its
credentials, the enclave or the host, can ask only what this role may do. In
Terraform:

```hcl
resource "aws_iam_role_policy" "enclave_permission_preflight" {
  role = aws_iam_role.enclave.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PermissionPreflight"
      Effect   = "Allow"
      Action   = "iam:SimulatePrincipalPolicy"
      Resource = aws_iam_role.enclave.arn
    }]
  })
}
```

## Blue/green migration

Migration preserves an existing deployment's secrets and TLS identity while
moving to a new PCR0. **Booting a candidate is the request**: the protocol runs
between enclaves over SSM, with no control endpoint.

```text
predecessor                                candidate
  publish challenge   ------------------>  read it
  read answers        <------------------  publish attestation
  verify, record Object-Locked intent
  ... cooldown, abort window ...
  commit KMSKeyID/<target>  ------------>  adopt, publish snapshot/<target>
```

The predecessor verifies a live attestation bound to the same namespace, app and
lock posture. The host cannot forge that evidence, but it can choose which image
to launch. The protocol does not establish operator approval of that image.
Run one candidate image at a time for deterministic selection: the first verified
answer wins. Predecessor replicas share the challenge and intent chain.

1. Build the successor with `ENCLAVE_PREVIOUS_PCR0` set to the predecessor's
   PCR0, preserving namespace, app name and lock posture.
2. Boot it as a candidate. It answers the predecessor's challenge without
   serving the application or attestation endpoint.
3. Check `migration.target_pcr0` on the predecessor's `/enclave/v1/info` during
   the cooldown. To abort, write that target PCR0 to
   `/<namespace>/<app>/enclave/MigrationResponse/<predecessor PCR0>/abort` and
   stop the candidate. The predecessor records the abort in its intent log.
4. After the cooldown, the predecessor commits the target into PCR31, creates
   the successor's KMS key, and writes the encrypted seed, TLS key, lineage and
   transition receipt to SSM. It writes `KMSKeyID/<successor PCR0>` last,
   create-only, so only one predecessor replica can commit the handoff.
5. The successor verifies the handoff and key policy before decrypting, then
   publishes its snapshot with both receipts. Check `/enclave/v1/info` for
   `status: "ready"`, the expected `previous_pcr0`, and a non-empty
   `previous_pcr0_attestation`. Snapshot publication alone is not readiness.
6. Shift traffic using your deployment system. Keep both generations healthy
   during the soak period, then retire the predecessor. Its snapshot and key
   remain available for restarts unless you explicitly retire the key.

Leave handoff parameters intact until the successor is ready. Afterwards they
may be deleted: published generations resume from S3. A candidate that misses
the handoff because a peer adopted and the parameters were cleaned up can
recover by restarting. If adoption fails, keep serving from the predecessor;
its state is unchanged by the handoff.

A committed handoff pointer prevents the predecessor from retrying. Attempts
that lose the create-only write or stop before it may leave unused keys and SSM
parameters. Do not manage `KMSKeyID/<pcr0>` through deployment tooling.

An abort can also be recorded after handoff. It prevents an unpublished
successor from adopting, but does not revoke a published snapshot. To migrate
to a different target afterwards, restart the predecessor: its PCR31 remains
committed to the earlier target for that boot.

**Retiring keys.** Keep a generation's key if you may need to boot it again.
Otherwise, schedule deletion out of band and check the successor's signed
`/enclave/v1/info` response until the ancestor reports `state: "deleted"`.
`pending_deletion` is reversible: the instance role can call `CancelKeyDeletion`
and then `EnableKey` to restore access. To prevent that role from cancelling a
retirement, attach a deny scoped to the retired key before scheduling deletion:

```json
{
  "Effect": "Deny",
  "Action": "kms:CancelKeyDeletion",
  "Resource": "arn:aws:kms:<region>:<account>:key/<retired key ID>"
}
```

The deny overrides the key policy's allow. Retain the ancestor's locked snapshot
so the audit can follow the lineage; missing or unverifiable state makes ancestry
incomplete and does not prove retirement.

### Compatibility

This state format has no import or fallback for earlier SSM-backed deployments,
`deployment-genesis` objects, or older snapshots and receipts. Their transition
receipts cover a different state root and cannot be adopted. Start a fresh
genesis under a new namespace or app name, with a new seed and derived secrets.

Earlier images still running keep their state in SSM. Until they are retired:

- leave their role's `PutParameter` grant on `/<namespace>/<app>/enclave/*` in
  place; narrowing it strands them;
- do not attach parameter policies, expiration in particular, to their
  runtime-written parameters; and
- deny `ssm:DeleteParameter` and `ssm:DeleteParameters` on those paths, because
  for those images SSM, not Object Lock, is all that protects their state.

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
enclave curl /enclave/v1/info \
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
| `user_data` is exactly `sha256:` plus the raw 32-byte TLS PublicKey SHA-256, and the live certificate contains that public key | on | `InsecureTLS` |
| Public CA and hostname validation | off | enabled by `StrictTLS` |
| PCR16 onward match `ExpectedPCRs` | off | populated by `ExpectedPCRs` |

The certificate pin is installed from the attestation document before any
request carrying data is made, so a request issued before verification completes
fails closed.

`GRPCConn` uses the same PCR verification and attested TLS pinning model as HTTP,
but does not perform public CA validation. Applications serving gRPC must set
`ENCLAVE_UPSTREAM=h2c`.

## Testing

```sh
nix flake check
```

| Check | Purpose |
|---|---|
| `eif-build` | Builds predecessor and successor EIFs, validates PCR0 shape, and proves the measurements differ. |
| `e2e` | x86-only runtime lifecycle across five NixOS nodes: AWS setup, concurrent genesis and handoffs, clock recovery, attestation, ACME, secret derivation and replacement, replica joins, and restart recovery. |

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
hypercall while its own clocksource is TSC-based. The enclave test nodes
therefore force `clocksource=tsc`; NixOS test instrumentation otherwise appends
`clocksource=acpi_pm`, and the kernel honours the last value on the command line.
Without this the enclave has no `/dev/ptp0` and boot fails before networking.

The e2e test includes a one-minute migration cooldown. During that cooldown,
it replays a genuine intent through a multipart upload initiated 48 hours earlier
and checks that both blue replicas preserve the original eligibility time and
keep green waiting. The same fleet then completes the handoff and recovery checks.

Run the lifecycle check on Linux with
`nix build .#checks.x86_64-linux.e2e --print-build-logs`.

### Reading test output

`--print-build-logs` includes every test VM's kernel and systemd serial output.
Filter it to keep evaluation progress, test driver actions, failures, and the
result:

```sh
set -o pipefail
nix flake check --print-build-logs 2>&1 |
  rg --line-buffered \
    '(^evaluating |^checking |^error:|> (machine|aws|blue(_peer)?|green(_peer)?):|> !!!|> cleanup|> test script|all checks passed)'
```

`pipefail` preserves the exit status through the filter.

### E2E boundaries

The test uses five NixOS nodes: `aws` runs the AWS emulator, KMS Recipient proxy,
IMDS, ACME fixtures and OTLP receiver; `blue`, `blue_peer`, `green` and
`green_peer` run measured EIFs under QEMU. It covers:

- Concurrent genesis and successor adoption, with one locked snapshot per PCR0.
- Static/inherited secret replacement under unchanged environment variable names,
  missing inherited values, derivation continuity and TLS certificate reuse.
- Restart and replica joins after handoff parameters are deleted or corrupted
  and invalid newer snapshot versions are added.
- Predecessor key deletion scheduling and cancellation, with successor recovery.

The emulator has limits; Go tests cover the corresponding branches, but these
behaviours also need validation against AWS:

| Boundary | Emulator limitation |
|---|---|
| Delete markers | Rejects deletion of a locked object rather than adding a marker. |
| Retention | Tracks retention per key rather than per version. Stacked E2E versions therefore omit lock headers. |
| Object Lock permissions | Does not establish real bucket configuration and `PutObjectRetention` enforcement. |
| IAM scoping | Denies by action only, so resource restrictions need separate validation. |
| Completed KMS deletion | The run reaches `pending_deletion`; Go tests model a fully deleted predecessor key. |

The test namespace is `ark/e2e/dev`. Images enable `ENCLAVE_DEV` and
`ENCLAVE_INSECURE_VERIFY_SKIPPED` because QEMU's NSM has no AWS certificate chain.
Signature verification is covered by Go tests, not E2E. Normal dev deployments
should leave the skip flag unset. Tests also enable clock-source verification,
traces and metrics, and use a 60-second migration cooldown.

The driver provisions AWS resources and controls node startup. It does not test
a deployment system, host image lifecycle or traffic cutover.

### Troubleshooting

**The enclave does not start.** Inspect the QEMU launcher and enclave console on
the affected enclave node.

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

**Migration stalls under QEMU.** `vhost-device-vsock`
0.3 occasionally drops a forwarded host-to-guest connection before it reaches
the enclave. Retry. This affects the emulated transport only; production uses
Nitro AF_VSOCK. A genuine validation failure returns an HTTP status and body and
should not be retried.

## Security notes

**Pin PCR0.** The client requires `ExpectedPCR0`, verifies Nitro attestation and
PCRs, and pins the live TLS leaf to the attested hash before sending application
requests. Attestation without an expected measurement does not identify your
code.

**Dev mode still verifies signatures.** `ENCLAVE_DEV` retains the KMS root
recovery principal and shortens retention, write timeout and clock-sync
intervals. Signature checks are skipped only when
`ENCLAVE_INSECURE_VERIFY_SKIPPED=true` is also set; production ignores that flag.
The skip is for QEMU tests, where PCR and payload checks still run but COSE
signature and certificate-chain checks do not. Namespace names such as `dev`
and `prod` do not select a security mode.

**Host credentials alone cannot decrypt state.** KMS operations require the
PCR0-bound policy and enclave attestation. Static secrets are committed to
locked PCRs. Snapshot authentication and recovery rules are described under
[Generation state](#generation-state).

**Migration verifies the candidate, not operator approval.** A live challenge
prevents replay, but the host chooses which image to launch. Inspect the target
PCR0 during the cooldown as described in [Blue/green migration](#bluegreen-migration).

**CloudWatch Logs is a boot dependency.** Startup creates both log groups and
streams and probes the runtime group's OTLP path. The probe does not test
application uploads: those can fail later and increment
`enclave_otlp_logs_upstream_errors_total`. Trace and metric export failures are
not fatal.

**Telemetry forwarding uses the instance role.** The loopback-only forwarders
require a per-boot `ENCLAVE_RUNTIME_TOKEN`, expose no read endpoints, and keep no
local history. Their IAM permissions are write-only.
