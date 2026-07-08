# nitriding upstream provenance

Vendored from https://github.com/brave/nitriding-daemon.

- **Tag**: `v1.4.2`
- **Rev**: `efde3854070055d2a632e3c7bbf231f89ac09656`
- **Vendored**: 2026-04-24

## What's vendored vs dropped

**Kept (25 files):** `attestation.go`, `bufferpool.go`, `cache.go`, `certcache.go`,
`enclave.go`, `handlers.go`, `keysync_{initiator,responder,shared}.go`,
`metrics.go`, `proxy.go`, `system.go`, `system_linux.go`, plus matching `_test.go`
files, plus `package_init.go` (locally added).

**Dropped:** `main.go` and `main_test.go` (upstream CLI entrypoint — we construct
the `Enclave` programmatically from [runtime/cmd/runtime/main.go](../cmd/runtime/main.go));
`system_darwin.go` and `system_darwin_test.go` (EIF targets Linux only).

## Local modifications

The vendored files are byte-identical to upstream except for one line per file:

    -package main
    +package nitriding

The `elog` logger, `inEnclave` package variable, and `func init()` that upstream
defined in `main.go` are reproduced verbatim in `package_init.go` so other files
in the package keep compiling.

**`proxy.go` — stale TAP link cleanup in `setupNetworking`.** Upstream's
teardown only closes the vsock connection and the tap fd; the interface's IP
address and default route can survive across retries. When the host-side
gvproxy restarts (e.g. supervisor relaunch), the reconnect loop in
`RunNetworking` then fails forever: `configureTapIface` gets EEXIST
("failed to set link address: file exists") on every attempt, leaving the
enclave alive but permanently unreachable. We delete any pre-existing
`tap0` link before creating the TAP device, guaranteeing a clean slate.
Re-apply this block when syncing to a newer upstream.

## Syncing to a newer upstream

1. `git diff --stat v1.4.2..<new-tag> -- '*.go' ':!main*' ':!system_darwin*'` against
   brave/nitriding-daemon.
2. Apply the diff here, preserving the `package nitriding` first line.
3. If upstream adds package-level state or logic to `main.go`, port it into
   `package_init.go`.
4. Update this file's Tag / Rev / Vendored date.
5. Bump `vendorHash` in [flake.nix](../../flake.nix).
