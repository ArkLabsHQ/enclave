# nitriding upstream provenance

Vendored from https://github.com/brave/nitriding-daemon.

- **Tag**: `v1.4.2`
- **Rev**: `efde3854070055d2a632e3c7bbf231f89ac09656`
- **Vendored**: 2026-04-24

## What's vendored vs dropped

**Currently retained:** five upstream-derived implementation files —
`bufferpool.go`, `proxy.go`, `system.go`, `system_linux.go`, and
`system_darwin.go` — plus `bufferpool_test.go`, `proxy_test.go`, and
`system_test.go`. `package_init.go` is locally added.

**Dropped:** the upstream CLI entrypoint and `Enclave` API; HTTP handlers;
TLS/cert caching; metrics; attestation/hash helpers; the expiring cache; the
bounded reader; and key synchronization. `runtime` now owns TLS, attestation
endpoints, state and migration, metrics, and application proxying.

## Local modifications

The retained files are not byte-identical to upstream. In addition to changing
`package main` to `package nitriding`, local changes include:

- `package_init.go` reproduces the `elog` logger, `inEnclave` state, and `init()`
  bootstrap that upstream kept in `main.go`.
- `proxy.go` owns only the TAP/vsock tunnel used by `runtime`; attestation,
  HTTP, metrics, and key-sync integration were removed.
- `system_darwin.go` remains as a compilation stub even though EIFs target Linux.

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

This tree is intentionally pruned. Sync only fixes relevant to the retained
buffer-pool, TAP/vsock, Linux system, and entropy-bootstrap code; do not restore
dropped subsystems unless production callers are added.

1. Compare `v1.4.2..<new-tag>` for the retained paths in brave/nitriding-daemon.
2. Apply fixes selectively, preserving `package nitriding`, the platform stubs,
   and the stale-TAP cleanup above.
3. If upstream adds package-level bootstrap logic to `main.go`, port the relevant
   parts into `package_init.go`.
4. Update this file's Tag / Rev / Vendored date.
