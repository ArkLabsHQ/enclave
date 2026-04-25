# viproxy upstream provenance

Vendored from https://github.com/brave/viproxy.

- **Tag**: `v0.1.2`
- **Rev**: `f0ad28e2e76bf3c04d22c46d31ca9c96ffe59f12`
- **License**: Mozilla Public License 2.0 (see upstream LICENSE)
- **Vendored**: 2026-04-24

## What's vendored

Single file: `viproxy.go` (137 lines), byte-identical to upstream.

## Local modifications

None. Upstream ships as `package viproxy` already — no rename required.

## Why in-tree

Upstream publishes a Go module (`github.com/brave/viproxy`), so we could
import it directly. We vendor anyway for the same reasons as nitriding: we
own the version, we can patch without waiting on upstream, and the "fetch
external Go module at Nix build time" path is what we eliminated when we
stopped building viproxy as a separate binary.

## Syncing to a newer upstream

1. `git diff v0.1.2..<new-tag> -- viproxy.go` against brave/viproxy.
2. Apply the diff here.
3. Update this file's Tag / Rev / Vendored date.
4. Bump `vendorHash` in [flake.nix](../../flake.nix).
