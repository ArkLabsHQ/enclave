# Binary cache + reproducible nixpkgs

`enclave build` is a Nix build. If any transitive dependency moves upstream —
a Cargo crate yanked, a GitHub repo renamed, a tarball removed — the rebuild
fails. Production EIFs that ran for months can become un-rebuildable from
one upstream event. See [ArkLabsHQ/enclave#127](https://github.com/ArkLabsHQ/enclave/issues/127)
for the failure mode that motivated this feature.

Two complementary tools fix it:

| Tool | What it solves |
|---|---|
| **Cachix binary cache** | Once an EIF is built, it can be re-served byte-identically from cache — regardless of upstream state. |
| **Pinned nixpkgs commit** | Stops the derivation graph from changing under you when the nixpkgs branch tip moves. |

Use both together. The cache without the pin only delays the inevitable —
when nixpkgs moves, the graph changes and the cache misses.

## 1. Set up Cachix (one-time)

1. Sign up at <https://app.cachix.org> and create a cache (free tier = 5 GB).
2. Copy the **public key** from the cache settings page.
3. Generate a **personal auth token** at <https://app.cachix.org/personal-auth-tokens>.

Add the cache details to `enclave/enclave.yaml`:

```yaml
nix:
  substituters:
    - "https://your-cache.cachix.org"      # only Cachix URLs are accepted
  trusted_public_keys:
    - "your-cache.cachix.org-1:<base64-key>="
```

Only `https://<name>.cachix.org` URLs are accepted. S3/Attic/self-hosted
backends are rejected at config load — this is intentional. See the
"Other backends" section at the bottom.

Install the `cachix` CLI on machines that push:

```sh
nix profile install nixpkgs#cachix
```

## 2. Pin nixpkgs

```sh
enclave nixpkgs pin --latest
```

This:
- queries `git ls-remote` for the tip of `nixos-25.11`,
- computes the SRI hash via `nix-prefetch-url --unpack`,
- writes `nix.nixpkgs_rev` + `nix.nixpkgs_hash` to `enclave/enclave.yaml`,
- rewrites `enclave/flake.nix`'s `nixpkgs.url` line to point at the commit.

Validate the pin without bumping:

```sh
enclave nixpkgs pin --check
```

Follow a different branch:

```sh
enclave nixpkgs pin --latest --branch nixos-unstable
```

## 3. Build and push

```sh
export CACHIX_AUTH_TOKEN=...
enclave build --push-cache
```

The closure (sources + intermediate derivations + the final EIF) is pushed
to the first substituter. Subsequent `enclave build` invocations on any
machine resolve from the cache instead of fetching upstream.

## 4. Wire into GitHub Actions

The scaffolded `.github/workflows/build-eif.yml` and
`.github/workflows/deploy-enclave.yml` already include a `Setup Cachix` step
gated on a repo variable. To enable it, set two values under your repo's
**Settings → Secrets and variables → Actions**:

| Kind | Name | Value |
|---|---|---|
| Variable | `CACHIX_CACHE_NAME` | the cache name from the URL, e.g. `merlin` for `https://merlin.cachix.org` |
| Secret | `CACHIX_AUTH_TOKEN` | the personal auth token from <https://app.cachix.org/personal-auth-tokens> |

When `CACHIX_CACHE_NAME` is unset, the step is skipped and the workflow runs
without the cache (same as today). When both are set, `cachix-action`:

- wires the substituter into `nix.conf` before the build (pull cached paths),
- pushes any newly-built paths to Cachix at job end (no need for `--push-cache` in CI).

`--push-cache` is for local dev and non-GHA CI (GitLab, Jenkins, etc.) where
the cachix-action isn't available.

## Reproducing a six-month-old EIF

```sh
git checkout <old-commit>     # the enclave.yaml at the time of original build
enclave build                  # cache hit on the closure — no upstream fetch
sha384sum .enclave/artifacts/image.eif
# Identical to the original PCR0 (the pinned nixpkgs + cached crates guarantee
# byte-identical output).
```

## Bumping the pin

Bumping picks up upstream security patches. It is an intentional EIF change —
the new PCR0 needs to go through normal migration.

```sh
enclave nixpkgs pin --latest        # writes new rev + hash + flake.nix
git add enclave/enclave.yaml enclave/flake.nix
git commit -m "bump nixpkgs pin (CVE-XXXX-YYYY)"
enclave build --push-cache          # populate cache with new closure
# Deploy as a normal migration.
```

The `git log enclave/enclave.yaml` history is your audit trail.

## Other backends

The framework only supports Cachix. To add S3, Attic, or self-hosted backends
would require:

- a separate URL-format validator,
- a separate push command per backend,
- per-backend auth conventions in docs.

Open an issue describing your requirements before submitting a patch — the
validation is intentionally strict, not an oversight.

## Trust model

Closures live on cachix.org. This is acceptable because:

- The cache contains BUILD OUTPUTS, not cryptographic material.
- The enclave's KMS-protected keys are generated inside the Nitro VM at boot;
  they never appear in any derivation.
- Cache entries are content-addressed by hash. A compromised cache can serve
  garbage but cannot serve "different code with the same hash."
- The public-key check in `trusted_public_keys` is signature verification on
  the narinfo (Nix's per-store-path metadata). Even a cache operator cannot
  substitute a different binary under your store path.

Worst case from `CACHIX_AUTH_TOKEN` leakage: an attacker pushes spam to your
cache (which counts against your storage quota). They cannot push under your
PCR0 — that requires building the actual derivation.

## Limits and caveats

- **Cachix free-tier limit is 5 GB.** Rust EIFs are 200 MB – 1 GB each. Watch
  your usage in the Cachix dashboard.
- **`aws-nitro-util.url` and `flake-utils.url` are framework-pinned commits**
  (the `AwsNitroUtilRef` and `FlakeUtilsRef` constants in `cli/framework_files.go`).
  Bumping is a framework-release activity, not per-project. `follows` declarations
  collapse their transitive inputs onto the operator's `nixpkgs` pin.
- **`enclave nixpkgs pin --latest` requires `git`, `nix`, and network
  access.** Surface the install hints from the error messages.
- **`flake.lock` may go stale relative to the rev in `enclave.yaml`.** If you
  see drift, delete `enclave/flake.lock` and re-run `enclave build` to
  regenerate it under the new pin.

## Vendor mode (Rust + Go) — survives upstream dep disappearance

Cachix protects rebuilds **once the cache has been populated**. But a fresh
build with no cache history still fails when an upstream crate disappears.
For belt-and-suspenders coverage, the framework supports an opt-in vendor
mode that switches Nix to use a committed `vendor/` directory in the app
source — no network access for app deps regardless of cache state.

Supported for `language: rust` and `language: go` only.

- **Node.js** has no clean vendor-mode equivalent in `buildNpmPackage`
  (`npmDepsHash` is mandatory).
- **.NET** already vendors via `nugetDeps = ./deps.json` — every package is
  manifest-pinned with content-addressed fetches, so the equivalent
  protection is already on.

### Opt-in workflow

Order matters: flip `vendor: true` BEFORE running `enclave setup`. Otherwise setup runs a trial Nix build to compute the vendor hash, which fetches from crates.io / the Go module proxy — and that's exactly the upstream you're trying to escape from in the recovery scenario.

```sh
# 1. In the upstream app's repo (NOT the framework repo):
cd ~/my-app
enclave vendor --path .       # runs `cargo vendor` (Rust) or `go mod vendor` (Go)
git add vendor/
git commit -m "vendor deps"
git push

# 2. Edit enclave/enclave.yaml:
#    set app.vendor: true
#    clear app.nix_vendor_hash (now unused; validation rejects setting both)

# 3. From the framework / project root:
enclave setup                 # sees vendor: true, skips hash discovery, refreshes nix_rev + nix_hash

# 4. Build as normal — Nix uses vendor/, no upstream fetch for app deps
enclave build
```

`enclave vendor` honours `app.nix_subdir` (changes into the subdir before
running `cargo vendor` / `go mod vendor`).

### How it complements Cachix

Vendor and cache cover different layers of the closure:

| Layer | Pin (in flake URLs) | Vendor (in repo) | Cachix |
|---|---|---|---|
| App source deps (Cargo / Go modules) | ✅ via lockfile + hash | ✅ explicit `vendor/` | ✅ if cached |
| Runtime supervisor + deps | ✅ | ❌ | ✅ if cached |
| nixpkgs + framework Nix inputs | ✅ | ❌ | ✅ if cached |

Vendor cuts the app-source fetch step entirely; Cachix still serves
everything else (nixpkgs, runtime, aws-nitro-util tooling) for fast rebuilds.
Use both for maximum robustness — neither subsumes the other.

### Trade-off

`vendor/` adds 100 MB – 1 GB to the upstream app repo (depending on dep
count). Reviewable in PRs (vendored crate source is plain text); just bulky.
For long-lived projects where every rebuild matters, the cost is worth it.

## Commit `enclave/flake.lock`

The scaffolded `enclave/flake.nix` pins every input (`nixpkgs`,
`flake-utils`, `aws-nitro-util`) by commit SHA and uses `follows`
declarations to collapse transitive inputs onto your top-level pins.

Even with that, **commit `enclave/flake.lock`**. It captures any transitive
input a future framework dep might introduce — `follows` only covers what you
explicitly enumerate, and a new aws-nitro-util release could add a new
transitive flake input that wasn't there before. The lockfile is your safety
net.

The file is small (a few hundred lines of JSON), regenerated only when you
intentionally update inputs (`nix flake update` or `enclave nixpkgs pin
--latest`), and the diff is reviewable.
