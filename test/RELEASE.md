# Releasing the test rig images

The CLI command `enclave test init` pulls two images from GHCR:

- `ghcr.io/arklabshq/enclave-awsmocks:<version>`
- `ghcr.io/arklabshq/enclave-test-runner:<version>`

`<version>` matches `cli/runtime-hashes.json::rev` with the leading
`v` stripped (e.g. tag `v0.0.75` → image tag `0.0.75`). When a new
framework version is cut, a maintainer **manually** builds and
pushes both images to keep them in lock-step with the CLI.

## Prerequisites

- Docker with buildx enabled.
- A GitHub PAT with `write:packages` scope:
  `docker login ghcr.io -u <gh-user> -p <PAT>`
- First-time only: after the first push of each image, open the
  package on GHCR (Org → Packages → enclave-awsmocks /
  enclave-test-runner → Package settings → Change visibility →
  Public) so users can pull anonymously.

## Build + push (per release)

From the repo root:

```bash
TAG=0.0.X   # strip the leading v from cli/runtime-hashes.json::rev

# Image 1 — awsmocks (~20 MB). Self-contained in awsmocks/.
docker buildx build \
  --platform linux/amd64 \
  -f awsmocks/Dockerfile \
  -t ghcr.io/arklabshq/enclave-awsmocks:$TAG \
  -t ghcr.io/arklabshq/enclave-awsmocks:latest \
  --push awsmocks/

# Image 2 — test-runner (~2 GB; bundles QEMU + vsock + supervisor + runner).
# Build context is the repo root (multi-stage needs go.mod for supervisor).
docker buildx build \
  --platform linux/amd64 \
  -f runner/Dockerfile \
  -t ghcr.io/arklabshq/enclave-test-runner:$TAG \
  -t ghcr.io/arklabshq/enclave-test-runner:latest \
  --push .
```

Verify after push:

```bash
docker pull ghcr.io/arklabshq/enclave-awsmocks:$TAG
docker pull ghcr.io/arklabshq/enclave-test-runner:$TAG
```

## Failure mode

If the CLI is bumped to framework version `X.Y.Z` but the matching
images haven't been pushed, `enclave test init` will fail at
`docker compose up` with a manifest-not-found error. The maintainer
fix is "push the missing tag." There is no fallback.
