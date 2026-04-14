# Reproducible builder for running `make test-build` on any host.
# Container is pinned to linux/amd64 so Nix natively builds the x86_64-linux EIF
# (matters on aarch64-darwin / aarch64-linux hosts where the Mac kernel or wrong
# arch would otherwise block execution of Linux build steps).
#
# The enclave CLI is built from the bind-mounted /workspace at runtime, not
# pinned to a published release — so local changes to the CLI, sdk, and mgmt
# are exercised end-to-end.
#
#   docker build --platform=linux/amd64 -t introspector-enclave-builder .
#   docker run  --rm --platform=linux/amd64 \
#               --user "$(id -u):$(id -g)" -e HOME=/tmp \
#               -v "$(pwd):/workspace" -w /workspace \
#               introspector-enclave-builder
FROM --platform=linux/amd64 nixos/nix:latest

RUN mkdir -p /etc/nix \
 && printf 'experimental-features = nix-command flakes\nsandbox = false\nfilter-syscalls = false\n' \
      > /etc/nix/nix.conf

RUN nix profile install \
      'nixpkgs/nixos-25.11#go_1_25' \
      'nixpkgs/nixos-25.11#gnumake' \
      'nixpkgs/nixos-25.11#jq' \
      'nixpkgs/nixos-25.11#gnused'

# Trust bind-mounted repos regardless of host uid. --system writes to
# /etc/gitconfig so it applies to any uid the container runs as.
RUN git config --system --add safe.directory '*'

ENV GOCACHE=/root/.cache/go-build \
    GOPATH=/root/go \
    CGO_ENABLED=0 \
    PATH=/root/go/bin:/root/.nix-profile/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /workspace

# Build the enclave CLI from the mounted workspace (so SDK/mgmt/CLI local changes
# are all exercised), then run the standard test-build target. Container runs as
# root because Nix needs an /etc/passwd entry that matches its uid; we chown the
# workspace back to HOST_UID/HOST_GID at exit so the host user can edit/delete
# the generated artifacts.
CMD ["sh", "-c", "trap 'chown -R \"${HOST_UID:-0}:${HOST_GID:-0}\" /workspace 2>/dev/null || true' EXIT; mkdir -p /root/go/bin && go build -trimpath -o /root/go/bin/enclave ./cmd/enclave && make test-build"]
