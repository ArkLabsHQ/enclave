# Reproducible builder for running `make test-build` on any host.
# Container is pinned to linux/amd64 so Nix natively builds the x86_64-linux EIF
# (matters on aarch64-darwin / aarch64-linux hosts where the Mac kernel or wrong
# arch would otherwise block execution of Linux build steps).
#
#   docker build --platform=linux/amd64 -t introspector-enclave-builder .
#   docker run  --rm --platform=linux/amd64 \
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

ENV GOCACHE=/root/.cache/go-build \
    GOPATH=/root/go \
    CGO_ENABLED=0 \
    PATH=/root/go/bin:/root/.nix-profile/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

ARG ENCLAVE_VERSION=v0.0.67
RUN go install "github.com/ArkLabsHQ/introspector-enclave/cmd/enclave@${ENCLAVE_VERSION}"

# Trust bind-mounted repos regardless of host uid (libgit2/nix git fetcher refuses
# otherwise when /workspace is owned by the host user but the container runs as root).
RUN git config --global --add safe.directory '*'

WORKDIR /workspace

CMD ["make", "test-build"]
