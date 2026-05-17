# enclave-test-runner image — bundles every long-lived asset the
# upstream-app integration-test rig needs: QEMU 9.2.4, vhost-device-vsock
# 0.3.0, the framework supervisor binary, and the runner Go program.
#
# Build context is the repo root so the supervisor-build stage can
# reach `supervisor/cmd/supervisor` (top-level Go module) and
# `runner/` (its own module).
#
# Build + push (manual, by a framework maintainer):
#   docker buildx build --platform linux/amd64 \
#     -f runner/Dockerfile \
#     -t ghcr.io/arklabshq/enclave-test-runner:<v> \
#     -t ghcr.io/arklabshq/enclave-test-runner:latest \
#     --push .

# --- Stage 1: vhost-device-vsock 0.3.0 ---
FROM rust:1.83-bookworm AS vsock-build
WORKDIR /src
RUN git clone --depth 1 --branch vhost-device-vsock-v0.3.0 \
      https://github.com/rust-vmm/vhost-device.git .
RUN cargo build --release -p vhost-device-vsock

# --- Stage 2: framework supervisor (Go) ---
FROM golang:1.25-bookworm AS supervisor-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /supervisor ./supervisor/cmd/supervisor

# --- Stage 3: runner binary (Go) ---
FROM golang:1.25-bookworm AS runner-build
WORKDIR /src/runner
COPY runner/go.mod runner/go.sum ./
RUN go mod download
COPY runner/*.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /runner .

# --- Stage 4: QEMU 9.2.4 (x86_64 system emulator, nitro-enclave machine) ---
FROM debian:bookworm AS qemu-build
RUN apt-get update && apt-get install -y \
      build-essential meson ninja-build pkg-config git \
      python3 python3-venv wget flex bison \
      libglib2.0-dev libpixman-1-dev libfdt-dev libcap-ng-dev \
      libslirp-dev liburing-dev \
      libcbor-dev libgnutls28-dev
RUN wget -q https://download.qemu.org/qemu-9.2.4.tar.xz && tar xf qemu-9.2.4.tar.xz
WORKDIR /qemu-9.2.4
RUN ./configure \
      --target-list=x86_64-softmmu \
      --enable-kvm \
      --enable-vhost-user \
      --enable-gnutls
RUN make -j$(nproc)
RUN make DESTDIR=/qemu-install install

# --- Stage 5: runtime image ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates procps psmisc \
      libglib2.0-0 libpixman-1-0 libfdt1 libcap-ng0 \
      libslirp0 liburing2 libcbor0.8 libgnutls30 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=vsock-build      /src/target/release/vhost-device-vsock /usr/local/bin/
COPY --from=supervisor-build /supervisor                            /usr/local/bin/
COPY --from=runner-build     /runner                                /usr/local/bin/
COPY --from=qemu-build       /qemu-install/usr/local/               /usr/local/

# The runner reads /data/image.eif (bind-mounted by docker-compose).
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/runner"]
