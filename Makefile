REPO_OWNER := ArkLabsHQ
REPO_NAME  := introspector-enclave
HASHES_FILE := sdk-hashes.json
NIX_IMAGE   := nixos/nix:2.24.9

# Default REV to latest tag, or HEAD if no tags exist.
REV ?= $(shell git describe --tags --abbrev=0 2>/dev/null || git rev-parse HEAD)
# Set LOCAL=1 to use local nix instead of Docker container.
LOCAL ?=

# Read cached hashes from sdk-hashes.json (if it exists).
SDK_REV        = $(shell jq -r '.rev'         $(HASHES_FILE) 2>/dev/null)
SDK_HASH       = $(shell jq -r '.hash'        $(HASHES_FILE) 2>/dev/null)
SDK_VENDOR_HASH = $(shell jq -r '.vendor_hash' $(HASHES_FILE) 2>/dev/null)

MODULE  := github.com/ArkLabsHQ/introspector-enclave

LDFLAGS := -X $(MODULE).sdkRev=$(SDK_REV) \
           -X $(MODULE).sdkHash=$(SDK_HASH) \
           -X $(MODULE).sdkVendorHash=$(SDK_VENDOR_HASH)

.PHONY: build install sdk-hashes help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

build: ## Build the enclave CLI with SDK hashes baked in
	go build -ldflags '$(LDFLAGS)' -o enclave-cli ./cmd/enclave

install: ## Install the enclave CLI to $GOPATH/bin with SDK hashes baked in
	go install -ldflags '$(LDFLAGS)' ./cmd/enclave

sdk-hashes: ## Compute hashes, commit, tag REV (LOCAL=1 to skip Docker)
	@if [ "$(REV)" = "$$(git describe --tags --abbrev=0 2>/dev/null || git rev-parse HEAD)" ] && ! git tag -l "$(REV)" | grep -q .; then \
	  echo "Error: REV=$(REV) looks like a default — pass an explicit REV=vX.Y.Z"; exit 1; \
	fi
	@# Step 1: Compute vendor hash via a failing nix build.
	@echo "[sdk-hashes] Computing vendor hash (trial nix build)..."
	@NIX_EXPR='let pkgs = import <nixpkgs> {}; in pkgs.buildGoModule { pname = "enclave-supervisor"; version = "dev"; src = ./.; subPackages = ["cmd/enclave-supervisor"]; vendorHash = ""; doCheck = false; }' && \
	if [ -n "$(LOCAL)" ]; then \
	  OUTPUT=$$(cd sdk && nix build --impure \
	    --extra-experimental-features 'nix-command flakes' \
	    --expr "$$NIX_EXPR" 2>&1); \
	else \
	  OUTPUT=$$(docker run --rm -e NIX_PATH=nixpkgs=channel:nixos-25.05 -v "$(CURDIR):/src" -w /src/sdk $(NIX_IMAGE) \
	    sh -c "git config --global --add safe.directory /src && \
	    nix build --impure --extra-experimental-features 'nix-command flakes' \
	    --expr '$$NIX_EXPR'" 2>&1); \
	fi; \
	VENDOR_HASH=$$(echo "$$OUTPUT" | grep 'got:' | awk '{print $$2}') && \
	if [ -z "$$VENDOR_HASH" ]; then \
	  echo "Error: could not extract vendor hash from nix build output." && \
	  echo "$$OUTPUT" | tail -20; \
	  exit 1; \
	fi && \
	echo "  Vendor hash: $$VENDOR_HASH" && \
	echo "$$VENDOR_HASH" > /tmp/sdk-vendor-hash
	@# Step 2: Compute source hash from HEAD (sdk-hashes.json excluded via .gitattributes).
	@echo "[sdk-hashes] Computing source hash..."
	@TMPDIR=$$(mktemp -d) && \
	git archive --format=tar.gz --prefix=source/ HEAD | tar xz -C "$$TMPDIR" && \
	if [ -n "$(LOCAL)" ]; then \
	  SOURCE_HASH=$$(nix hash path "$$TMPDIR/source"); \
	else \
	  SOURCE_HASH=$$(docker run --rm -v "$$TMPDIR:/work:ro" $(NIX_IMAGE) \
	    nix --extra-experimental-features nix-command hash path /work/source); \
	fi && \
	rm -rf "$$TMPDIR" && \
	echo "  Source hash: $$SOURCE_HASH" && \
	VENDOR_HASH=$$(cat /tmp/sdk-vendor-hash) && \
	echo "{\"rev\":\"$(REV)\",\"hash\":\"$$SOURCE_HASH\",\"vendor_hash\":\"$$VENDOR_HASH\"}" | jq '.' > $(HASHES_FILE) && \
	rm -f /tmp/sdk-vendor-hash
	@# Step 3: Commit and tag.
	@echo "[sdk-hashes] Committing and tagging..."
	@git add $(HASHES_FILE) && \
	git commit -m "sdk hashes for $(REV)" && \
	if git tag -l "$(REV)" | grep -q .; then \
	  git tag -d "$(REV)" > /dev/null; \
	fi && \
	git tag "$(REV)" && \
	echo "" && \
	echo "[sdk-hashes] Done." && \
	echo "  Push with: git push && git push --tags"
