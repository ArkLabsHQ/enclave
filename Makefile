HASHES_FILE := sdk-hashes.json

# Read cached hashes from sdk-hashes.json (if it exists).
SDK_REV        = $(shell jq -r '.rev'         $(HASHES_FILE) 2>/dev/null)
SDK_HASH       = $(shell jq -r '.hash'        $(HASHES_FILE) 2>/dev/null)
SDK_VENDOR_HASH = $(shell jq -r '.vendor_hash' $(HASHES_FILE) 2>/dev/null)

MODULE  := github.com/ArkLabsHQ/introspector-enclave

LDFLAGS := -X $(MODULE).sdkRev=$(SDK_REV) \
           -X $(MODULE).sdkHash=$(SDK_HASH) \
           -X $(MODULE).sdkVendorHash=$(SDK_VENDOR_HASH)

.PHONY: build install help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

build: ## Build the enclave CLI with SDK hashes baked in
	go build -ldflags '$(LDFLAGS)' -o enclave-cli ./cmd/enclave

install: ## Install the enclave CLI to $GOPATH/bin with SDK hashes baked in
	go install -ldflags '$(LDFLAGS)' ./cmd/enclave

.PHONY: test test-build test-run

test: test-build test-run ## Build test EIFs and run integration tests

test-build:  ## Build test EIFs (v1 + v2 for migration)
	cd test/app && enclave build --local
	cd test/app && sed -i 's/^version: .*/version: 0.0.2/' enclave/enclave.yaml
	cd test/app && enclave build --local
	cp test/app/enclave/artifacts/image.eif test/app/enclave/artifacts/image-v2.eif
	cd test/app && sed -i 's/^version: .*/version: 0.0.1/' enclave/enclave.yaml
	cd test/app && enclave build --local

test-run: ## Run integration tests (requires test-build first)
	cd test && docker compose --profile test run --build test-runner
