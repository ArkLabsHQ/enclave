HASHES_FILE := sdk-hashes.json

# Read cached hashes from sdk-hashes.json (if it exists).
SDK_REV        = $(shell jq -r '.rev'         $(HASHES_FILE) 2>/dev/null)
SDK_HASH       = $(shell jq -r '.hash'        $(HASHES_FILE) 2>/dev/null)
SDK_VENDOR_HASH = $(shell jq -r '.vendor_hash' $(HASHES_FILE) 2>/dev/null)

MODULE  := github.com/ArkLabsHQ/introspector-enclave

LDFLAGS := -X $(MODULE).sdkRev=$(SDK_REV) \
           -X $(MODULE).sdkHash=$(SDK_HASH) \
           -X $(MODULE).sdkVendorHash=$(SDK_VENDOR_HASH)

.PHONY: build install help lint

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

build: ## Build the enclave CLI with SDK hashes baked in
	go build -ldflags '$(LDFLAGS)' -o enclave-cli ./cmd/enclave

install: ## Install the enclave CLI to $GOPATH/bin with SDK hashes baked in
	go install -ldflags '$(LDFLAGS)' ./cmd/enclave

lint: ## Run golangci-lint on all modules (matches CI)
	golangci-lint run ./...
	cd sdk && golangci-lint run ./...
	cd mgmt && golangci-lint run ./...
	cd client && golangci-lint run ./...

.PHONY: test-cli _test-cli-lang test test-build test-run

# ── CLI tests (mirrors .github/workflows/cli.yml) ──────────────
# Requires: go, nix (with nixpkgs=channel:nixos-25.11 on NIX_PATH)
CLI_BIN    := /tmp/enclave-cli
COMMIT1    := 66c6883
COMMIT1_FULL := 66c6883d60cbc7e04224a9bc149bb182c93c9e53
COMMIT1_HASH := sha256-OhBGQoAdqjAEtR6SghBR4tbkrsjmH5I5T+U19chXHRA=
COMMIT2    := 0782325
COMMIT2_FULL := 078232572efba4f95543d0c7c84c0f47a3782955
COMMIT2_HASH := sha256-xuWFL/Lr4vi8n/A61bhyAfa+HrwJvLFrgt0rFEWBFcw=

LANGUAGES  := go nodejs rust dotnet
APP_DIR_go     := test/cli/go-app
APP_DIR_nodejs := test/cli/nodejs-app
APP_DIR_rust   := test/cli/rust-app
APP_DIR_dotnet := test/cli/dotnet-app

test-cli: ## Run CLI tests for all languages (init, setup, update)
	go build -o $(CLI_BIN) ./cmd/enclave
	@for lang in $(LANGUAGES); do \
		echo "=== CLI test: $$lang ==="; \
		$(MAKE) --no-print-directory _test-cli-lang LANG=$$lang || exit 1; \
		echo "PASS: $$lang"; echo; \
	done
	@echo "All CLI tests passed."

_test-cli-lang:
	$(eval APP_DIR := $(APP_DIR_$(LANG)))
	@set -e; \
	REPO_ROOT=$$(cd $(CURDIR) && pwd); \
	WORK=$$(mktemp -d); \
	cp -r $(APP_DIR)/. "$$WORK/"; \
	cd "$$WORK"; \
	git init -q; \
	git remote add origin https://github.com/ArkLabsHQ/introspector-enclave.git; \
	git add .; \
	git -c user.email=ci@test -c user.name=CI -c commit.gpgsign=false commit -q -m "init"; \
	echo "[test] enclave init --language $(LANG)"; \
	$(CLI_BIN) init --language $(LANG); \
	test -f enclave/enclave.yaml; \
	test -f flake.nix; \
	test -f enclave/start.sh; \
	test -f enclave/scripts/enclave_init.sh; \
	test -f enclave/tofu/modules/enclave/kms.tf; \
	grep -q '/dev/nsm' enclave/start.sh; \
	grep -q 'when    = destroy' enclave/tofu/modules/enclave/kms.tf; \
	echo "[test] enclave setup --commit $(COMMIT1)"; \
	git add .; \
	git -c user.email=ci@test -c user.name=CI -c commit.gpgsign=false commit -q -m "add enclave files"; \
	git fetch -q "$$REPO_ROOT" master; \
	sed -i 's/nix_subdir: ""/nix_subdir: "test\/cli\/$(LANG)-app"/' enclave/enclave.yaml; \
	$(CLI_BIN) setup --commit $(COMMIT1); \
	grep -q '$(COMMIT1_FULL)' enclave/enclave.yaml || { echo "FAIL: nix_rev"; exit 1; }; \
	grep -q '$(COMMIT1_HASH)' enclave/enclave.yaml || { echo "FAIL: nix_hash"; exit 1; }; \
	grep -q 'nix_owner: "ArkLabsHQ"' enclave/enclave.yaml; \
	grep -q 'nix_repo: "introspector-enclave"' enclave/enclave.yaml; \
	if [ "$(LANG)" = "go" ]; then \
		grep -q 'nix_vendor_hash: "sha256-' enclave/enclave.yaml || { echo "FAIL: nix_vendor_hash is empty"; cat enclave/enclave.yaml; exit 1; }; \
	fi; \
	echo "[test] enclave build"; \
	git add .; \
	git -c user.email=ci@test -c user.name=CI -c commit.gpgsign=false commit -q -m "pre-build commit"; \
	$(CLI_BIN) build || { echo "FAIL: enclave build"; exit 1; }; \
	test -f enclave/artifacts/image.eif || { echo "FAIL: image.eif missing"; exit 1; }; \
	test -f enclave/artifacts/pcr.json || { echo "FAIL: pcr.json missing"; exit 1; }; \
	jq -e '.PCR0' enclave/artifacts/pcr.json >/dev/null || { echo "FAIL: PCR0 missing from pcr.json"; exit 1; }; \
	test -f enclave/artifacts/enclave-mgmt || { echo "FAIL: enclave-mgmt missing"; exit 1; }; \
	test -f enclave/artifacts/gvproxy || { echo "FAIL: gvproxy missing"; exit 1; }; \
	echo "[test] build artifacts verified"; \
	echo "[test] enclave update --commit $(COMMIT2)"; \
	$(CLI_BIN) update --commit $(COMMIT2); \
	grep -q '$(COMMIT2_FULL)' enclave/enclave.yaml || { echo "FAIL: nix_rev"; exit 1; }; \
	grep -q '$(COMMIT2_HASH)' enclave/enclave.yaml || { echo "FAIL: nix_hash"; exit 1; }; \
	if [ "$(COMMIT1_HASH)" = "$(COMMIT2_HASH)" ]; then echo "ERROR: hashes should differ"; exit 1; fi; \
	rm -rf "$$WORK"

test: test-build test-run ## Build test EIFs and run integration tests

test-build:  ## Build test EIFs (v1 + v2 for migration with previousPCR0)
	cd sdk && go mod vendor
	cd test/app && SDK_LOCAL_PATH=$(CURDIR) enclave build
	cp test/app/enclave/artifacts/pcr.json /tmp/pcr-v1.json
	V1_PCR0=$$(jq -r '.PCR0' test/app/enclave/artifacts/pcr.json) && \
	sed -i 's/^version: .*/version: 0.0.2/' test/app/enclave/enclave.yaml && \
	if grep -q '^previous_pcr0:' test/app/enclave/enclave.yaml; then \
		sed -i "s/^previous_pcr0: .*/previous_pcr0: \"$$V1_PCR0\"/" test/app/enclave/enclave.yaml; \
	else \
		echo "" >> test/app/enclave/enclave.yaml; \
		echo "previous_pcr0: \"$$V1_PCR0\"" >> test/app/enclave/enclave.yaml; \
	fi
	cd test/app && SDK_LOCAL_PATH=$(CURDIR) enclave build
	cp test/app/enclave/artifacts/image.eif /tmp/image-v2.eif
	cp test/app/enclave/artifacts/pcr.json /tmp/pcr-v2.json
	sed -i 's/^version: .*/version: 0.0.1/' test/app/enclave/enclave.yaml
	sed -i '/^previous_pcr0:/d' test/app/enclave/enclave.yaml
	cd test/app && SDK_LOCAL_PATH=$(CURDIR) enclave build
	cp test/app/enclave/artifacts/pcr.json test/app/enclave/artifacts/pcr-v1.json
	cp /tmp/image-v2.eif test/app/enclave/artifacts/image-v2.eif
	cp /tmp/pcr-v2.json test/app/enclave/artifacts/pcr-v2.json

test-run: ## Run integration tests (requires test-build first)
	cd test && docker compose --profile test run --build test-runner
