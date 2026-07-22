HASHES_FILE := cli/runtime-hashes.json

# Read cached hashes from runtime-hashes.json (if it exists).
RUNTIME_REV        = $(shell jq -r '.rev'         $(HASHES_FILE) 2>/dev/null)
RUNTIME_HASH       = $(shell jq -r '.hash'        $(HASHES_FILE) 2>/dev/null)
RUNTIME_VENDOR_HASH = $(shell jq -r '.vendor_hash' $(HASHES_FILE) 2>/dev/null)

MODULE  := github.com/ArkLabsHQ/introspector-enclave

LDFLAGS := -X $(MODULE)/cli.runtimeRev=$(RUNTIME_REV) \
           -X $(MODULE)/cli.runtimeHash=$(RUNTIME_HASH) \
           -X $(MODULE)/cli.runtimeVendorHash=$(RUNTIME_VENDOR_HASH)

.PHONY: build install help lint

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

build: ## Build the enclave CLI with runtime hashes baked in
	go build -ldflags '$(LDFLAGS)' -o enclave-cli ./cli/cmd/enclave

install: ## Install the enclave CLI to $GOPATH/bin with runtime hashes baked in
	go install -ldflags '$(LDFLAGS)' ./cli/cmd/enclave

lint: ## Run golangci-lint on all modules (matches CI)
	golangci-lint run ./...
	cd runtime && golangci-lint run ./...
	cd supervisor && golangci-lint run ./...
	cd client && golangci-lint run ./...

.PHONY: test test-build test-run test-rebuild test-acme

test: test-build test-run ## Build test EIFs and run integration tests

test-build:  ## Build v1/v2/v3/v4 migration fixtures (v4 has the wrong app name for rollback)
	cd runtime && go mod vendor
	cd test/app && go mod vendor
	cp test/app/enclave/enclave.yaml /tmp/enclave.yaml.original
	# Build v1 once and stash; re-using the same artifact for the final v1 copy
	# keeps v2's baked predecessor PCR0 consistent with the running v1.
	cd test/app && RUNTIME_LOCAL_PATH=$(CURDIR) SUPERVISOR_LOCAL_PATH=$(CURDIR) APP_LOCAL_PATH=$(CURDIR)/test/app /tmp/enclave build
	cp test/app/.enclave/artifacts/image.eif /tmp/image-v1.eif
	cp test/app/.enclave/artifacts/pcr.json /tmp/pcr-v1.json
	V1_PCR0=$$(jq -r '.PCR0' /tmp/pcr-v1.json) && \
	sed -i 's/^version: .*/version: 0.0.2/' test/app/enclave/enclave.yaml && \
	sed -i 's/^migration_cooldown: .*/migration_cooldown: "0s"/' test/app/enclave/enclave.yaml && \
	if grep -q '^previous_pcr0:' test/app/enclave/enclave.yaml; then \
		sed -i "s/^previous_pcr0: .*/previous_pcr0: \"$$V1_PCR0\"/" test/app/enclave/enclave.yaml; \
	else \
		echo "" >> test/app/enclave/enclave.yaml; \
		echo "previous_pcr0: \"$$V1_PCR0\"" >> test/app/enclave/enclave.yaml; \
	fi
	cd test/app && RUNTIME_LOCAL_PATH=$(CURDIR) SUPERVISOR_LOCAL_PATH=$(CURDIR) APP_LOCAL_PATH=$(CURDIR)/test/app /tmp/enclave build
	cp test/app/.enclave/artifacts/image.eif /tmp/image-v2.eif
	cp test/app/.enclave/artifacts/pcr.json /tmp/pcr-v2.json
	# v3: healthy successor with zero cooldown.
	V2_PCR0=$$(jq -r '.PCR0' /tmp/pcr-v2.json) && \
	sed -i 's/^version: .*/version: 0.0.3/' test/app/enclave/enclave.yaml && \
	sed -i "s|^previous_pcr0: .*|previous_pcr0: \"$$V2_PCR0\"|" test/app/enclave/enclave.yaml
	cd test/app && RUNTIME_LOCAL_PATH=$(CURDIR) SUPERVISOR_LOCAL_PATH=$(CURDIR) APP_LOCAL_PATH=$(CURDIR)/test/app /tmp/enclave build
	cp test/app/.enclave/artifacts/image.eif /tmp/image-v3.eif
	cp test/app/.enclave/artifacts/pcr.json /tmp/pcr-v3.json
	# v4: wrong app name -> Init/readiness failure -> supervisor rollback to v3.
	V3_PCR0=$$(jq -r '.PCR0' /tmp/pcr-v3.json) && \
	sed -i 's/^version: .*/version: 0.0.4/' test/app/enclave/enclave.yaml && \
	sed -i "s|^previous_pcr0: .*|previous_pcr0: \"$$V3_PCR0\"|" test/app/enclave/enclave.yaml && \
	sed -i 's|^name: my-app\b|name: my-app-wrong|' test/app/enclave/enclave.yaml
	cd test/app && RUNTIME_LOCAL_PATH=$(CURDIR) SUPERVISOR_LOCAL_PATH=$(CURDIR) APP_LOCAL_PATH=$(CURDIR)/test/app /tmp/enclave build
	cp test/app/.enclave/artifacts/image.eif /tmp/image-v4.eif
	cp test/app/.enclave/artifacts/pcr.json /tmp/pcr-v4.json
	cp /tmp/enclave.yaml.original test/app/enclave/enclave.yaml
	cp /tmp/image-v1.eif test/app/.enclave/artifacts/image.eif
	cp /tmp/pcr-v1.json test/app/.enclave/artifacts/pcr.json
	cp /tmp/image-v1.eif test/app/.enclave/artifacts/image-v1.eif
	cp /tmp/pcr-v1.json test/app/.enclave/artifacts/pcr-v1.json
	cp /tmp/image-v2.eif test/app/.enclave/artifacts/image-v2.eif
	cp /tmp/pcr-v2.json test/app/.enclave/artifacts/pcr-v2.json
	cp /tmp/image-v3.eif test/app/.enclave/artifacts/image-v3.eif
	cp /tmp/pcr-v3.json test/app/.enclave/artifacts/pcr-v3.json
	cp /tmp/image-v4.eif test/app/.enclave/artifacts/image-v4.eif
	cp /tmp/pcr-v4.json test/app/.enclave/artifacts/pcr-v4.json

test-run: ## Run integration tests (uses last-built test-runner image)
	cd test && docker compose --profile test down -v
	cd test && docker compose --profile test run test-runner

test-rebuild: ## Rebuild test-runner image and run integration tests
	cd test && docker compose --profile test down -v
	cd test && docker compose --profile test run --build test-runner

test-acme: test-build ## Build the test EIF and run the end-to-end ACME (Pebble) test
	bash test/pebble/gen-certs.sh
	cd test && docker compose --profile acme down -v
	cd test && docker compose --profile acme run --build acme-runner

.PHONY: test-build-docker test-docker
test-build-docker: ## Run test-build inside a linux/amd64 container (for macOS/ARM hosts)
	docker build --platform=linux/amd64 -t introspector-enclave-builder .
	docker run --rm --platform=linux/amd64 \
	  -e HOST_UID=$(shell id -u) \
	  -e HOST_GID=$(shell id -g) \
	  -v "$(CURDIR):/workspace" \
	  -w /workspace \
	  introspector-enclave-builder

test-docker: test-build-docker test-run ## Build and run tests in containers (test-run needs vsock_loopback — Linux hosts only)
