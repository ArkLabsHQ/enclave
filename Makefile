.PHONY: test lint fmt

ROOT_PACKAGES := ./client/... ./cmd/enclave/...

# These targets expect go, golangci-lint, golines, and gofumpt from nix develop.

test:
	go test $(ROOT_PACKAGES)
	cd runtime && go test ./...

lint:
	golangci-lint run $(ROOT_PACKAGES)
	cd runtime && golangci-lint run ./...

fmt:
	cd client && golines -w --max-len=100 .
	cd client && gofumpt -w .
	cd cmd/enclave && golines -w --max-len=100 .
	cd cmd/enclave && gofumpt -w .
	cd runtime && golines -w --max-len=100 .
	cd runtime && gofumpt -w .
