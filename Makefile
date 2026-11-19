.PHONY: test lint fmt

ROOT_PACKAGES := ./client/... ./cmd/enclave/...

# These targets expect go, golangci-lint, golines, and gofumpt from nix develop.

test:
	go test $(ROOT_PACKAGES)
	cd runtime && go test ./...
	cd internal/migration && go test ./...
	cd internal/signing && go test ./...

lint:
	CGO_ENABLED=0 GOOS=linux golangci-lint run $(ROOT_PACKAGES)
	cd runtime && CGO_ENABLED=0 GOOS=linux golangci-lint run ./...
	cd internal/migration && CGO_ENABLED=0 GOOS=linux golangci-lint run ./...
	cd internal/signing && CGO_ENABLED=0 GOOS=linux golangci-lint run ./...

fmt:
	cd client && golines -w --max-len=100 .
	cd client && gofumpt -w .
	cd cmd/enclave && golines -w --max-len=100 .
	cd cmd/enclave && gofumpt -w .
	cd runtime && golines -w --max-len=100 .
	cd runtime && gofumpt -w .
	cd internal/migration && golines -w --max-len=100 .
	cd internal/migration && gofumpt -w .
	cd internal/signing && golines -w --max-len=100 .
	cd internal/signing && gofumpt -w .
