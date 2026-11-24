.PHONY: test lint fmt proto

ROOT_PACKAGES := ./client/... ./cmd/enclave/...

# These targets expect go, golangci-lint, golines, gofumpt, node, and buf with
# its plugins from nix develop.

test:
	go test $(ROOT_PACKAGES)
	cd runtime && go test ./...
	cd internal/signing && go test ./...
	cd examples/proxy && npm ci --prefix ts && go test ./...

lint:
	CGO_ENABLED=0 GOOS=linux golangci-lint run $(ROOT_PACKAGES)
	cd runtime && CGO_ENABLED=0 GOOS=linux golangci-lint run ./...
	cd internal/signing && CGO_ENABLED=0 GOOS=linux golangci-lint run ./...
	cd examples/proxy && CGO_ENABLED=0 GOOS=linux golangci-lint run ./...

fmt:
	cd client && golines -w --max-len=100 .
	cd client && gofumpt -w .
	cd cmd/enclave && golines -w --max-len=100 .
	cd cmd/enclave && gofumpt -w .
	cd runtime && golines -w --max-len=100 .
	cd runtime && gofumpt -w .
	cd internal/signing && golines -w --max-len=100 .
	cd internal/signing && gofumpt -w .
	cd examples/proxy && golines -w --max-len=100 .
	cd examples/proxy && gofumpt -w .

proto:
	cd examples/proxy && buf generate
