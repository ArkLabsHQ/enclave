{ pkgs }:
pkgs.mkShell {
  packages = [
    pkgs.go
    pkgs.gofumpt
    pkgs.golangci-lint
    pkgs.golangci-lint-langserver
    pkgs.golines
    pkgs.gopls
  ];
}
