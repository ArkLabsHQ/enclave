{
  description = "Local enclave testing dev shell — QEMU 9.2 with nitro-enclave + vhost-device-vsock";

  inputs = {
    # Pin to nixos-25.05 for QEMU 9.2.4 — first version with -M nitro-enclave (added in 9.2).
    # Compatible with vhost-device-vsock 0.3.0's vhost-user protocol.
    # QEMU 10.x (nixos-unstable) has a vhost-user protocol mismatch with v0.3.0.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # vhost-device-vsock from rust-vmm — not yet packaged in nixpkgs.
        # Provides the vsock bridge between QEMU guest and host.
        vhost-device-vsock = pkgs.rustPlatform.buildRustPackage rec {
          pname = "vhost-device-vsock";
          version = "0.3.0";

          src = pkgs.fetchFromGitHub {
            owner = "rust-vmm";
            repo = "vhost-device";
            rev = "vhost-device-vsock-v${version}";
            hash = "sha256-g+u6WBJtizIgQwC0kkWdAcTiYCM1zMI4YBLVRU4MOrs=";
          };

          buildAndTestSubdir = "vhost-device-vsock";
          cargoLock.lockFile = "${src}/Cargo.lock";

          # Only build the vsock binary.
          cargoBuildFlags = [ "-p" "vhost-device-vsock" ];

          meta = with pkgs.lib; {
            description = "vhost-user vsock device backend (rust-vmm)";
            homepage = "https://github.com/rust-vmm/vhost-device";
            license = with licenses; [ asl20 bsd3 ];
          };
        };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            # QEMU 9.2.x with -M nitro-enclave and virtio-nsm support.
            pkgs.qemu

            # vsock bridge: connects QEMU guest vsock to host Unix sockets.
            vhost-device-vsock

            # gvproxy: outbound networking for the enclave via TAP over vsock.
            pkgs.gvproxy

            # Node.js for CDK synthesis (jsii) and cdklocal.
            pkgs.nodejs_20

            # Utilities for testing.
            pkgs.curl
            pkgs.jq
            pkgs.socat
            pkgs.awscli2
          ];

          shellHook = ''
            echo "Enclave test dev shell"
            echo "  QEMU:               $(qemu-system-x86_64 --version | head -1)"
            echo "  vhost-device-vsock:  ${vhost-device-vsock.version}"
            echo "  gvproxy:             $(gvproxy --version 2>&1 | head -1 || echo 'available')"
            echo ""
            echo "Usage:"
            echo "  ./run.sh <path-to-eif>     Run full test suite"
            echo "  ./boot-qemu.sh <path-to-eif>  Boot enclave in QEMU"
            echo "  ./smoke-test.sh            Run smoke tests against running enclave"
          '';
        };
      }
    );
}
