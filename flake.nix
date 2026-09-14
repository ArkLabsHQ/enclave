{
  description = "Simple AWS Nitro Enclave Runtime";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    aws-nitro-util.url = "github:monzo/aws-nitro-util";
  };

  outputs =
    {
      nixpkgs,
      aws-nitro-util,
      self,
    }:
    let
      enclaveSystems = [
        "x86_64-linux"
      ];

      allSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      forSystems =
        systems: f:
        nixpkgs.lib.genAttrs systems (
          system:
          f {
            inherit system;
            pkgs = import nixpkgs { inherit system; };
          }
        );
    in
    {
      packages =
        nixpkgs.lib.recursiveUpdate
          (forSystems enclaveSystems (
            { pkgs, system, ... }:
            {
              runtime = pkgs.buildGoModule (finalAttrs: {
                pname = "runtime";
                version = "0.1.0";
                src = ./runtime;
                subPackages = [ "cmd/runtime" ];
                vendorHash = "sha256-npi7g0YtHbxtOeYHOQ8aExneTUU65jsWYCpFrS51hxU=";
                env.CGO_ENABLED = "0";
                buildFlags = [
                  "-trimpath"
                ];
                ldflags = [
                  "-X github.com/ArkLabsHQ/enclave/runtime.Version=${finalAttrs.version}"
                ];
                tags = [ "netgo" ];
              });
            }
          ))
          (
            forSystems allSystems (
              { pkgs, system, ... }:
              {
                cli = pkgs.buildGoModule (finalAttrs: {
                  pname = "enclave-cli";
                  version = "0.1.0";
                  src = ./.;
                  subPackages = [ "cmd/enclave" ];
                  vendorHash = "sha256-UpYTFzOGPnETUaftmz0SwC/gDKbeUWj5zeYULCAsyf8=";
                  env.GOWORK = "off";
                  buildFlags = [
                    "-trimpath"
                  ];
                  ldflags = [
                    "-X main.Version=${finalAttrs.version}"
                  ];

                  # subPackages installs cmd/enclave as bin/enclave, but nix run derives
                  # the program name from pname and would look for bin/enclave-cli.
                  meta.mainProgram = "enclave";
                });
                default = self.packages.${system}.cli;
              }
            )
          );

      devShells = forSystems allSystems (
        { pkgs, system, ... }:
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.go
              pkgs.gofumpt
              pkgs.golangci-lint
              pkgs.golangci-lint-langserver
              pkgs.golines
              pkgs.gopls
            ];
          };
        }
      );

      checks = forSystems enclaveSystems (
        { pkgs, system, ... }:
        import ./nix/tests {
          inherit
            pkgs
            system
            self
            ;
        }
      );

      lib = {
        buildEif = import ./nix/build-eif.nix { inherit self aws-nitro-util; };
      };
    };
}
