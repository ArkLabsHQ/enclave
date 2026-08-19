{
  description = "Simple AWS Nitro Enclave Runtime";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    aws-nitro-util.url = "github:monzo/aws-nitro-util";
    tofunix.url = "gitlab:technofab/tofunix?dir=lib";
  };

  outputs =
    {
      nixpkgs,
      aws-nitro-util,
      tofunix,
      self,
    }:
    let
      enclaveSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      allSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
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
              runtime = import ./nix/runtime.nix { inherit pkgs; };
              aws-nitro-enclaves-cli = import ./nix/aws-nitro-enclaves-cli.nix { inherit pkgs; };
            }
          ))
          (
            forSystems allSystems (
              { pkgs, system, ... }:
              {
                cli = import ./nix/cli.nix { inherit pkgs; };
                default = self.packages.${system}.cli;
              }
            )
          );

      devShells = forSystems allSystems (
        { pkgs, system, ... }:
        {
          default = import ./nix/shell.nix { inherit pkgs; };
        }
      );

      checks = forSystems enclaveSystems (
        { pkgs, system, ... }:
        import ./nix/tests {
          inherit
            pkgs
            system
            self
            aws-nitro-util
            ;
        }
      );

      templates.default = {
        path = ./nix/template;
        description = "Downstream App Template";
      };

      lib = {
        buildEif = import ./nix/build-eif.nix { inherit self aws-nitro-util; };
        mkEnclaveAmi = import ./nix/mk-enclave-ami.nix { inherit self nixpkgs; };
        mkEnclaveQemuAmi = import ./nix/mk-enclave-qemu-ami.nix;
        mkEnclaveTofu = import ./nix/mk-enclave-tofu.nix { inherit tofunix; };
      };
    };
}
