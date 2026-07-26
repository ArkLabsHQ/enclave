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
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (
          system:
          f {
            inherit system;
            pkgs = import nixpkgs { inherit system; };
          }
        );
    in
    {
      packages = forAllSystems (
        { pkgs, system, ... }:
        {
          runtime = import ./nix/runtime.nix { inherit pkgs; };
          aws-nitro-enclaves-cli = import ./nix/aws-nitro-enclaves-cli.nix { inherit pkgs; };
          default = self.packages.${system}.runtime;
        }
      );

      checks = forAllSystems (
        { system, ... }:
        {
          unit-tests = self.packages.${system}.runtime;
        }
      );

      lib = {
        buildEif = import nix/build-eif.nix { inherit self aws-nitro-util; };
        mkEnclaveAmi = import nix/mk-enclave-ami.nix { inherit self; };
        mkEnclaveTofu = import nix/mk-enclave-tofu.nix { inherit tofunix; };
      };
    };
}
