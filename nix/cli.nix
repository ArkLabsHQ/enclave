{ pkgs }:
pkgs.buildGoModule (finalAttrs: {
  pname = "enclave-cli";
  version = "0.1.0";
  src = ../.;
  subPackages = [ "cmd/enclave" ];
  vendorHash = "sha256-/LPCpvpa1869AaFWPQAZNOmdIFPe8ZoQqLHwPXcifcA=";
  env.GOWORK = "off";
  buildFlags = [
    "-trimpath"
  ];
  ldflags = [
    "-X main.Version=${finalAttrs.version}"
  ];
})
