{ pkgs }:
pkgs.buildGoModule (finalAttrs: {
  pname = "runtime";
  version = "0.1.0";
  src = ../runtime;
  subPackages = [ "cmd/runtime" ];
  vendorHash = "sha256-oSXsjIcvIXj4K758lfXXS28+4XiU3c5d8ERPNGj4TCI=";
  env.CGO_ENABLED = "0";
  buildFlags = [
    "-trimpath"
  ];
  ldflags = [
    "-X github.com/ArkLabsHQ/enclave/runtime.Version=${finalAttrs.version}"
  ];
  tags = [ "netgo" ];
})
