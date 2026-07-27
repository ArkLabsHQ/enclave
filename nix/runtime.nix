{ pkgs }:
pkgs.buildGoModule (finalAttrs: {
  pname = "runtime";
  version = "0.1.0";
  src = ../runtime;
  subPackages = [ "cmd/runtime" ];
  vendorHash = "sha256-8bNEo1h22hmnzttU49QzHQslt/WnrDqTf1LRgwd1eN4=";
  env.CGO_ENABLED = "0";
  buildFlags = [
    "-trimpath"
  ];
  ldflags = [
    "-X github.com/ArkLabsHQ/enclave/runtime.Version=${finalAttrs.version}"
  ];
  tags = [ "netgo" ];
})
