{ pkgs }:
pkgs.buildGoModule {
  pname = "testapp";
  version = "0.1.0";
  src = ./test-app;
  vendorHash = null;
  env.CGO_ENABLED = "0";
}
