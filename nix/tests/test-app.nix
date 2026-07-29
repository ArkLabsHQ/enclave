# buildEif copies `${app}/bin/${app.name}`; override buildGoModule's versioned
# name so it resolves to the installed binary.
{ pkgs }:
pkgs.buildGoModule {
  pname = "testapp";
  version = "0.1.0";
  src = ./test-app;
  vendorHash = null;
  env.CGO_ENABLED = "0";
}
// {
  name = "testapp";
}
