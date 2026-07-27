# Test application baked into test EIFs: a tiny stdlib-only Go HTTP server
# exposing the seams the NixOS test driver needs to observe and perturb the
# enclave. Built with buildGoModule; stdlib only, so no go.sum and an empty
# vendor hash.
#
# Routes (reached through the runtime's reverse proxy on :443):
#   GET  /test/health     -> {"status":"ok"}
#   GET  /test/env/{name} -> {"name":"...","value":"..."}  (os.Getenv)
#   GET  /test/clock      -> {"unix":<sec>,"nsec":<ns>}
#   POST /test/clock      -> {"offset_seconds":N}  (bounded +/-10)
#                            sets CLOCK_REALTIME and returns before/after
#
# The derivation carries `.name`/`.version` as required by buildEif's `app`
# contract (${app}/bin/${app.name} is copied to /app/${app.name}).
# buildGoModule sets name = "${pname}-${version}"; override to just the binary
# name so buildEif's `cp ${app}/bin/${app.name}` resolves correctly.
{ pkgs }:
pkgs.buildGoModule {
  pname = "testapp";
  version = "0.1.0";
  src = ./test-app;
  vendorHash = null;
  env.CGO_ENABLED = "0";
} // {
  name = "testapp";
}
