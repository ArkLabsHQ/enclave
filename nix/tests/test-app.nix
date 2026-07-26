# Test application baked into test EIFs: a tiny REST server that executes
# shell scripts, built from busybox httpd + CGI (busybox is already part of
# the EIF rootfs — see nix/build-eif.nix).
#
# Endpoints (reached through the runtime's reverse proxy on :443):
#   GET  /cgi-bin/health  -> {"status":"ok"}
#   POST /cgi-bin/run     -> body is executed with /bin/sh; combined output returned
#
# The derivation carries `.name`/`.version` as required by buildEif's `app`
# contract (${app}/bin/${app.name} is copied to /app/${app.name}).
{ pkgs }:
(pkgs.writeShellScriptBin "testapp" ''
  set -eu
  # The EIF init mounts /tmp noexec; CGI scripts must live on the executable
  # rootfs alongside the app.
  WWW=/app/test-www
  /bin/busybox mkdir -p "$WWW/cgi-bin"

  /bin/busybox cat > "$WWW/cgi-bin/health" <<'EOF'
  #!/bin/busybox sh
  printf 'Content-Type: application/json\r\n\r\n'
  printf '{"status":"ok"}'
  EOF

  /bin/busybox cat > "$WWW/cgi-bin/run" <<'EOF'
  #!/bin/busybox sh
  # Execute the POSTed shell script, return combined output.
  printf 'Content-Type: text/plain\r\n\r\n'
  script=$(/bin/busybox cat)
  /bin/busybox sh -c "$script" 2>&1 || true
  EOF

  /bin/busybox chmod +x "$WWW/cgi-bin/health" "$WWW/cgi-bin/run"

  echo "testapp: serving on 127.0.0.1:''${PORT:-7074}"
  exec /bin/busybox httpd -f -v -p "127.0.0.1:''${PORT:-7074}" -h "$WWW"
'')
// {
  version = "0.1.0";
}
