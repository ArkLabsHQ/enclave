# Shared enclave-host NixOS module: everything an instance runs *around* the
# enclave, independent of how the enclave VM itself is launched.
#
# Consumed by:
#   - nix/mk-enclave-ami.nix       (production: nitro-cli on EC2)
#   - nix/mk-enclave-qemu-ami.nix  (tests: qemu-system-x86_64 + vhost-device-vsock)
#
# The launcher interface abstracts the only real difference between the two:
#   launcherFor :: pkgs -> {
#     run       : command that starts the enclave VM and returns (async);
#     alive     : command that exits 0 iff the enclave VM is running;
#     terminate : command that kills the enclave VM (may fail if not running);
#     path      : packages for the watchdog unit's PATH;
#     requires  : extra systemd units enclave-start depends on;
#   }
{
  launcherFor,
  # CID the host uses to reach the enclave's vsock listeners. This is the
  # enclave CID in production and CID 1 for vhost-device-vsock forwarding.
  hostToEnclaveCID,
}:
{ pkgs, ... }:
let
  launcher = launcherFor pkgs;
in
{
  environment.etc."gvproxy/config.yml".source =
    (pkgs.formats.yaml { }).generate "gvproxy-config.yml"
      {
        stack.forwards = {
          ":443" = "192.168.127.2:443";
        };
      };

  # gvproxy: L2 vsock network on vsock:1024. The enclave's
  # nitriding daemon dials this on boot for TLS :443 egress.
  systemd.services.gvproxy = {
    description = "gvproxy L2 vsock network for enclave";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${pkgs.gvproxy}/bin/gvproxy --listen vsock://:1024 --config /etc/gvproxy/config.yml";
      Restart = "always";
      RestartSec = 5;
    };
  };

  # IMDS proxy: vsock:8002 → 169.254.169.254:80. The enclave's
  # viproxy dials this for AWS credentials.
  systemd.services.imds-proxy = {
    description = "IMDS proxy (vsock:8002 → 169.254.169.254:80)";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${pkgs.socat}/bin/socat VSOCK-LISTEN:8002,fork TCP:169.254.169.254:80";
      Restart = "always";
      RestartSec = 5;
    };
  };

  # Migration control proxy: localhost:8003 → enclave vsock:8003.
  # Operators SSM-forward 8003 and curl /request-migration |
  # /finalise-migration directly on the enclave.
  systemd.services.migration-proxy = {
    description = "Migration control proxy (localhost:8003 → enclave vsock:8003)";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${pkgs.socat}/bin/socat TCP-LISTEN:8003,bind=127.0.0.1,fork,reuseaddr VSOCK-CONNECT:${toString hostToEnclaveCID}:8003";
      Restart = "always";
      RestartSec = 5;
    };
  };

  systemd.services.enclave-start = {
    description = "Launch enclave VM";
    wantedBy = [ "multi-user.target" ];
    after = [
      "gvproxy.service"
      "imds-proxy.service"
    ] ++ launcher.requires;
    requires = launcher.requires;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = launcher.run;
    };
    path = launcher.path;
  };

  systemd.services.enclave-watchdog = {
    description = "Enclave VM watchdog (auto-restart on death)";
    wantedBy = [ "multi-user.target" ];
    after = [ "enclave-start.service" ];
    requires = [ "enclave-start.service" ];
    serviceConfig = {
      Type = "simple";
      Restart = "always";
      RestartSec = 5;
    };
    path = launcher.path ++ [
      pkgs.coreutils
    ];
    script = ''
      MISSING=0
      BACKOFF=1
      while true; do
        sleep 5
        if ${launcher.alive}; then
          MISSING=0
          BACKOFF=1
          continue
        fi
        MISSING=$((MISSING + 1))
        if [ "$MISSING" -lt 12 ]; then
          continue
        fi
        echo "enclave watchdog: enclave missing after $MISSING checks; attempting restart"
        ${launcher.terminate} || true
        sleep "$BACKOFF"
        if ${launcher.run}; then
          echo "enclave watchdog: restart command succeeded"
          MISSING=0
          BACKOFF=1
        else
          BACKOFF=$((BACKOFF * 2))
          if [ "$BACKOFF" -gt 30 ]; then BACKOFF=30; fi
          echo "enclave watchdog: restart command failed; retrying with ''${BACKOFF}s backoff"
        fi
      done
    '';
  };
}
