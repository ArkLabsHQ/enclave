{
  self,
}:
{
  eif,
  pkgs,
  memoryMib ? 4320,
  cpuCount ? 2,
  enclaveCID ? 16,
  enclaveName ? "enclave",
}:
let
  system = pkgs.stdenv.hostPlatform.system;
  nitroCli = self.packages.${system}.aws-nitro-enclaves-cli;

  runEnclaveArgs = [
    "run-enclave"
    "--cpu-count ${cpuCount}"
    "--memory ${memoryMib}"
    "--eif-path"
    "${eif}/image.eif"
    "--enclave-cid ${enclaveCID}"
    "--enclave-name ${enclaveName}"
  ];
  runEnclaveCmd = "${nitroCli}/bin/nitro-cli ${pkgs.lib.concatStringsSep " " runEnclaveArgs}";
in
pkgs.lib.nixosSystem {
  inherit system;
  modules = [
    (
      { modulesPath, pkgs, ... }:
      {
        imports = [ "${modulesPath}/virtualisation/amazon-image.nix" ];
        nixpkgs.hostPlatform = system;
        virtualisation.diskSize = 8 * 1024;
        services.amazon-ssm-agent.enable = true;
        i18n.defaultLocale = "en_US.UTF-8";
        i18n.supportedLocales = [ "en_US.UTF-8/UTF-8" ];
        system.stateVersion = pkgs.lib.trivial.release;
        boot.kernelPatches = [
          {
            name = "nitro_enclaves";
            patch = null;
            structuredExtraConfig = with pkgs.lib.kernel; {
              NITRO_ENCLAVES = module;
            };
          }
        ];
        boot.kernelModules = [ "nitro_enclaves" ];

        environment.etc."nitro_enclaves/allocator.yaml".source =
          (pkgs.formats.yaml { }).generate "gvproxy-config.yml"
            {
              memory_mib = memoryMib + 1820;
              cpu_count = cpuCount;
            };
        systemd.services.nitro-enclaves-allocator = {
          description = "Nitro Enclaves allocator";
          wantedBy = [ "multi-user.target" ];
          wants = [ "systemd-modules-load.service" ];
          after = [ "systemd-modules-load.service" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = "${nitroCli}/bin/nitro-enclaves-allocator";
          };
          environment.NITRO_CLI_INSTALL_DIR = "/";
          path = with pkgs; [
            bash
            coreutils
            gnused
            gnugrep
            util-linux
            file
          ];
        };

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
            ExecStart = "${pkgs.socat}/bin/socat TCP-LISTEN:8003,bind=127.0.0.1,fork,reuseaddr VSOCK-CONNECT:${enclaveCID}:8003";
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
            "nitro-enclaves-allocator.service"
          ];
          requires = [ "nitro-enclaves-allocator.service" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = runEnclaveCmd;
          };
          path = [ nitroCli ];
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
          path = [
            nitroCli
            pkgs.jq
            pkgs.coreutils
            pkgs.gnugrep
          ];
          script = ''
            MISSING=0
            BACKOFF=1
            while true; do
              sleep 5
              if nitro-cli describe-enclaves 2>/dev/null \
                | jq -e 'any(.State == "RUNNING" and .EnclaveName == "${enclaveName}")' >/dev/null 2>&1; then
                MISSING=0
                BACKOFF=1
                continue
              fi
              MISSING=$((MISSING + 1))
              if [ "$MISSING" -lt 12 ]; then
                continue
              fi
              nitro-cli terminate-enclave --enclave-name ${enclaveName} 2>/dev/null || true
              sleep "$BACKOFF"
              if ${runEnclaveCmd}; then
                MISSING=0
                BACKOFF=1
              else
                BACKOFF=$((BACKOFF * 2))
                if [ "$BACKOFF" -gt 30 ]; then BACKOFF=30; fi
              fi
            done
          '';
        };
      }
    )
  ];
}
