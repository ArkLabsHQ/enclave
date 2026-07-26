# Production AMI: NixOS system for the EC2 parent instance that hosts the
# Nitro Enclave. The enclave-host plumbing (gvproxy, IMDS proxy, migration
# proxy, watchdog) lives in enclave-host-module.nix and is shared with the
# QEMU-based test variant (mk-enclave-qemu-ami.nix); this wrapper adds the
# EC2/Nitro-specific parts: amazon image base, nitro_enclaves device,
# allocator, and the nitro-cli launcher.
{
  self,
  nixpkgs,
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

  launcherFor =
    pkgs':
    let
      nitroCli = self.packages.${pkgs'.stdenv.hostPlatform.system}.aws-nitro-enclaves-cli;
    in
    {
      run = pkgs'.lib.concatStringsSep " " [
        "${nitroCli}/bin/nitro-cli run-enclave"
        "--cpu-count ${toString cpuCount}"
        "--memory ${toString memoryMib}"
        "--eif-path ${eif}/image.eif"
        "--enclave-cid ${toString enclaveCID}"
        "--enclave-name ${enclaveName}"
      ];
      alive = ''${nitroCli}/bin/nitro-cli describe-enclaves 2>/dev/null | ${pkgs'.jq}/bin/jq -e 'any(.State == "RUNNING" and .EnclaveName == "${enclaveName}")' >/dev/null 2>&1'';
      terminate = "${nitroCli}/bin/nitro-cli terminate-enclave --enclave-name ${enclaveName} 2>/dev/null";
      path = [
        nitroCli
        pkgs'.jq
        pkgs'.gnugrep
      ];
      requires = [ "nitro-enclaves-allocator.service" ];
    };

  hostModule = import ./enclave-host-module.nix {
    inherit launcherFor;
    hostToEnclaveCID = enclaveCID;
  };

  ec2Module =
    { modulesPath, pkgs, ... }:
    let
      nitroCli = self.packages.${pkgs.stdenv.hostPlatform.system}.aws-nitro-enclaves-cli;
    in
    {
      imports = [ "${modulesPath}/virtualisation/amazon-image.nix" ];
      virtualisation.diskSize = 8 * 1024;
      services.amazon-ssm-agent.enable = true;
      i18n.defaultLocale = "en_US.UTF-8";
      i18n.supportedLocales = [ "en_US.UTF-8/UTF-8" ];
      system.stateVersion = pkgs.lib.trivial.release;

      # CONFIG_NITRO_ENCLAVES=m is part of the stock nixpkgs kernel.
      boot.kernelModules = [ "nitro_enclaves" ];

      environment.etc."nitro_enclaves/allocator.yaml".source =
        (pkgs.formats.yaml { }).generate "allocator.yaml"
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
    };
in
nixpkgs.lib.nixosSystem {
  inherit system;
  modules = [
    { nixpkgs.pkgs = pkgs; }
    hostModule
    ec2Module
  ];
}
