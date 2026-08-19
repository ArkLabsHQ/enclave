# Test-only stand-in for the production AMI (mk-enclave-ami.nix): a NixOS
# *module* (suitable for a NixOS-test node) that runs the same enclave-host
# stack — gvproxy, IMDS proxy, migration proxy, enclave-start, watchdog — via
# the shared enclave-host-module.nix, but launches the enclave with
# qemu-system-x86_64's `nitro-enclave` machine type instead of nitro-cli.
#
# Differences from production, and nothing else:
#   * launcher: vhost-device-vsock (vhost-user backend, mandatory for QEMU's
#     nitro-enclave machine) + QEMU with KVM, instead of the Nitro hypervisor.
#   * heartbeat responder on vsock:9000 (nitro-cli answers the EIF init's
#     boot heartbeat itself in production).
#   * vsock_loopback kernel module, so guest-initiated vsock connections
#     (gvproxy :1024, IMDS :8002, heartbeat :9000) reach the host's AF_VSOCK
#     loopback via vhost-device-vsock's forward-cid=1.
#   * host→enclave connections (migration control :8003) go through
#     vhost-device-vsock's forward-listen, which binds the host loopback CID,
#     so the migration-proxy dials CID 1 instead of the enclave CID.
#
# KVM is required (the enclave kernel's clock sync needs the kvm-ptp device,
# and TCG boot times are prohibitive). Test nodes must expose a nested
# /dev/kvm, e.g. `virtualisation.qemu.options = [ "-cpu host" ]`.
{
  eif,
  memoryMib ? 2048,
  cpuCount ? 2,
  enclaveCID ? 16,
  enclaveName ? "enclave",
  vhostDeviceVsock ? null,
}:
let
  runtimeDir = "vhost-vsock-${enclaveName}";
  vsockSocket = "/run/${runtimeDir}/vhost.socket";
  pidfile = "/run/${enclaveName}-qemu.pid";
  consoleLog = "/var/log/${enclaveName}-console.log";

  launcherFor = pkgs': {
    run =
      let
        script = pkgs'.writeShellScript "run-enclave-qemu" ''
          set -eu
          # Wait for the vhost-user socket (vhost-device-vsock.service).
          for _ in $(seq 1 50); do
            [ -S ${vsockSocket} ] && break
            sleep 0.2
          done
          exec ${pkgs'.qemu_kvm}/bin/qemu-system-x86_64 \
            -M nitro-enclave,vsock=c,id=${enclaveName} \
            -kernel ${eif}/image.eif \
            -m ${toString memoryMib}M \
            -smp ${toString cpuCount} \
            -enable-kvm \
            -cpu host \
            -display none \
            -chardev file,id=console,path=${consoleLog},append=on \
            -serial chardev:console \
            -no-reboot \
            -daemonize \
            -pidfile ${pidfile} \
            -chardev socket,id=c,path=${vsockSocket}
        '';
      in
      "${script}";
    alive = ''[ -s ${pidfile} ] && ${pkgs'.util-linux}/bin/kill -0 "$(cat ${pidfile})" 2>/dev/null'';
    terminate = ''{ [ -s ${pidfile} ] && ${pkgs'.util-linux}/bin/kill "$(cat ${pidfile})" 2>/dev/null; rm -f ${pidfile}; } || true'';
    path = [
      pkgs'.coreutils
      pkgs'.qemu_kvm
      pkgs'.util-linux
    ];
    requires = [
      "vhost-device-vsock.service"
      "enclave-heartbeat.service"
    ];
  };

  hostModule = import ./enclave-host-module.nix {
    inherit launcherFor;
    # vhost-device-vsock's forward-listen ports bind the host's loopback CID.
    hostToEnclaveCID = 1;
  };

  qemuModule =
    { pkgs, lib, ... }:
    let
      vhostDeviceVsockPackage =
        if vhostDeviceVsock == null then pkgs.vhost-device-vsock else vhostDeviceVsock;
    in
    {
      # Host side of AF_VSOCK loopback (CID 1) used by forward-cid/forward-listen.
      boot.kernelModules = [ "vsock_loopback" ];

      # The enclave kernel's ptp_kvm clock (which the runtime's clock sync
      # hard-requires) reads the time via KVM_HC_CLOCK_PAIRING, and KVM only
      # services that hypercall while *its own* clocksource is TSC-based.
      # nixpkgs' test-instrumentation pins guests to `clocksource=acpi_pm`,
      # so we must land after it on the cmdline: the kernel honours the last
      # clocksource= it sees. mkAfter is load-bearing, not cosmetic.
      boot.kernelParams = lib.mkAfter [
        "clocksource=tsc"
        "tsc=reliable"
      ];
      virtualisation.qemu.options = [ "-cpu host,migratable=off,+invtsc" ];

      systemd.services.vhost-device-vsock = {
        description = "vhost-user-vsock backend for the enclave QEMU VM";
        wantedBy = [ "multi-user.target" ];
        after = [ "systemd-modules-load.service" ];
        wants = [ "systemd-modules-load.service" ];
        serviceConfig = {
          Type = "simple";
          RuntimeDirectory = runtimeDir;
          # Larger queues prevent bursty forwarded connections exhausting LocalTxBuf.
          ExecStart = "${vhostDeviceVsockPackage}/bin/vhost-device-vsock --vm guest-cid=${toString enclaveCID},socket=${vsockSocket},forward-cid=1,forward-listen=8003,tx-buffer-size=65536,queue-size=1024";
          Restart = "always";
          RestartSec = 2;
        };
      };

      # The EIF's init dials vsock CID 3 port 9000 on boot, sends one byte
      # (0xB7) and expects it echoed. nitro-cli does this in production.
      systemd.services.enclave-heartbeat = {
        description = "Enclave boot heartbeat responder (vsock:9000)";
        wantedBy = [ "multi-user.target" ];
        after = [ "systemd-modules-load.service" ];
        serviceConfig = {
          Type = "simple";
          ExecStart = "${pkgs.socat}/bin/socat VSOCK-LISTEN:9000,fork EXEC:${pkgs.coreutils}/bin/cat";
          Restart = "always";
          RestartSec = 2;
        };
      };
    };
in
{
  imports = [
    hostModule
    qemuModule
  ];
}
