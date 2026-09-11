# Test-only Nitro host. Production provisioning lives outside this repository.
{ self }:
instances:
{ pkgs, lib, ... }:
let
  defaults = {
    cid = 1024;
    publicPort = 443;
    controlPort = 8003;
    autoStart = true;
  };
  slots = lib.mapAttrsToList (name: value: defaults // value // { inherit name; }) instances;
  cids = map (slot: slot.cid) slots;
  tcpPorts = lib.concatMap (slot: [
    slot.publicPort
    slot.controlPort
  ]) slots;
  qemu = pkgs.qemu_test.override { brlttySupport = false; };
  # v0.3.0's UDS backend filters destinations against VSOCK_HOST_CID=2.
  # Nitro uses 3. Adapt only this test backend; keep the EIF's production CID.
  # Protocol: vhost-device-vsock/README.md at tag vhost-device-vsock-v0.3.0.
  backend = pkgs.vhost-device-vsock.overrideAttrs (old: {
    postPatch =
      (old.postPatch or "")
      + ''
        substituteInPlace vhost-device-vsock/src/vhu_vsock.rs \
          --replace-fail 'const VSOCK_HOST_CID: u64 = 2;' 'const VSOCK_HOST_CID: u64 = 3;'
        # The upstream server unit test binds host port 9000, which may already
        # be occupied on a KVM builder. Ask the kernel for an unused test port.
        substituteInPlace vhost-device-vsock/src/main.rs \
          --replace-fail 'listen_ports: vec![9000],' 'listen_ports: vec![u32::MAX],'
      '';
  });
  controlConnect = pkgs.writeScript "enclave-control-connect" ''
    #!${pkgs.python3}/bin/python3
    import os
    import socket
    import sys

    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    peer.settimeout(5)
    peer.connect(sys.argv[1])
    peer.sendall(b"CONNECT 8003\n")
    # Read the acknowledgement unbuffered so HTTP bytes stay in the socket.
    reply = peer.makefile("rb", buffering=0).readline(64)
    if reply != b"OK 8003\n":
        raise RuntimeError(f"unexpected control handshake: {reply!r}")
    peer.settimeout(None)
    peer.set_inheritable(True)
    os.execv("${pkgs.socat}/bin/socat", ["socat", "STDIO", f"FD:{peer.fileno()}"])
  '';
  instanceModule =
    slot:
    let
      # Preserve the original single-enclave test's unit and diagnostic paths.
      suffix = lib.optionalString (slot.name != "enclave") "-${slot.name}";
      runtimeDir = "vhost-vsock-enclave${suffix}";
      vsockSocket = "/run/${runtimeDir}/vhost.socket";
      udsPath = "/run/${runtimeDir}/guest.socket";
      pidfile = "/run/enclave${suffix}-qemu.pid";
      consoleLog = "/var/log/enclave${suffix}-console.log";
      service = name: "${name}${suffix}.service";
      ports = [
        slot.cid
        8002
        9000
      ];
      bridgeName = port: "vsock-bridge${suffix}-${toString port}";
      runEnclave = pkgs.writeShellScript "run-enclave${suffix}-qemu" ''
        set -eu
        for socket in ${vsockSocket} ${
          lib.concatMapStringsSep " " (port: "${udsPath}_${toString port}") ports
        }; do
          for _ in $(seq 1 50); do
            [ -S "$socket" ] && break
            sleep 0.2
          done
          test -S "$socket"
        done
        exec ${qemu}/bin/qemu-system-x86_64 \
          -M nitro-enclave,vsock=c,id=${slot.name} \
          -kernel ${slot.eif}/image.eif \
          -m 2048M -smp 2 \
          -enable-kvm -cpu host -display none \
          -chardev file,id=console,path=${consoleLog},append=on \
          -serial chardev:console -no-reboot -daemonize -pidfile ${pidfile} \
          -chardev socket,id=c,path=${vsockSocket}
      '';
    in
    {
      environment.etc."gvproxy${suffix}/config.yml".source =
        (pkgs.formats.yaml { }).generate "gvproxy${suffix}-config.yml"
          {
            stack.forwards."0.0.0.0:${toString slot.publicPort}" = "192.168.127.2:443";
          };
      systemd.services =
        {
          "vhost-device-vsock${suffix}" = {
            description = "vhost-user-vsock backend for ${slot.name}";
            wantedBy = [ "multi-user.target" ];
            after = [ "systemd-modules-load.service" ];
            wants = [ "systemd-modules-load.service" ];
            serviceConfig = {
              RuntimeDirectory = runtimeDir;
              ExecStart = "${backend}/bin/vhost-device-vsock --vm guest-cid=${toString slot.cid},socket=${vsockSocket},uds-path=${udsPath},tx-buffer-size=65536,queue-size=1024";
              Restart = "always";
              RestartSec = 2;
            };
          };
          "gvproxy${suffix}" = {
            description = "gvproxy L2 vsock network for ${slot.name}";
            wantedBy = [ "multi-user.target" ];
            after = [ "network-online.target" ];
            wants = [ "network-online.target" ];
            serviceConfig = {
              ExecStart = "${pkgs.gvproxy}/bin/gvproxy --listen vsock://:${toString slot.cid} --config /etc/gvproxy${suffix}/config.yml";
              Restart = "always";
              RestartSec = 5;
            };
          };
          "migration-proxy${suffix}" = {
            description = "Operator control bridge for ${slot.name}";
            wantedBy = [ "multi-user.target" ];
            after = [ (service "vhost-device-vsock") ];
            requires = [ (service "vhost-device-vsock") ];
            serviceConfig = {
              ExecStart = "${pkgs.socat}/bin/socat TCP4-LISTEN:${toString slot.controlPort},bind=127.0.0.1,fork,reuseaddr EXEC:'${controlConnect} ${udsPath}'";
              Restart = "always";
              RestartSec = 2;
            };
          };
          "enclave-start${suffix}" = {
            description = "Launch enclave ${slot.name}";
            wantedBy = lib.optional slot.autoStart "multi-user.target";
            after = [
              (service "gvproxy")
              (service "vhost-device-vsock")
              "imds-proxy.service"
              "mock-imds-forward.service"
              "enclave-heartbeat.service"
            ] ++ map (port: "${bridgeName port}.service") ports;
            requires = [
              (service "vhost-device-vsock")
              "imds-proxy.service"
              "mock-imds-forward.service"
              "enclave-heartbeat.service"
            ] ++ map (port: "${bridgeName port}.service") ports;
            wants = [ (service "gvproxy") ];
            serviceConfig = {
              Type = "forking";
              PIDFile = pidfile;
              ExecStart = runEnclave;
              # systemd owns this QEMU's cgroup: stop/restart cannot kill its peer.
              TimeoutStopSec = 15;
            };
            path = [ pkgs.coreutils ];
          };
        }
        // builtins.listToAttrs (
          map (port: {
            name = bridgeName port;
            value = {
              description = "${slot.name} guest-to-host vsock ${toString port}";
              wantedBy = [ "multi-user.target" ];
              after = [ (service "vhost-device-vsock") ];
              requires = [ (service "vhost-device-vsock") ];
              serviceConfig = {
                ExecStart = "${pkgs.socat}/bin/socat UNIX-LISTEN:${udsPath}_${toString port},fork,unlink-early VSOCK-CONNECT:1:${toString port}";
                Restart = "always";
                RestartSec = 2;
              };
            };
          }) ports
        );
    };
in
assert lib.assertMsg (slots != [ ]) "enclave host requires at least one instance";
assert lib.assertMsg (lib.all (
  slot: builtins.match "[a-zA-Z0-9_-]+" slot.name != null
) slots) "invalid enclave instance name";
assert lib.assertMsg (lib.length (lib.unique cids) == lib.length cids) "duplicate enclave CIDs";
assert lib.assertMsg (lib.all (
  cid:
  builtins.isInt cid
  && cid > 3
  && cid < 4294967295
  && !(builtins.elem cid [
    8002
    9000
  ])
) cids) "reserved enclave CID or shared host vsock port";
assert lib.assertMsg (lib.all (
  port: builtins.isInt port && port > 0 && port <= 65535
) tcpPorts) "invalid host TCP port";
assert lib.assertMsg (
  lib.length (lib.unique tcpPorts) == lib.length tcpPorts
) "overlapping enclave host TCP bindings";
{
  imports = map instanceModule slots;
  documentation.enable = false;
  boot.enableContainers = false;
  system.tools.nixos-rebuild.enable = false;
  system.tools.nixos-generate-config.enable = false;
  boot.loader.grub.enable = lib.mkForce false;

  # 5 GiB for two 2 GiB enclaves, 3 GiB for the original single-enclave nodes.
  virtualisation.memorySize = 1024 + 2048 * lib.length slots;
  virtualisation.cores = 2 * lib.length slots;
  virtualisation.qemu.options = [ "-cpu host,migratable=off,+invtsc" ];
  boot.kernelModules = [ "vsock_loopback" ];
  boot.kernelParams = lib.mkAfter [
    "clocksource=tsc"
    "tsc=reliable"
  ];
  environment.systemPackages = [
    pkgs.curl
    pkgs.jq
    pkgs.openssl
    self.packages.${pkgs.stdenv.hostPlatform.system}.cli
  ];
  networking.firewall.allowedTCPPorts = map (slot: slot.publicPort) slots;

  # Shared host services fork per connection, including simultaneous guest boots.
  systemd.services.enclave-heartbeat = {
    wantedBy = [ "multi-user.target" ];
    after = [ "systemd-modules-load.service" ];
    serviceConfig = {
      ExecStart = "${pkgs.socat}/bin/socat VSOCK-LISTEN:9000,fork EXEC:${pkgs.coreutils}/bin/cat";
      Restart = "always";
      RestartSec = 2;
    };
  };
  systemd.services.imds-proxy = {
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.socat}/bin/socat VSOCK-LISTEN:8002,fork TCP:169.254.169.254:80";
      Restart = "always";
      RestartSec = 5;
    };
  };
  systemd.services.mock-imds-forward = {
    wantedBy = [ "multi-user.target" ];
    wants = [ "network-online.target" ];
    after = [ "network-online.target" ];
    serviceConfig = {
      ExecStartPre = "${pkgs.iproute2}/bin/ip address replace 169.254.169.254/32 dev lo";
      ExecStart = "${pkgs.socat}/bin/socat TCP4-LISTEN:80,bind=169.254.169.254,reuseaddr,fork TCP4:aws:1338";
      Restart = "on-failure";
    };
  };
}
