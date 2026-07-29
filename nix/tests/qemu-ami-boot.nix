# Boot the hardware-dependent EIF stages (NSM, PTP, and vsock) under QEMU.
# AWS is intentionally absent; failure later at SSM is expected.
{
  pkgs,
  self,
  eif,
}:
pkgs.testers.runNixOSTest {
  name = "qemu-ami-boot";

  nodes.machine =
    { ... }:
    {
      imports = [ (self.lib.mkEnclaveQemuAmi { inherit eif; }) ];
      virtualisation.memorySize = 4096;
      virtualisation.cores = 2;
    };

  testScript = ''
    machine.start()
    machine.wait_for_unit("vhost-device-vsock.service")
    machine.wait_for_unit("enclave-heartbeat.service")
    machine.wait_for_unit("gvproxy.service")

    # Nested KVM is a hard requirement (kvm-ptp clock, boot speed).
    machine.wait_until_succeeds("test -e /dev/kvm", timeout=60)

    machine.wait_for_unit("enclave-start.service")

    # QEMU stays alive (pidfile written by -daemonize).
    machine.wait_until_succeeds("test -s /run/enclave-qemu.pid", timeout=120)
    machine.succeed("kill -0 $(cat /run/enclave-qemu.pid)")

    # Guest console shows the runtime reaching clock sync over kvm-ptp —
    # proof that the EIF booted, /dev/nsm init ran, and /dev/ptp0 exists.
    try:
        machine.wait_until_succeeds(
            "grep -q 'clock sync: initial hard-step to hypervisor PTP completed' /var/log/enclave-console.log",
            timeout=300,
        )
    except Exception:
        print("=== diagnostics ===")
        print(machine.execute("ls -la /var/log/ /run/vhost-vsock-enclave/ 2>&1")[1])
        print(machine.execute("wc -c /var/log/enclave-console.log; tail -c 4000 /var/log/enclave-console.log 2>&1")[1])
        print(machine.execute("systemctl status vhost-device-vsock enclave-heartbeat enclave-start enclave-watchdog gvproxy 2>&1 | tail -60")[1])
        print(machine.execute("journalctl -u vhost-device-vsock -u enclave-heartbeat --no-pager 2>&1 | tail -40")[1])
        print(machine.execute("lsmod | grep -i vsock; ls /dev/vsock 2>&1; ps aux | grep qemu | head -5")[1])
        raise
  '';
}
