# Full-stack blue/green test:
#
#   * builds two distinct EIFs and two QEMU AMIs through mkEnclaveQemuAmi;
#   * registers those AMIs with ministack and feeds the allocated IDs to tofu;
#   * applies blue -> blue+green -> active green -> green-only;
#   * boots the real runtime inside each QEMU AMI through the production host
#     services shared with mkEnclaveAmi;
#   * performs the predecessor/successor migration handshake over vsock:8003;
#   * proves the static secret survives the KMS handoff.
{
  pkgs,
  self,
  enclaveTofu,
  blueEif,
  greenEif,
  bluePCR0,
  greenPCR0,
}:
let
  ministack = import ./ministack.nix { inherit pkgs; };
  awsmocks = import ./awsmocks.nix { inherit pkgs; };

  mkQemuAmiNode =
    eif:
    { pkgs, ... }:
    {
      imports = [
        (self.lib.mkEnclaveQemuAmi {
          inherit eif;
          memoryMib = 2048;
          cpuCount = 2;
        })
      ];

      virtualisation.memorySize = 4096;
      virtualisation.cores = 2;

      environment.systemPackages = with pkgs; [
        curl
        jq
      ];

      networking.firewall.allowedTCPPorts = [ 443 ];

      # EC2 provides this link-local address. In the test VPC it forwards to
      # the IMDS stub on the AWS node, leaving the AMI's production
      # imds-proxy (vsock:8002 -> 169.254.169.254:80) unchanged.
      systemd.services.mock-imds-forward = {
        description = "Test-VPC IMDS endpoint";
        wantedBy = [ "multi-user.target" ];
        wants = [ "network-online.target" ];
        after = [ "network-online.target" ];
        serviceConfig = {
          Type = "simple";
          ExecStartPre = "${pkgs.iproute2}/bin/ip address replace 169.254.169.254/32 dev lo";
          ExecStart = "${pkgs.socat}/bin/socat TCP4-LISTEN:80,bind=169.254.169.254,reuseaddr,fork TCP4:aws:1338";
          Restart = "on-failure";
        };
      };

      # EC2 provides IMDS before the host boots. Preserve that ordering for
      # the test's link-local IMDS stand-in before automatic enclave startup.
      systemd.services.enclave-start = {
        requires = [ "mock-imds-forward.service" ];
        after = [ "mock-imds-forward.service" ];
      };
    };
in
pkgs.testers.runNixOSTest {
  name = "enclave-blue-green-e2e";

  nodes = {
    aws =
      { pkgs, ... }:
      {
        virtualisation.memorySize = 2048;
        virtualisation.cores = 2;

        environment.systemPackages = [
          pkgs.awscli2
          pkgs.curl
          pkgs.jq
          enclaveTofu
        ];
        environment.variables = {
          AWS_ACCESS_KEY_ID = "000000000000";
          AWS_SECRET_ACCESS_KEY = "test";
          AWS_DEFAULT_REGION = "us-east-1";
          AWS_REQUEST_CHECKSUM_CALCULATION = "when_required";
          AWS_RESPONSE_CHECKSUM_VALIDATION = "when_required";
        };

        networking.firewall.allowedTCPPorts = [
          1338
          4000
          4566
        ];

        systemd.services.ministack = {
          description = "MiniStack AWS emulator";
          wantedBy = [ "multi-user.target" ];
          environment = {
            BIND_HOST = "0.0.0.0";
            GATEWAY_PORT = "4566";
            MINISTACK_REGION = "us-east-1";
            LOG_LEVEL = "INFO";
          };
          serviceConfig = {
            Type = "simple";
            ExecStart = "${ministack}/bin/ministack";
            Restart = "on-failure";
            StateDirectory = "ministack";
            WorkingDirectory = "/var/lib/ministack";
          };
        };

        systemd.services.awsmocks = {
          description = "Attested KMS proxy and IMDS stub";
          wantedBy = [ "multi-user.target" ];
          wants = [ "ministack.service" ];
          after = [ "ministack.service" ];
          environment = {
            KMS_PROXY_LISTEN_ADDR = ":4000";
            IMDS_LISTEN_ADDR = ":1338";
            UPSTREAM_KMS_URL = "http://127.0.0.1:4566";
          };
          serviceConfig = {
            Type = "simple";
            ExecStart = "${awsmocks}/bin/awsmocks";
            Restart = "on-failure";
          };
        };
      };

    blue = mkQemuAmiNode blueEif;
    green = mkQemuAmiNode greenEif;
  };

  testScript =
    ''
      BLUE_PCR0 = ${builtins.toJSON bluePCR0}
      GREEN_PCR0 = ${builtins.toJSON greenPCR0}
    ''
    + builtins.readFile ./e2e.py;
}
