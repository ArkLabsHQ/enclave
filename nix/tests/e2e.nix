{
  pkgs,
  self,
  enclaveTofu,
  testApp,
  commonEifEnv,
  awsNodeIP,
}:
let
  lib = pkgs.lib;

  mkEif =
    env:
    self.lib.buildEif {
      inherit pkgs;
      app = testApp;
      env = commonEifEnv // { ENCLAVE_DEV = "true"; } // env;
    };

  blueEif = mkEif {
    ENCLAVE_PREVIOUS_PCR0 = "genesis";
    ENCLAVE_TEST_SALT = "blue";
  };
  bluePCR0 = lib.toLower (builtins.fromJSON (builtins.readFile "${blueEif}/pcr.json")).PCR0;

  greenEif = mkEif {
    ENCLAVE_PREVIOUS_PCR0 = bluePCR0;
    ENCLAVE_TEST_SALT = "green";
  };
  greenPCR0 = lib.toLower (builtins.fromJSON (builtins.readFile "${greenEif}/pcr.json")).PCR0;

  ministack = import ./ministack.nix { inherit pkgs; };
  awsmocks = import ./awsmocks.nix { inherit pkgs; };
  pebbleFixtures = import ./pebble.nix {
    inherit pkgs;
    apiIP = awsNodeIP;
  };

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
        openssl
        self.packages.${pkgs.system}.cli
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
      { pkgs, nodes, ... }:
      {
        virtualisation.memorySize = 2048;
        virtualisation.cores = 2;

        environment.systemPackages = [
          pkgs.awscli2
          pkgs.curl
          pkgs.jq
          pkgs.openssl
          enclaveTofu
        ];
        environment.variables = {
          AWS_ACCESS_KEY_ID = "000000000000";
          AWS_SECRET_ACCESS_KEY = "test";
          AWS_DEFAULT_REGION = "us-east-1";
          AWS_REQUEST_CHECKSUM_CALCULATION = "when_required";
          AWS_RESPONSE_CHECKSUM_VALIDATION = "when_required";
        };

        # Pebble's TLS-ALPN-01 VA and chain verification dial green by name.
        networking.hosts."${nodes.green.networking.primaryIPAddress}" = [ "enclave.test" ];

        environment.etc."pebble/ca.crt".source = "${pebbleFixtures}/ca.crt";

        networking.firewall.allowedTCPPorts = [
          1338
          4000
          4566
          14000
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

        # Disable Pebble sleeps and nonce rejection to stay within test timeouts.
        # Its management API provides the per-launch root and certificate status.
        systemd.services.pebble = {
          description = "Pebble ACME test server";
          wantedBy = [ "multi-user.target" ];
          environment = {
            PEBBLE_VA_NOSLEEP = "1";
            PEBBLE_WFE_NONCEREJECT = "0";
          };
          serviceConfig = {
            Type = "simple";
            ExecStart = "${pkgs.pebble}/bin/pebble -config ${pebbleFixtures}/pebble-config.json -strict false";
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
      AWS_NODE_IP = ${builtins.toJSON awsNodeIP}
    ''
    + builtins.readFile ./e2e.py;
}
