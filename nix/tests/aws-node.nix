# Shared AWS and ACME fixtures for the integration tests.
{ awsNodeIP }:
{ pkgs, nodes, ... }:
let
  awsmocks = pkgs.buildGoModule {
    pname = "awsmocks";
    version = "0.1.0";
    src = ./awsmocks;
    vendorHash = "sha256-FlTEY1v5ZVqTICXGLTBgVW+JhlWwIiuJDekX2d3bfWs=";
    env.CGO_ENABLED = "0";
    meta.mainProgram = "awsmocks";
  };

  ministack = pkgs.python3Packages.buildPythonApplication rec {
    pname = "ministack";
    version = "1.4.16";
    pyproject = true;

    src = pkgs.fetchFromGitHub {
      owner = "ministackorg";
      repo = "ministack";
      tag = "v${version}";
      hash = "sha256-hqvlrhi/JLV3JCDXsQPmsWA+um/q/GsB/zwtFodxxj0=";
    };

    build-system = with pkgs.python3Packages; [
      setuptools
      wheel
    ];

    dependencies = with pkgs.python3Packages; [
      hypercorn
      pyyaml
      defusedxml
      cryptography
    ];

    doCheck = false;
    pythonImportsCheck = [ "ministack" ];
    meta.mainProgram = "ministack";
  };

  pebbleFixtures = pkgs.runCommand "pebble-fixtures" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir -p $out

    openssl ecparam -name prime256v1 -genkey -noout -out ca.key
    openssl req -x509 -new -key ca.key -days 3650 -sha256 \
      -subj "/CN=Enclave E2E Pebble API CA" -out $out/ca.crt

    openssl ecparam -name prime256v1 -genkey -noout -out $out/api.key
    openssl req -new -key $out/api.key -subj "/CN=pebble-api" -out api.csr
    printf 'subjectAltName=IP:${awsNodeIP},IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' > ext.cnf
    openssl x509 -req -in api.csr -days 3650 -sha256 \
      -CA $out/ca.crt -CAkey ca.key -CAcreateserial \
      -extfile ext.cnf \
      -out $out/api.crt

    cat > $out/pebble-config.json <<EOF
    {
      "pebble": {
        "listenAddress": "0.0.0.0:14000",
        "managementListenAddress": "127.0.0.1:15000",
        "certificate": "$out/api.crt",
        "privateKey": "$out/api.key",
        "httpPort": 5002,
        "tlsPort": 443,
        "ocspResponderURL": "",
        "externalAccountBindingRequired": false
      }
    }
    EOF
  '';

  # Independent NixOS VMs can differ slightly; production CAs backdate leaves,
  # but Pebble otherwise uses its own current time as NotBefore.
  testPebble = pkgs.pebble.overrideAttrs (old: {
    postPatch =
      (old.postPatch or "")
      + ''
        substituteInPlace ca/ca.go \
          --replace-fail 'certNotBefore := time.Now()' \
          'certNotBefore := time.Now().Add(-time.Hour)'
      '';
  });

  # Proxy runtime Route53 calls through MiniStack and update Pebble's DNS
  # challenge server before reporting the AWS change as complete.
  route53DNSProxy = pkgs.writeText "route53-dns-proxy.py" (builtins.readFile ./route53-dns-proxy.py);
in
{
  virtualisation.memorySize = 2048;
  virtualisation.cores = 2;

  environment.systemPackages = [
    pkgs.awscli2
    pkgs.curl
    pkgs.jq
    pkgs.openssl
  ];
  environment.variables = {
    AWS_ACCESS_KEY_ID = "000000000000";
    AWS_SECRET_ACCESS_KEY = "test";
    AWS_DEFAULT_REGION = "us-east-1";
    AWS_REQUEST_CHECKSUM_CALCULATION = "when_required";
    AWS_RESPONSE_CHECKSUM_VALIDATION = "when_required";
  };

  networking.hosts."${nodes.green.networking.primaryIPAddress}" = [ "enclave.test" ];
  environment.etc."pebble/ca.crt".source = "${pebbleFixtures}/ca.crt";
  networking.firewall.allowedTCPPorts = [
    1338
    4000
    4566
    4570
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

  systemd.services.pebble = {
    description = "Pebble ACME test server";
    wantedBy = [ "multi-user.target" ];
    wants = [ "pebble-challtestsrv.service" ];
    after = [ "pebble-challtestsrv.service" ];
    environment = {
      PEBBLE_VA_NOSLEEP = "1";
      PEBBLE_WFE_NONCEREJECT = "0";
    };
    serviceConfig = {
      Type = "simple";
      ExecStart = "${testPebble}/bin/pebble -config ${pebbleFixtures}/pebble-config.json -strict=false -dnsserver 127.0.0.1:8053";
      Restart = "on-failure";
    };
  };

  systemd.services.pebble-challtestsrv = {
    description = "Pebble DNS-01 challenge server";
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${testPebble}/bin/pebble-challtestsrv -dns01 127.0.0.1:8053 -management 127.0.0.1:8055 -http01= -https01= -tlsalpn01= -doh= -defaultIPv6=";
      Restart = "on-failure";
    };
  };

  systemd.services.route53-dns-proxy = {
    description = "Route53 proxy backed by Pebble challenge DNS";
    wantedBy = [ "multi-user.target" ];
    wants = [
      "ministack.service"
      "pebble-challtestsrv.service"
    ];
    after = [
      "ministack.service"
      "pebble-challtestsrv.service"
    ];
    serviceConfig = {
      Type = "simple";
      StateDirectory = "route53-dns-proxy";
      ExecStart = "${pkgs.python3}/bin/python ${route53DNSProxy}";
      Restart = "on-failure";
    };
  };
}
