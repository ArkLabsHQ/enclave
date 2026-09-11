{
  pkgs,
  system,
  self,
}:
let
  lib = pkgs.lib;

  awsNodeIP = "192.168.1.1";

  testApp = pkgs.buildGoModule {
    pname = "testapp";
    version = "0.1.0";
    src = ./test-app;
    vendorHash = "sha256-8FrG/O0buFies3nVPhnfLnG7mSUi9XjClpcQ7OBPmlg=";
    env.CGO_ENABLED = "0";
  };

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
  route53DNSProxy = pkgs.writeText "route53-dns-proxy.py" ''
    import json
    import os
    import urllib.error
    import urllib.request
    import xml.etree.ElementTree as ET
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    UPSTREAM = "http://127.0.0.1:4566"
    CHALLENGE_API = "http://127.0.0.1:8055"
    EVENTS = "/var/lib/route53-dns-proxy/events"

    def local_name(element):
        return element.tag.rsplit("}", 1)[-1]

    def child_text(element, name):
        for child in element:
            if local_name(child) == name:
                return child.text or ""
        return ""

    def challenge_request(path, payload):
        request = urllib.request.Request(
            CHALLENGE_API + path,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            response.read()

    def sync_challenges(body):
        root = ET.fromstring(body)
        for change in (node for node in root.iter() if local_name(node) == "Change"):
            action = child_text(change, "Action")
            record_set = next(
                (node for node in change if local_name(node) == "ResourceRecordSet"),
                None,
            )
            if record_set is None or child_text(record_set, "Type") != "TXT":
                continue
            host = child_text(record_set, "Name")
            if action == "DELETE":
                challenge_request("/clear-txt", {"host": host})
                continue
            for record in (
                node for node in record_set.iter() if local_name(node) == "ResourceRecord"
            ):
                value = child_text(record, "Value").strip('"')
                challenge_request("/set-txt", {"host": host, "value": value})
                with open(EVENTS, "a", encoding="ascii") as events:
                    events.write(host + " " + value + "\n")

    class Handler(BaseHTTPRequestHandler):
        def proxy(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            headers = {
                key: value for key, value in self.headers.items()
                if key.lower() not in {"host", "content-length"}
            }
            request = urllib.request.Request(
                UPSTREAM + self.path,
                data=body if self.command == "POST" else None,
                headers=headers,
                method=self.command,
            )
            try:
                response = urllib.request.urlopen(request)
            except urllib.error.HTTPError as error:
                response = error
            response_body = response.read()

            if self.command == "POST" and "/rrset" in self.path and response.status < 300:
                sync_challenges(body)

            self.send_response(response.status)
            for key, value in response.headers.items():
                if key.lower() not in {"content-length", "transfer-encoding", "connection"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

        do_GET = proxy
        do_POST = proxy

        def log_message(self, format, *args):
            return

    os.makedirs(os.path.dirname(EVENTS), exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", 4570), Handler).serve_forever()
  '';

  # The AWS node sorts first in both topologies, keeping its VLAN address stable.
  # Using it directly avoids depending on gvproxy forwarding /etc/hosts entries.
  commonEifEnv = {
    ENCLAVE_DEPLOYMENT = "dev";
    ENCLAVE_DEV = "true";
    ENCLAVE_APP_NAME = "testapp";
    ENCLAVE_AWS_REGION = "us-east-1";
    ENCLAVE_UPSTREAM = "h1";
    ENCLAVE_SECRETS_CONFIG = builtins.toJSON [
      {
        name = "e2e-signing-key";
        env_var = "E2E_SIGNING_KEY";
      }
    ];

    AWS_ENDPOINT_URL_KMS = "http://${awsNodeIP}:4000";
    AWS_ENDPOINT_URL_SSM = "http://${awsNodeIP}:4566";
    AWS_ENDPOINT_URL_S3 = "http://${awsNodeIP}:4566";
    AWS_ENDPOINT_URL_STS = "http://${awsNodeIP}:4566";
    AWS_ENDPOINT_URL_LOGS = "http://${awsNodeIP}:4566";
    AWS_ENDPOINT_URL_ROUTE53 = "http://${awsNodeIP}:4570";
    AWS_REQUEST_CHECKSUM_CALCULATION = "when_required";
    AWS_RESPONSE_CHECKSUM_VALIDATION = "when_required";
  };

  mkTestEif =
    env:
    self.lib.buildEif {
      inherit pkgs;
      app = testApp;
      env = commonEifEnv // env;
    };

  blueEif = mkTestEif {
    ENCLAVE_PREVIOUS_PCR0 = "genesis";
    ENCLAVE_TEST_SALT = "blue";
  };
  bluePCR0 = lib.toLower (builtins.fromJSON (builtins.readFile "${blueEif}/pcr.json")).PCR0;

  greenEif = mkTestEif {
    ENCLAVE_PREVIOUS_PCR0 = bluePCR0;
    ENCLAVE_TEST_SALT = "green";
  };
  greenPCR0 = lib.toLower (builtins.fromJSON (builtins.readFile "${greenEif}/pcr.json")).PCR0;

  mkEnclaveHost = import ./enclave-host.nix { inherit self; };
  mkEnclaveNode = eif: mkEnclaveHost { enclave = { inherit eif; }; };

  appOneEif = mkTestEif {
    ENCLAVE_APP_NAME = "appOne";
    ENCLAVE_PREVIOUS_PCR0 = "genesis";
  };
  appOnePCR0 = lib.toLower (builtins.fromJSON (builtins.readFile "${appOneEif}/pcr.json")).PCR0;
  appTwoEif = mkTestEif {
    ENCLAVE_APP_NAME = "appTwo";
    ENCLAVE_PREVIOUS_PCR0 = "genesis";
  };
  appTwoPCR0 = lib.toLower (builtins.fromJSON (builtins.readFile "${appTwoEif}/pcr.json")).PCR0;
  successorEif = mkTestEif {
    ENCLAVE_APP_NAME = "appTwo";
    ENCLAVE_PREVIOUS_PCR0 = appTwoPCR0;
  };
  successorPCR0 = lib.toLower (builtins.fromJSON (builtins.readFile "${successorEif}/pcr.json")).PCR0;
  multiInstances = {
    appOne = {
      eif = appOneEif;
      cid = 1024;
      publicPort = 8443;
      controlPort = 18003;
    };
    appTwo = {
      eif = appTwoEif;
      cid = 1025;
      publicPort = 9443;
      controlPort = 18004;
    };
  };

  awsNode =
    { pkgs, nodes, ... }:
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
    };
in
{
  eif-build = pkgs.runCommand "check-eif-build" { nativeBuildInputs = [ pkgs.jq ]; } ''
    test -s ${blueEif}/image.eif
    test -s ${greenEif}/image.eif
    jq -e '.PCR0 | test("^[0-9a-fA-F]{96}$")' ${blueEif}/pcr.json
    jq -e '.PCR0 | test("^[0-9a-fA-F]{96}$")' ${greenEif}/pcr.json
    test ${lib.escapeShellArg bluePCR0} != ${lib.escapeShellArg greenPCR0}
    touch $out
  '';

  e2e = pkgs.testers.runNixOSTest {
    name = "enclave-runtime-e2e";
    nodes = {
      aws = awsNode;
      blue = mkEnclaveNode blueEif;
      blue_peer = mkEnclaveNode blueEif;
      green = mkEnclaveNode greenEif;
      green_peer = mkEnclaveNode greenEif;
    };
    testScript =
      ''
        BLUE_PCR0 = ${builtins.toJSON bluePCR0}
        GREEN_PCR0 = ${builtins.toJSON greenPCR0}
        AWS_NODE_IP = ${builtins.toJSON awsNodeIP}
      ''
      + builtins.readFile ./helpers.py
      + "\n"
      + builtins.readFile ./e2e.py;
  };

  e2e-multi-enclave = pkgs.testers.runNixOSTest {
    name = "enclave-runtime-e2e-multi-enclave";
    nodes = {
      aws = awsNode;
      blue = mkEnclaveHost multiInstances;
      green = mkEnclaveHost (
        multiInstances
        // {
          appTwo = multiInstances.appTwo // {
            eif = successorEif;
            autoStart = false;
          };
        }
      );
    };
    testScript =
      ''
        APP_ONE_PCR0 = ${builtins.toJSON appOnePCR0}
        APP_TWO_PCR0 = ${builtins.toJSON appTwoPCR0}
        SUCCESSOR_PCR0 = ${builtins.toJSON successorPCR0}
        AWS_NODE_IP = ${builtins.toJSON awsNodeIP}
      ''
      + builtins.readFile ./helpers.py
      + "\n"
      + builtins.readFile ./multi-enclave.py;
  };
}
