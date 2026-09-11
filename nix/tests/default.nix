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

  awsNode = import ./aws-node.nix { inherit awsNodeIP; };
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
