{
  pkgs,
  system,
  self,
  aws-nitro-util,
}:
let
  testApp = import ./test-app.nix { inherit pkgs; };
  lib = pkgs.lib;
  awsNodeIP = "192.168.1.1";

  # The test uses a fixed three-node NixOS-test network. The enclave reaches
  # these addresses through gvproxy; using the AWS node's stable VLAN address
  # avoids depending on gvproxy forwarding the host's /etc/hosts entries.
  commonEifEnv = {
    ENCLAVE_DEPLOYMENT = "dev";
    ENCLAVE_APP_NAME = "testapp";
    ENCLAVE_AWS_REGION = "us-east-1";
    ENCLAVE_KMS_KEY_LOCKED = "false";
    ENCLAVE_MIGRATION_COOLDOWN = "2s";
    ENCLAVE_MIGRATION_INTENT_RETENTION = "1h";
    ENCLAVE_NITRIDING_UPSTREAM = "h1";
    ENCLAVE_LOG_CLOUDWATCH = "false";
    # Test-only cadence exercises the unchanged servo without waiting five minutes.
    ENCLAVE_CLOCK_POLL_INTERVAL = "2s";
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
    AWS_REQUEST_CHECKSUM_CALCULATION = "when_required";
    AWS_RESPONSE_CHECKSUM_VALIDATION = "when_required";
  };

  # An otherwise-unused salt deliberately changes the EIF measurement between
  # slots without changing runtime behaviour.
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

  enclaveTofu = self.lib.mkEnclaveTofu {
    inherit pkgs;
    app = "testapp";
    deployment = "dev";
    local = true;
  };

  prodAmi = self.lib.mkEnclaveAmi {
    inherit pkgs;
    eif = blueEif;
  };
in
{
  # The production AMI's NixOS system evaluates and builds.
  ami-build = prodAmi.config.system.build.toplevel;

  # buildEif produces a bootable image with measured PCRs.
  eif-build = pkgs.runCommand "check-eif-build" { nativeBuildInputs = [ pkgs.jq ]; } ''
    test -s ${blueEif}/image.eif
    test -s ${greenEif}/image.eif
    jq -e '.PCR0 | test("^[0-9a-fA-F]{96}$")' ${blueEif}/pcr.json
    jq -e '.PCR0 | test("^[0-9a-fA-F]{96}$")' ${greenEif}/pcr.json
    test ${lib.escapeShellArg bluePCR0} != ${lib.escapeShellArg greenPCR0}
    touch $out
  '';

  # Validate generated configuration with the offline store-pinned provider.
  tofu-validate =
    pkgs.runCommand "check-tofu-validate"
      {
        nativeBuildInputs = [
          enclaveTofu
          pkgs.jq
        ];
      }
      ''
        export HOME=$TMPDIR
        cd $TMPDIR

        # Generated resource blocks are arrays of single-key objects.
        jq -e '
          ([.resource.aws_instance[] | has("nitro")] | any)
          and ([.resource.aws_eip_association[] | has("instance")] | any)
          and (.output | has("elastic_ip"))
          and (.variable | has("instances"))
          and (.variable | has("active_slot"))
        ' ${enclaveTofu.tfjson}

        tofunix init -backend=false -input=false
        tofunix validate
        touch $out
      '';
}
# QEMU's nitro-enclave machine type is x86_64-only.
// pkgs.lib.optionalAttrs (system == "x86_64-linux") {
  e2e = import ./e2e.nix {
    inherit
      pkgs
      self
      aws-nitro-util
      enclaveTofu
      testApp
      commonEifEnv
      awsNodeIP
      ;
  };
}
