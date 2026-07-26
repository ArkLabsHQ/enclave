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
    { lib, pkgs, ... }:
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

      # Build both complete AMIs, but let the test start each simulated EC2
      # instance at the same point that its tofu resource is created.
      systemd.services.enclave-start.wantedBy = lib.mkForce [ ];
      systemd.services.enclave-watchdog.wantedBy = lib.mkForce [ ];
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

  testScript = ''
    import json
    import shlex
    import time

    CLOUD = "aws --no-cli-pager --endpoint-url http://127.0.0.1:4566 --region us-east-1"
    WORK = "/var/lib/enclave-e2e"
    TFVARS = f"{WORK}/deploy.tfvars.json"

    def cloud(command):
        return aws.succeed(f"{CLOUD} {command}").strip()

    def tofu(command):
        return aws.succeed(f"cd {WORK} && tofunix {command}").strip()

    def write_tfvars(instances, active_slot):
        payload = json.dumps({
            "account": "000000000000",
            "instances": instances,
            "active_slot": active_slot,
        })
        aws.succeed(f"printf %s {shlex.quote(payload)} > {TFVARS}")

    def clear_released_lock():
        # MiniStack occasionally retains OpenTofu's conditionally-deleted lock
        # after the command has exited. Commands in this test are strictly
        # serial, so remove only this stack's exact lock key between commands.
        cloud(
            "dynamodb delete-item --table-name enclave-e2e-tofu-lock "
            "--key '{\"LockID\":{\"S\":\"enclave-e2e-tofu-state/enclave.tfstate\"}}'"
        )

    def plan(name):
        path = f"{WORK}/{name}.plan"
        tofu(f"plan -input=false -out={path} -var-file={TFVARS}")
        clear_released_lock()
        return path

    def changed_resources(plan_path):
        doc = json.loads(tofu(f"show -json {plan_path}"))
        return [
            (change["address"], change["change"]["actions"])
            for change in doc.get("resource_changes", [])
            if change["change"]["actions"] != ["no-op"]
        ]

    def instance_ids():
        return json.loads(tofu("output -json instance_ids"))

    def wait_healthy(node):
        try:
            node.wait_until_succeeds(
                "curl -skf --http1.1 https://127.0.0.1/health | jq -e '.status == \"ready\"'",
                timeout=300,
            )
            node.wait_until_succeeds(
                "curl -skf --http1.1 https://127.0.0.1/cgi-bin/health "
                "| jq -e '.status == \"ok\"'",
                timeout=30,
            )
        except Exception:
            print(node.execute("tail -n 120 /var/log/enclave-console.log 2>&1")[1])
            print(node.execute("journalctl -u gvproxy -u imds-proxy -u migration-proxy -u enclave-start -u enclave-watchdog --no-pager -n 100")[1])
            print(aws.execute("journalctl -u ministack -u awsmocks --no-pager -n 100")[1])
            raise

    def secret_fingerprint(node):
        command = (
            "curl -skf --http1.1 --data-binary "
            "'printf \"%s\" \"$E2E_SIGNING_KEY\" | sha256sum | cut -d \" \" -f 1' "
            "https://127.0.0.1/cgi-bin/run"
        )
        fingerprint = node.succeed(command).strip()
        assert len(fingerprint) == 64, fingerprint
        assert all(c in "0123456789abcdef" for c in fingerprint), fingerprint
        return fingerprint

    start_all()
    for node in (aws, blue, green):
        node.wait_for_unit("multi-user.target")

    aws.wait_for_open_port(4566)
    aws.wait_until_succeeds("curl -fsS http://127.0.0.1:4566/_ministack/health")
    aws.wait_for_open_port(4000)
    aws.wait_for_open_port(1338)

    for node in (blue, green):
        node.wait_for_unit("mock-imds-forward.service")
        node.wait_until_succeeds("curl -fsS http://169.254.169.254/health")
        node.fail("systemctl is-active --quiet enclave-start.service")
        node.fail("systemctl is-active --quiet enclave-watchdog.service")

    aws.succeed(f"mkdir -p {WORK}")

    # Remote state backend: the test does the same one-time bootstrap the
    # runbook requires, then runs the generated main stack through its S3
    # backend and DynamoDB lock table.
    cloud("s3api create-bucket --bucket enclave-e2e-tofu-state")
    cloud(
        "dynamodb create-table --table-name enclave-e2e-tofu-lock "
        "--attribute-definitions AttributeName=LockID,AttributeType=S "
        "--key-schema AttributeName=LockID,KeyType=HASH "
        "--billing-mode PAY_PER_REQUEST"
    )
    tofu(
        "init -input=false "
        "-backend-config=bucket=enclave-e2e-tofu-state "
        "-backend-config=region=us-east-1 "
        "-backend-config=dynamodb_table=enclave-e2e-tofu-lock"
    )

    # Release/register both AMIs. MiniStack allocates the IDs consumed by the
    # instances tfvars; the PCR0 in each image's metadata identifies the EIF
    # actually embedded in the corresponding QEMU AMI node.
    blue_ami = cloud(
        "ec2 register-image "
        "--name enclave-blue-${bluePCR0} "
        "--description PCR0=${bluePCR0} "
        "--root-device-name /dev/xvda "
        "--query ImageId --output text"
    )
    green_ami = cloud(
        "ec2 register-image "
        "--name enclave-green-${greenPCR0} "
        "--description PCR0=${greenPCR0} "
        "--root-device-name /dev/xvda "
        "--query ImageId --output text"
    )
    assert blue_ami.startswith("ami-")
    assert green_ami.startswith("ami-")
    assert blue_ami != green_ami
    assert cloud(
        f"ec2 describe-images --image-ids {blue_ami} "
        "--query 'Images[0].Name' --output text"
    ) == "enclave-blue-${bluePCR0}"
    assert cloud(
        f"ec2 describe-images --image-ids {green_ami} "
        "--query 'Images[0].Name' --output text"
    ) == "enclave-green-${greenPCR0}"

    blue_instance = {"ami_id": blue_ami, "instance_type": "m5.xlarge"}
    green_instance = {"ami_id": green_ami, "instance_type": "m5.xlarge"}

    # First deployment: only blue exists and owns the stable EIP.
    write_tfvars({"blue": blue_instance}, "blue")
    initial_plan = plan("initial-blue")
    tofu(f"apply -auto-approve -input=false {initial_plan}")
    clear_released_lock()
    ids = instance_ids()
    blue_instance_id = ids["blue"]
    assert cloud(
        f"ec2 describe-instances --instance-ids {blue_instance_id} "
        "--query 'Reservations[0].Instances[0].ImageId' --output text"
    ) == blue_ami
    elastic_ip = tofu("output -raw elastic_ip")
    assert cloud(
        "ec2 describe-addresses --query 'Addresses[0].InstanceId' --output text"
    ) == blue_instance_id

    # SSM runtime override is deliberately created through the AWS API, then
    # observed from inside the EIF through the test app.
    cloud(
        "ssm put-parameter --name /dev/testapp/env/E2E_OVERRIDE "
        "--type String --value override-from-ssm"
    )

    blue.succeed("systemctl start enclave-watchdog.service")
    blue.wait_for_unit("enclave-start.service")
    blue.wait_for_unit("enclave-watchdog.service")
    wait_healthy(blue)
    blue.succeed(
        "test \"$(curl -skf --http1.1 --data-binary "
        "'printf \"%s\" \"$E2E_OVERRIDE\"' "
        "https://127.0.0.1/cgi-bin/run)\" = override-from-ssm"
    )
    blue_secret = secret_fingerprint(blue)
    blue.succeed(
        "curl -skf --http1.1 https://127.0.0.1/v1/enclave-info "
        "| jq -e --arg p '${bluePCR0}' "
        "'.previous_pcr0 == \"genesis\" and .migration.state == \"none\" "
        "and .migration.source_pcr0 == $p'"
    )

    key_param = "/dev/testapp/unlocked/KMSKeyID"
    genesis_key = cloud(
        f"ssm get-parameter --name {key_param} --query Parameter.Value --output text"
    )
    assert genesis_key not in ("", "UNSET", "None")

    # Stand up green in the mock cloud, but do not boot its AMI yet. This is
    # the runbook's pre-cutover validation window.
    write_tfvars(
        {"blue": blue_instance, "green": green_instance},
        "blue",
    )
    add_green_plan = plan("add-green")
    add_green_changes = changed_resources(add_green_plan)
    assert add_green_changes == [
        ('aws_instance.nitro["green"]', ["create"]),
    ], add_green_changes
    tofu(f"apply -auto-approve -input=false {add_green_plan}")
    clear_released_lock()
    ids = instance_ids()
    green_instance_id = ids["green"]
    assert ids["blue"] == blue_instance_id
    assert cloud(
        f"ec2 describe-instances --instance-ids {green_instance_id} "
        "--query 'Reservations[0].Instances[0].ImageId' --output text"
    ) == green_ami
    assert cloud(
        "ec2 describe-addresses --query 'Addresses[0].InstanceId' --output text"
    ) == blue_instance_id

    # Blue authorises and finalises the handoff to green over the production
    # migration-proxy path (localhost:8003 -> enclave vsock:8003).
    # vhost-device-vsock 0.3 occasionally drops a newly forwarded host->guest
    # connection before the request reaches the guest. Retry only until a
    # valid runtime response is present; each successful `requested` intent is
    # safe to supersede with the same target.
    migration_request_output = ""
    for _ in range(10):
        migration_status, migration_request_output = blue.execute(
            "rm -f /tmp/request-migration.json; "
            "curl -fsS -H 'Content-Type: application/json' "
            "--data '{\"action\":\"requested\",\"target_pcr0\":\"${greenPCR0}\"}' "
            "--output /tmp/request-migration.json "
            "http://127.0.0.1:8003/request-migration"
        )
        valid_status, _ = blue.execute(
            "jq -e --arg p '${greenPCR0}' "
            "'.target_pcr0 == $p and (.state == \"cooling_down\" or .state == \"eligible\")' "
            "/tmp/request-migration.json"
        )
        if migration_status == 0 and valid_status == 0:
            break
        time.sleep(0.2)
    else:
        print(migration_request_output)
        print(blue.execute("systemctl status migration-proxy vhost-device-vsock --no-pager")[1])
        print(blue.execute("journalctl -u migration-proxy -u vhost-device-vsock --no-pager -n 100")[1])
        print(blue.execute("tail -n 100 /var/log/enclave-console.log")[1])
        raise Exception("request-migration did not reach the enclave")
    intent_bucket = tofu("output -raw migration_intent_log_bucket")
    assert int(cloud(
        f"s3api list-object-versions --bucket {intent_bucket} "
        "--query 'length(Versions)' --output text"
    )) >= 1
    blue.wait_until_succeeds(
        "curl -skf --http1.1 https://127.0.0.1/v1/enclave-info "
        "| jq -e '.migration.state == \"eligible\"'",
        timeout=30,
    )

    finalise_response_valid = False
    migration_key = genesis_key
    finalise_output = ""
    for _ in range(10):
        finalise_status, finalise_output = blue.execute(
            "rm -f /tmp/finalise-migration.json; "
            "curl -fsS -H 'Content-Type: application/json' "
            "--data '{\"new_pcr0\":\"${greenPCR0}\"}' "
            "--output /tmp/finalise-migration.json "
            "http://127.0.0.1:8003/finalise-migration"
        )
        response_status, _ = blue.execute(
            "jq -e --arg p '${bluePCR0}' "
            "'.pcr0 == $p and (.exported | index(\"e2e-signing-key\"))' "
            "/tmp/finalise-migration.json"
        )
        if finalise_status == 0 and response_status == 0:
            finalise_response_valid = True
        migration_key = cloud(
            f"ssm get-parameter --name {key_param} --query Parameter.Value --output text"
        )
        # KMSKeyID is the migration's last write and atomic commit. If it
        # changed, finalisation succeeded even if the QEMU transport dropped
        # only the HTTP response on the way back.
        if migration_key != genesis_key:
            break
        time.sleep(0.2)
    else:
        print(finalise_output)
        print(blue.execute("cat /tmp/finalise-migration.json 2>/dev/null || true")[1])
        print(blue.execute("tail -n 100 /var/log/enclave-console.log")[1])
        raise Exception("finalise-migration did not commit")

    if finalise_response_valid:
        blue.succeed(
            "jq -e --arg p '${bluePCR0}' "
            "'.pcr0 == $p and (.exported | index(\"e2e-signing-key\"))' "
            "/tmp/finalise-migration.json"
        )
    assert migration_key != genesis_key

    # Green now boots against the atomic handoff. A healthy app plus matching
    # predecessor and secret proves receipt verification and attested decrypt.
    green.succeed("systemctl start enclave-watchdog.service")
    green.wait_for_unit("enclave-start.service")
    green.wait_for_unit("enclave-watchdog.service")
    wait_healthy(green)
    assert secret_fingerprint(green) == blue_secret
    green.succeed(
        "curl -skf --http1.1 https://127.0.0.1/v1/enclave-info "
        "| jq -e --arg prev '${bluePCR0}' --arg current '${greenPCR0}' "
        "'.previous_pcr0 == $prev "
        "and (.previous_pcr0_attestation | length) > 0 "
        "and .migration.state == \"none\" "
        "and .migration.source_pcr0 == $current'"
    )

    # Cut over the stable EIP. The association replacement is the only cloud
    # change; both enclave AMIs remain healthy throughout.
    write_tfvars(
        {"blue": blue_instance, "green": green_instance},
        "green",
    )
    flip_plan = plan("flip-green")
    flip_changes = changed_resources(flip_plan)
    assert len(flip_changes) == 1, flip_changes
    assert flip_changes[0][0] == "aws_eip_association.instance", flip_changes
    tofu(f"apply -auto-approve -input=false {flip_plan}")
    clear_released_lock()
    assert tofu("output -raw elastic_ip") == elastic_ip
    assert cloud(
        "ec2 describe-addresses --query 'Addresses[0].InstanceId' --output text"
    ) == green_instance_id
    wait_healthy(blue)
    wait_healthy(green)

    # End the soak period and retire blue. The stable EIP/association and all
    # shared state stay untouched.
    write_tfvars({"green": green_instance}, "green")
    retire_plan = plan("retire-blue")
    retire_changes = changed_resources(retire_plan)
    assert retire_changes == [
        ('aws_instance.nitro["blue"]', ["delete"]),
    ], retire_changes
    tofu(f"apply -auto-approve -input=false {retire_plan}")
    clear_released_lock()
    assert list(instance_ids()) == ["green"]
    assert tofu("output -raw elastic_ip") == elastic_ip
    assert cloud(
        "ec2 describe-addresses --query 'Addresses[0].InstanceId' --output text"
    ) == green_instance_id

    blue.shutdown()
    wait_healthy(green)
  '';
}
