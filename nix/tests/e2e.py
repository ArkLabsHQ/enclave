# e2e.nix prepends BLUE_PCR0, GREEN_PCR0, and AWS_NODE_IP.
# The NixOS test driver injects nodes, aws, blue, and green.

import json
import shlex
import time

CLOUD = "aws --no-cli-pager --endpoint-url http://127.0.0.1:4566 --region us-east-1"
WORK = "/var/lib/enclave-e2e"
TFVARS = f"{WORK}/deploy.tfvars.json"
FQDN = "enclave.test"


def cloud(command):
    return aws.succeed(f"{CLOUD} {command}").strip()


def put_env(name, value):
    cloud(
        f"ssm put-parameter --name /dev/testapp/env/{name} "
        f"--type String --value {shlex.quote(value)}"
    )


def served_leaf(node, x509_args):
    return node.succeed(
        f"openssl s_client -connect 127.0.0.1:443 -servername {FQDN} "
        f"</dev/null 2>/dev/null | openssl x509 {x509_args}"
    ).strip()


def served_leaf_sha(node):
    return node.succeed(
        f"openssl s_client -connect 127.0.0.1:443 -servername {FQDN} "
        "</dev/null 2>/dev/null | openssl x509 -outform DER "
        "| sha256sum | cut -d' ' -f1"
    ).strip()


def enclave_curl(node, pcr0):
    # QEMU's NSM cannot sign or supply an AWS chain. PCR0, nonce, TLS pin,
    # key binding, and the response signature remain verified.
    return node.execute(
        f"enclave curl /health --base-url https://127.0.0.1 "
        f"--expected-pcr0 {pcr0} --insecure-skip-cose-verify 2>&1"
    )


def tofu(command):
    return aws.succeed(f"cd {WORK} && tofunix {command}").strip()


def write_tfvars(instances, active_slot):
    payload = json.dumps(
        {
            "account": "000000000000",
            "instances": instances,
            "active_slot": active_slot,
        }
    )
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
            "curl -skf --http1.1 https://127.0.0.1/health "
            "| jq -e '.status == \"ready\"'",
            timeout=300,
        )
        node.wait_until_succeeds(
            "curl -skf --http1.1 https://127.0.0.1/test/health "
            "| jq -e '.status == \"ok\"'",
            timeout=30,
        )
    except Exception:
        print(node.execute("tail -n 120 /var/log/enclave-console.log 2>&1")[1])
        print(
            node.execute(
                "journalctl -u gvproxy -u imds-proxy -u migration-proxy "
                "-u enclave-start -u enclave-watchdog --no-pager -n 100"
            )[1]
        )
        print(
            aws.execute(
                "journalctl -u ministack -u awsmocks --no-pager -n 100"
            )[1]
        )
        raise


def secret_value(node):
    value = node.succeed(
        "curl -skf --http1.1 https://127.0.0.1/test/env/E2E_SIGNING_KEY "
        "| jq -r .value"
    ).strip()
    assert len(value) == 64, value
    assert all(c in "0123456789abcdef" for c in value), value
    return value


# MiniStack is the control plane: it records AWS resources but cannot boot an
# AMI. Start only that node until OpenTofu creates the first mock EC2 instance.
aws.start()
aws.wait_for_unit("multi-user.target")
aws.wait_for_open_port(4566)
aws.wait_until_succeeds("curl -fsS http://127.0.0.1:4566/_ministack/health")
aws.wait_for_open_port(4000)
aws.wait_for_open_port(1338)

aws.wait_for_open_port(14000)
aws.wait_until_succeeds(
    "curl -fsS --cacert /etc/pebble/ca.crt https://127.0.0.1:14000/dir "
    "| grep -q newOrder"
)

aws.succeed(f"mkdir -p {WORK}")

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
    f"--name enclave-blue-{BLUE_PCR0} "
    f"--description PCR0={BLUE_PCR0} "
    "--root-device-name /dev/xvda "
    "--query ImageId --output text"
)
green_ami = cloud(
    "ec2 register-image "
    f"--name enclave-green-{GREEN_PCR0} "
    f"--description PCR0={GREEN_PCR0} "
    "--root-device-name /dev/xvda "
    "--query ImageId --output text"
)
assert blue_ami.startswith("ami-")
assert green_ami.startswith("ami-")
assert blue_ami != green_ami
assert (
    cloud(
        f"ec2 describe-images --image-ids {blue_ami} "
        "--query 'Images[0].Name' --output text"
    )
    == f"enclave-blue-{BLUE_PCR0}"
)
assert (
    cloud(
        f"ec2 describe-images --image-ids {green_ami} "
        "--query 'Images[0].Name' --output text"
    )
    == f"enclave-green-{GREEN_PCR0}"
)

blue_instance = {"ami_id": blue_ami, "instance_type": "m5.xlarge"}
green_instance = {"ami_id": green_ami, "instance_type": "m5.xlarge"}

# First deployment: only blue exists and owns the stable EIP.
write_tfvars({"blue": blue_instance}, "blue")
initial_plan = plan("initial-blue")
tofu(f"apply -auto-approve -input=false {initial_plan}")
clear_released_lock()
ids = instance_ids()
blue_instance_id = ids["blue"]
assert (
    cloud(
        f"ec2 describe-instances --instance-ids {blue_instance_id} "
        "--query 'Reservations[0].Instances[0].ImageId' --output text"
    )
    == blue_ami
)
elastic_ip = tofu("output -raw elastic_ip")
tls_bucket = tofu("output -raw tls_cache_bucket")
assert (
    cloud("ec2 describe-addresses --query 'Addresses[0].InstanceId' --output text")
    == blue_instance_id
)

cloud(
    "ssm put-parameter --name /dev/testapp/env/E2E_OVERRIDE "
    "--type String --value override-from-ssm"
)

# FQDN must come from the runtime's SSM overlay, not the baked EIF env.
put_env("ENCLAVE_NITRIDING_FQDN", FQDN)

# MiniStack cannot execute the selected AMI, so pair the successful EC2 apply
# with its outer NixOS host VM. Normal multi-user activation starts the same
# enclave services as the production AMI, which then launches the inner EIF.
blue.start()
blue.wait_for_unit("multi-user.target")
blue.wait_for_unit("mock-imds-forward.service")
blue.wait_until_succeeds("curl -fsS http://169.254.169.254/health")
blue.wait_for_unit("enclave-start.service")
blue.wait_for_unit("enclave-watchdog.service")
wait_healthy(blue)
blue.succeed(
    "test \"$(curl -skf --http1.1 "
    "https://127.0.0.1/test/env/E2E_OVERRIDE "
    "| jq -r .value)\" = override-from-ssm"
)
blue_secret = secret_value(blue)
blue.succeed(
    "curl -skf --http1.1 https://127.0.0.1/v1/enclave-info "
    f"| jq -e --arg p '{BLUE_PCR0}' "
    "'.previous_pcr0 == \"genesis\" and .migration.state == \"none\" "
    "and .migration.source_pcr0 == $p'"
)

leaf_issuer = served_leaf(blue, "-noout -issuer")
assert "AWS Nitro enclave application" in leaf_issuer, leaf_issuer
leaf_subject = served_leaf(blue, "-noout -subject")
assert "AWS Nitro enclave application" in leaf_subject, leaf_subject
leaf_san = served_leaf(blue, "-noout -ext subjectAltName")
assert f"DNS:{FQDN}" in leaf_san, leaf_san
cache_keys = cloud(
    f"s3api list-objects-v2 --bucket {tls_bucket} "
    "--query 'Contents[].Key' --output text"
)
assert cache_keys in ("", "None"), cache_keys
status, out = enclave_curl(blue, BLUE_PCR0)
assert status == 0, out
assert "WARNING" in out, out

key_param = "/dev/testapp/unlocked/KMSKeyID"
genesis_key = cloud(
    f"ssm get-parameter --name {key_param} --query Parameter.Value --output text"
)
assert genesis_key not in ("", "UNSET", "None")

# Skew before migration so cooldown and receipt timestamps remain valid. The
# 2s test poll exercises the unchanged /dev/ptp0 servo without waiting five minutes.
host_ts = int(blue.succeed("date +%s").strip())
enclave_ts = int(
    blue.succeed("curl -skf --http1.1 https://127.0.0.1/test/clock | jq .unix").strip()
)
assert abs(enclave_ts - host_ts) <= 2, (enclave_ts, host_ts)

# This excludes the distinct "initial hard-step" boot message.
initial_hardsteps = int(
    blue.succeed(
        "grep -c 'clock sync: hard-step' /var/log/enclave-console.log || true"
    ).strip()
)

# A +5s skew exceeds the 100ms hard-step threshold on the next 2s poll.
clock_resp = json.loads(
    blue.succeed(
        "curl -skf --http1.1 -X POST -H 'Content-Type: application/json' "
        "--data '{\"offset_seconds\":5}' https://127.0.0.1/test/clock"
    )
)
skewed_ts = clock_resp["after"]["unix"]
host_ts_after = int(blue.succeed("date +%s").strip())
assert skewed_ts - host_ts_after >= 3, (skewed_ts, host_ts_after)

# Wait for the syncer to hard-step the clock back onto the PHC.
blue.wait_until_succeeds(
    f"test \"$(grep -c 'clock sync: hard-step' /var/log/enclave-console.log)\" "
    f"-ge {initial_hardsteps + 1}",
    timeout=30,
)

# Poll until the enclave clock is back within 2s of the outer host.
blue.wait_until_succeeds(
    "test $(( $(curl -skf --http1.1 https://127.0.0.1/test/clock | jq .unix) "
    "- $(date +%s) )) -le 2 "
    "&& test $(( $(date +%s) "
    "- $(curl -skf --http1.1 https://127.0.0.1/test/clock | jq .unix) )) -le 2",
    timeout=30,
)
final_hardsteps = int(
    blue.succeed(
        "grep -c 'clock sync: hard-step' /var/log/enclave-console.log || true"
    ).strip()
)
assert final_hardsteps == initial_hardsteps + 1, (initial_hardsteps, final_hardsteps)
wait_healthy(blue)

# Prove the next infrastructure change creates only green, but do not apply
# the saved plan yet: a real EC2 create would immediately boot the AMI, and
# green must not boot until blue has committed the migration.
write_tfvars(
    {"blue": blue_instance, "green": green_instance},
    "blue",
)
add_green_plan = plan("add-green")
add_green_changes = changed_resources(add_green_plan)
assert add_green_changes == [
    ('aws_instance.nitro["green"]', ["create"]),
], add_green_changes

# vhost-device-vsock 0.3 may drop migration-proxy requests. Repeating the same
# target's request is safe, so retry until a valid response arrives.
migration_request_output = ""
for _ in range(30):
    migration_status, migration_request_output = blue.execute(
        "rm -f /tmp/request-migration.json; "
        "curl -fsS -H 'Content-Type: application/json' "
        f"--data '{{\"action\":\"requested\",\"target_pcr0\":\"{GREEN_PCR0}\"}}' "
        "--output /tmp/request-migration.json "
        "http://127.0.0.1:8003/request-migration"
    )
    valid_status, _ = blue.execute(
        f"jq -e --arg p '{GREEN_PCR0}' "
        "'.target_pcr0 == $p and "
        "(.state == \"cooling_down\" or .state == \"eligible\")' "
        "/tmp/request-migration.json"
    )
    if migration_status == 0 and valid_status == 0:
        break
    # vhost-device-vsock drops cluster under rapid-fire new connections;
    # spacing the retries out recovers more reliably than hammering.
    time.sleep(1)
else:
    print(migration_request_output)
    print(
        blue.execute(
            "systemctl status migration-proxy vhost-device-vsock --no-pager"
        )[1]
    )
    print(
        blue.execute(
            "journalctl -u migration-proxy -u vhost-device-vsock --no-pager -n 100"
        )[1]
    )
    print(blue.execute("tail -n 100 /var/log/enclave-console.log")[1])
    raise Exception("request-migration did not reach the enclave")
intent_bucket = tofu("output -raw migration_intent_log_bucket")
assert (
    int(
        cloud(
            f"s3api list-object-versions --bucket {intent_bucket} "
            "--query 'length(Versions)' --output text"
        )
    )
    >= 1
)
blue.wait_until_succeeds(
    "curl -skf --http1.1 https://127.0.0.1/v1/enclave-info "
    "| jq -e '.migration.state == \"eligible\"'",
    timeout=30,
)

finalise_response_valid = False
migration_key = genesis_key
finalise_output = ""
for attempt in range(30):
    finalise_status, finalise_output = blue.execute(
        "rm -f /tmp/finalise-migration.json; "
        "curl -fsS -H 'Content-Type: application/json' "
        f"--data '{{\"new_pcr0\":\"{GREEN_PCR0}\"}}' "
        "--output /tmp/finalise-migration.json "
        "http://127.0.0.1:8003/finalise-migration"
    )
    if finalise_status != 0:
        print(f"finalise attempt {attempt}: curl rc={finalise_status}")
    response_status, _ = blue.execute(
        f"jq -e --arg p '{BLUE_PCR0}' "
        "'.pcr0 == $p and (.exported | index(\"e2e-signing-key\"))' "
        "/tmp/finalise-migration.json"
    )
    if finalise_status == 0 and response_status == 0:
        finalise_response_valid = True
    # KMSKeyID is the final atomic-commit write, proving success despite a
    # dropped response. MiniStack reads take ~3s, so check every third failed
    # attempt and after every successful response.
    if finalise_status == 0 or attempt % 3 == 2:
        migration_key = cloud(
            f"ssm get-parameter --name {key_param} --query Parameter.Value --output text"
        )
        if migration_key != genesis_key:
            break
    time.sleep(1)
else:
    print(finalise_output)
    print(
        blue.execute("cat /tmp/finalise-migration.json 2>/dev/null || true")[1]
    )
    print(
        "=== console ===\n"
        + blue.execute("tail -n 120 /var/log/enclave-console.log 2>&1")[1]
    )
    print(
        "=== watchdog ===\n"
        + blue.execute(
            "journalctl -u enclave-watchdog -u enclave-start --no-pager -n 60 2>&1"
        )[1]
    )
    print(
        "=== migration-proxy/vsock ===\n"
        + blue.execute(
            "journalctl -u migration-proxy -u vhost-device-vsock --no-pager -n 60 2>&1"
        )[1]
    )
    raise Exception("finalise-migration did not commit")

if finalise_response_valid:
    blue.succeed(
        f"jq -e --arg p '{BLUE_PCR0}' "
        "'.pcr0 == $p and (.exported | index(\"e2e-signing-key\"))' "
        "/tmp/finalise-migration.json"
    )
assert migration_key != genesis_key

tofu(f"apply -auto-approve -input=false {add_green_plan}")
clear_released_lock()
ids = instance_ids()
green_instance_id = ids["green"]
assert ids["blue"] == blue_instance_id
assert (
    cloud(
        f"ec2 describe-instances --instance-ids {green_instance_id} "
        "--query 'Reservations[0].Instances[0].ImageId' --output text"
    )
    == green_ami
)
assert (
    cloud("ec2 describe-addresses --query 'Addresses[0].InstanceId' --output text")
    == blue_instance_id
)

# Point green's TLS at Pebble. The runtime reads these SSM params once per
# boot at ConfigureTLS; blue already booted self-signed and is unaffected.
put_env("ENCLAVE_NITRIDING_USE_ACME", "true")
put_env("ENCLAVE_NITRIDING_ACME_DIRECTORY", f"https://{AWS_NODE_IP}:14000/dir")
put_env("ENCLAVE_NITRIDING_ACME_EMAIL", f"acme-test@{FQDN}")
put_env("ENCLAVE_NITRIDING_ACME_CA", aws.succeed("cat /etc/pebble/ca.crt"))

green.start()
green.wait_for_unit("multi-user.target")
green.wait_for_unit("mock-imds-forward.service")
green.wait_until_succeeds("curl -fsS http://169.254.169.254/health")
green.wait_for_unit("enclave-start.service")
green.wait_for_unit("enclave-watchdog.service")
wait_healthy(green)
assert secret_value(green) == blue_secret
green.succeed(
    "curl -skf --http1.1 https://127.0.0.1/v1/enclave-info "
    f"| jq -e --arg prev '{BLUE_PCR0}' --arg current '{GREEN_PCR0}' "
    "'.previous_pcr0 == $prev "
    "and (.previous_pcr0_attestation | length) > 0 "
    "and .migration.state == \"none\" "
    "and .migration.source_pcr0 == $current'"
)

# Validate the served chain against Pebble's per-launch issuance root.
leaf_issuer = served_leaf(green, "-noout -issuer")
assert "Pebble" in leaf_issuer, leaf_issuer
leaf_san = served_leaf(green, "-noout -ext subjectAltName")
assert f"DNS:{FQDN}" in leaf_san, leaf_san
assert leaf_san.count("DNS:") == 1, leaf_san
chain_certs = int(
    green.succeed(
        f"openssl s_client -connect 127.0.0.1:443 -servername {FQDN} -showcerts "
        "</dev/null 2>/dev/null | grep -c 'BEGIN CERTIFICATE'"
    ).strip()
)
assert chain_certs >= 2, chain_certs
aws.succeed("curl -ks https://127.0.0.1:15000/roots/0 -o /tmp/pebble-root.pem")
aws.succeed(
    f"openssl s_client -connect {FQDN}:443 -servername {FQDN} "
    "-CAfile /tmp/pebble-root.pem -verify_return_error </dev/null 2>/dev/null"
)

# Pebble confirms it issued exactly the certificate the enclave serves.
leaf_serial = served_leaf(green, "-noout -serial").split("=", 1)[1].lower()
cert_status = json.loads(
    aws.succeed(f"curl -ks https://127.0.0.1:15000/cert-status-by-serial/{leaf_serial}")
)
assert cert_status["Status"] == "Valid", cert_status
aws.succeed(f"printf %s {shlex.quote(cert_status['Certificate'])} > /tmp/mgmt-leaf.pem")
mgmt_sha = aws.succeed(
    "openssl x509 -in /tmp/mgmt-leaf.pem -outform DER | sha256sum | cut -d' ' -f1"
).strip()
assert mgmt_sha == served_leaf_sha(green)

# The attestation is bound to the ACME leaf, and only the FQDN is served.
status, out = enclave_curl(green, GREEN_PCR0)
assert status == 0, out
status, _ = green.execute(
    "openssl s_client -connect 127.0.0.1:443 -servername other.example "
    "</dev/null 2>/dev/null | openssl x509 -noout -subject"
)
assert status != 0

cache_keys = cloud(
    f"s3api list-objects-v2 --bucket {tls_bucket} "
    "--query 'Contents[].Key' --output text"
).split()
assert f"dev/testapp/data/acme/{FQDN}" in cache_keys, cache_keys
assert all(k.startswith("dev/testapp/data/acme/") for k in cache_keys), cache_keys
aws.succeed("rm -rf /tmp/tls-cache")
cloud(f"s3 cp s3://{tls_bucket} /tmp/tls-cache --recursive")
_, pem_hits = aws.execute(
    "grep -rl 'BEGIN CERTIFICATE' /tmp/tls-cache 2>/dev/null; "
    "grep -rl 'PRIVATE KEY' /tmp/tls-cache 2>/dev/null; true"
)
assert pem_hits.strip() == "", pem_hits

# Restart green to prove the migrated slot reuses the encrypted S3 certificate
# cache while recovering non-genesis state.
leaf_sha_before = served_leaf_sha(green)
green.succeed("kill $(cat /run/enclave-qemu.pid)")
green.succeed("systemctl restart enclave-start")
wait_healthy(green)
assert served_leaf_sha(green) == leaf_sha_before
status, out = enclave_curl(green, GREEN_PCR0)
assert status == 0, out

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
assert (
    cloud("ec2 describe-addresses --query 'Addresses[0].InstanceId' --output text")
    == green_instance_id
)
wait_healthy(blue)
wait_healthy(green)

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
assert (
    cloud("ec2 describe-addresses --query 'Addresses[0].InstanceId' --output text")
    == green_instance_id
)

blue.shutdown()
wait_healthy(green)
