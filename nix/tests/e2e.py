# default.nix prepends BLUE_PCR0, GREEN_PCR0, and AWS_NODE_IP.
# The NixOS test driver injects aws, blue, and green.

import json
import shlex
import time

CLOUD = "aws --no-cli-pager --endpoint-url http://127.0.0.1:4566 --region us-east-1"
FQDN = "enclave.test"
TLS_BUCKET = "enclave-e2e-tls-cache"
INTENT_BUCKET = "enclave-e2e-migration-intent"


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


def print_enclave_diagnostics(node):
    print(
        node.execute(
            "echo '=== qemu ==='; "
            "if [ -s /run/enclave-qemu.pid ]; then "
            "pid=$(cat /run/enclave-qemu.pid); "
            "echo pid=$pid; "
            'if kill -0 "$pid" 2>/dev/null; then echo alive=yes; else echo alive=no; fi; '
            "else echo pidfile=missing; fi; "
            "ls -l /dev/kvm; "
            "ps -eo pid,ppid,stat,pcpu,comm,args | grep '[q]emu-system' || true"
        )[1]
    )
    print(
        node.execute(
            "systemctl status vhost-device-vsock enclave-heartbeat gvproxy "
            "imds-proxy migration-proxy mock-imds-forward enclave-start "
            "--no-pager 2>&1"
        )[1]
    )
    print(
        node.execute(
            "journalctl -u vhost-device-vsock -u enclave-heartbeat -u gvproxy "
            "-u imds-proxy -u migration-proxy -u mock-imds-forward "
            "-u enclave-start --no-pager -n 150 2>&1"
        )[1]
    )
    print(
        node.execute(
            "echo '=== enclave console ==='; "
            "if [ -e /var/log/enclave-console.log ]; then "
            "echo bytes=$(wc -c </var/log/enclave-console.log); "
            "tr -d '\\000' </var/log/enclave-console.log | tr '\\r' '\\n' "
            "| tail -n 160; "
            "echo '=== enclave console hex tail ==='; "
            "tail -c 256 /var/log/enclave-console.log | od -An -tx1; "
            "else echo missing; fi"
        )[1]
    )


def wait_healthy(node):
    try:
        node.wait_until_succeeds(
            "curl --connect-timeout 2 --max-time 5 -skf --http1.1 "
            'https://127.0.0.1/health | jq -e ".status == \\"ready\\""',
            timeout=900,
        )
        node.wait_until_succeeds(
            "curl --connect-timeout 2 --max-time 5 -skf --http1.1 "
            'https://127.0.0.1/test/health | jq -e ".status == \\"ok\\""',
            timeout=300,
        )
    except Exception:
        print_enclave_diagnostics(node)
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

# Create only the AWS resources consumed by the runtime.
cloud(f"s3api create-bucket --bucket {TLS_BUCKET}")
cloud(
    f"s3api create-bucket --bucket {INTENT_BUCKET} "
    "--object-lock-enabled-for-bucket"
)
cloud(
    f"s3api put-bucket-versioning --bucket {INTENT_BUCKET} "
    "--versioning-configuration Status=Enabled"
)
cloud(
    "ssm put-parameter --name /dev/testapp/TLSCacheBucketName "
    f"--type String --value {TLS_BUCKET}"
)
cloud(
    "ssm put-parameter --name /dev/testapp/MigrationIntentBucketName "
    f"--type String --value {INTENT_BUCKET}"
)
put_env("E2E_OVERRIDE", "override-from-ssm")
put_env("ENCLAVE_NITRIDING_FQDN", FQDN)

blue.start()
blue.wait_for_unit("multi-user.target")
blue.wait_for_unit("mock-imds-forward.service")
blue.wait_until_succeeds("curl -fsS http://169.254.169.254/health")
blue.wait_for_unit("enclave-start.service")
wait_healthy(blue)
blue.succeed(
    "test \"$(curl -skf --http1.1 "
    "https://127.0.0.1/test/env/E2E_OVERRIDE "
    "| jq -r .value)\" = override-from-ssm"
)
blue_secret = secret_value(blue)
blue.succeed(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
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
    f"s3api list-objects-v2 --bucket {TLS_BUCKET} "
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

# Exercise both the hard-step and PI-servo paths against the real /dev/ptp0.
host_ts = int(blue.succeed("date +%s").strip())
enclave_ts = int(
    blue.succeed(
        "curl -skf --http1.1 https://127.0.0.1/test/clock | jq .unix"
    ).strip()
)
assert abs(enclave_ts - host_ts) <= 2, (enclave_ts, host_ts)
blue.succeed(
    "grep -q 'clock sync: initial hard-step to hypervisor PTP completed' "
    "/var/log/enclave-console.log"
)

initial_hardsteps = int(
    blue.succeed(
        "grep -c 'clock sync: hard-step' /var/log/enclave-console.log || true"
    ).strip()
)
clock_resp = json.loads(
    blue.succeed(
        "curl -skf --http1.1 -X POST -H 'Content-Type: application/json' "
        "--data '{\"offset_seconds\":5}' https://127.0.0.1/test/clock"
    )
)
skewed_ts = clock_resp["after"]["unix"]
host_ts_after = int(blue.succeed("date +%s").strip())
assert skewed_ts - host_ts_after >= 3, (skewed_ts, host_ts_after)
blue.wait_until_succeeds(
    f"test \"$(grep -c 'clock sync: hard-step' /var/log/enclave-console.log)\" "
    f"-ge {initial_hardsteps + 1}",
    timeout=30,
)
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

hardsteps_before_sub = int(
    blue.succeed(
        "grep -c 'clock sync: hard-step' /var/log/enclave-console.log || true"
    ).strip()
)
log_lines_before = int(blue.succeed("wc -l < /var/log/enclave-console.log").strip())
blue.succeed(
    "curl -skf --http1.1 -X POST -H 'Content-Type: application/json' "
    "--data '{\"offset_ms\":50}' https://127.0.0.1/test/clock"
)
blue.wait_until_succeeds(
    f"tail -n +{log_lines_before + 1} /var/log/enclave-console.log "
    "| grep 'clock sync: disciplined' "
    "| jq -e 'select(.offset_us != null and (.offset_us | fabs) >= 30000)'",
    timeout=15,
)
_, sub_lines = blue.execute(
    f"tail -n +{log_lines_before + 1} /var/log/enclave-console.log "
    "| grep 'clock sync: disciplined' || true"
)
max_offset_us = 0.0
for line in sub_lines.splitlines():
    try:
        entry = json.loads(line)
    except ValueError:
        continue
    max_offset_us = max(max_offset_us, abs(float(entry.get("offset_us", 0))))
assert max_offset_us >= 30000, max_offset_us
hardsteps_after_sub = int(
    blue.succeed(
        "grep -c 'clock sync: hard-step' /var/log/enclave-console.log || true"
    ).strip()
)
assert hardsteps_after_sub == hardsteps_before_sub, (
    hardsteps_before_sub,
    hardsteps_after_sub,
)
wait_healthy(blue)

# Green remains off until blue has atomically committed the handoff.
migration_request_output = ""
for _ in range(30):
    migration_status, migration_request_output = blue.execute(
        "rm -f /tmp/request-migration.json; "
        "curl --fail-with-body -sS -H 'Content-Type: application/json' "
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
    time.sleep(1)
else:
    print(migration_request_output)
    print(blue.execute("cat /tmp/request-migration.json 2>/dev/null || true")[1])
    print_enclave_diagnostics(blue)
    raise Exception("request-migration did not succeed")

assert (
    int(
        cloud(
            f"s3api list-object-versions --bucket {INTENT_BUCKET} "
            "--query 'length(Versions)' --output text"
        )
    )
    >= 1
)
blue.wait_until_succeeds(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    "| jq -e '.migration.state == \"eligible\"'",
    timeout=120,
)

finalise_response_valid = False
migration_key = genesis_key
finalise_output = ""
for attempt in range(30):
    finalise_status, finalise_output = blue.execute(
        "rm -f /tmp/finalise-migration.json; "
        "curl --fail-with-body -sS -H 'Content-Type: application/json' "
        f"--data '{{\"new_pcr0\":\"{GREEN_PCR0}\"}}' "
        "--output /tmp/finalise-migration.json "
        "http://127.0.0.1:8003/finalise-migration"
    )
    response_status, _ = blue.execute(
        f"jq -e --arg p '{BLUE_PCR0}' "
        "'.pcr0 == $p and (.exported | index(\"e2e-signing-key\"))' "
        "/tmp/finalise-migration.json"
    )
    if finalise_status == 0 and response_status == 0:
        finalise_response_valid = True
    if finalise_status == 0 or attempt % 3 == 2:
        migration_key = cloud(
            f"ssm get-parameter --name {key_param} "
            "--query Parameter.Value --output text"
        )
        if migration_key != genesis_key:
            break
    time.sleep(1)
else:
    print(finalise_output)
    print(blue.execute("cat /tmp/finalise-migration.json 2>/dev/null || true")[1])
    print_enclave_diagnostics(blue)
    raise Exception("finalise-migration did not commit")

if finalise_response_valid:
    blue.succeed(
        f"jq -e --arg p '{BLUE_PCR0}' "
        "'.pcr0 == $p and (.exported | index(\"e2e-signing-key\"))' "
        "/tmp/finalise-migration.json"
    )
assert migration_key != genesis_key

# ACME settings are loaded once at boot, so blue remains self-signed.
put_env("ENCLAVE_NITRIDING_USE_ACME", "true")
put_env("ENCLAVE_NITRIDING_ACME_DIRECTORY", f"https://{AWS_NODE_IP}:14000/dir")
put_env("ENCLAVE_NITRIDING_ACME_EMAIL", f"acme-test@{FQDN}")
put_env("ENCLAVE_NITRIDING_ACME_CA", aws.succeed("cat /etc/pebble/ca.crt"))

green.start()
green.wait_for_unit("multi-user.target")
green.wait_for_unit("mock-imds-forward.service")
green.wait_until_succeeds("curl -fsS http://169.254.169.254/health")
green.wait_for_unit("enclave-start.service")
wait_healthy(green)
assert secret_value(green) == blue_secret
green.succeed(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    f"| jq -e --arg prev '{BLUE_PCR0}' --arg current '{GREEN_PCR0}' "
    "'.previous_pcr0 == $prev "
    "and (.previous_pcr0_attestation | length) > 0 "
    "and .migration.state == \"none\" "
    "and .migration.source_pcr0 == $current'"
)

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

leaf_serial = served_leaf(green, "-noout -serial").split("=", 1)[1].lower()
cert_status = json.loads(
    aws.succeed(
        f"curl -ks https://127.0.0.1:15000/cert-status-by-serial/{leaf_serial}"
    )
)
assert cert_status["Status"] == "Valid", cert_status
aws.succeed(
    f"printf %s {shlex.quote(cert_status['Certificate'])} > /tmp/mgmt-leaf.pem"
)
mgmt_sha = aws.succeed(
    "openssl x509 -in /tmp/mgmt-leaf.pem -outform DER "
    "| sha256sum | cut -d' ' -f1"
).strip()
assert mgmt_sha == served_leaf_sha(green)

status, out = enclave_curl(green, GREEN_PCR0)
assert status == 0, out
status, _ = green.execute(
    "openssl s_client -connect 127.0.0.1:443 -servername other.example "
    "</dev/null 2>/dev/null | openssl x509 -noout -subject"
)
assert status != 0

cache_keys = cloud(
    f"s3api list-objects-v2 --bucket {TLS_BUCKET} "
    "--query 'Contents[].Key' --output text"
).split()
assert f"dev/testapp/data/acme/{FQDN}" in cache_keys, cache_keys
assert all(k.startswith("dev/testapp/data/acme/") for k in cache_keys), cache_keys
aws.succeed("rm -rf /tmp/tls-cache")
cloud(f"s3 cp s3://{TLS_BUCKET} /tmp/tls-cache --recursive")
_, pem_hits = aws.execute(
    "grep -rl 'BEGIN CERTIFICATE' /tmp/tls-cache 2>/dev/null; "
    "grep -rl 'PRIVATE KEY' /tmp/tls-cache 2>/dev/null; true"
)
assert pem_hits.strip() == "", pem_hits

leaf_sha_before = served_leaf_sha(green)
green.succeed("kill $(cat /run/enclave-qemu.pid)")
green.succeed("systemctl restart enclave-start")
wait_healthy(green)
assert served_leaf_sha(green) == leaf_sha_before
status, out = enclave_curl(green, GREEN_PCR0)
assert status == 0, out

wait_healthy(blue)
wait_healthy(green)
