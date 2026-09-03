# default.nix prepends BLUE_PCR0, GREEN_PCR0, and AWS_NODE_IP.
# The NixOS test driver injects aws, blue, blue_peer, green, and green_peer.

import hashlib
import json
import shlex
import time

CLOUD = "aws --no-cli-pager --endpoint-url http://127.0.0.1:4566 --region us-east-1"
AWS_ACCOUNT_ID = "000000000000"
FQDN = "enclave.test"
CERT_BUCKET = "enclave-e2e-certificates"
LEASE_BUCKET = "enclave-e2e-leases"
INTENT_DIGEST = hashlib.sha256(b"dev\x00testapp").digest()[:8].hex()
INTENT_BUCKET = f"enclave-{AWS_ACCOUNT_ID}-{INTENT_DIGEST}-migration-intents"
CERT_KEY = f"dev/testapp/data/acme/{FQDN}/cert"
ACCOUNT_KEY = "dev/testapp/data/acme/account.key"
SELF_SIGNED_KEY = f"dev/testapp/data/self-signed/{FQDN}/cert"
CHALLENGE_NAME = f"_acme-challenge.{FQDN}."


def cloud(command):
    return aws.succeed(f"{CLOUD} {command}").strip()


def key_param(pcr0):
    return f"/dev/testapp/unlocked/KMSKeyID/{pcr0}"


def get_param(name):
    status, out = aws.execute(
        f"{CLOUD} ssm get-parameter --name {name} --query Parameter.Value --output text"
    )
    return out.strip() if status == 0 else ""


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


def console_has(node, needle):
    status, _ = node.execute(
        "tr -d '\\000' </var/log/enclave-console.log | tr '\\r' '\\n' "
        f"| grep -F {shlex.quote(needle)} >/dev/null"
    )
    return status == 0


def console_owners(nodes, needle):
    return [n.name for n in nodes if console_has(n, needle)]


def enclave_curl(node, pcr0, path="/health"):
    # QEMU's NSM cannot sign or supply an AWS chain. PCR0, nonce, the exact
    # 39-byte TLS binding, and live certificate pinning remain checked.
    return node.execute(
        f"enclave curl {path} --base-url https://127.0.0.1 "
        f"--expected-pcr0 {pcr0} --insecure-skip-cose-verify 2>&1"
    )


def kms_key_count():
    return int(cloud("kms list-keys --query 'length(Keys)' --output text"))


def cert_etag():
    return cloud(
        f"s3api head-object --bucket {CERT_BUCKET} --key {CERT_KEY} "
        "--query ETag --output text"
    )


def challenge_event_count():
    return int(
        aws.succeed(
            "test -e /var/lib/route53-dns-proxy/events "
            "&& wc -l < /var/lib/route53-dns-proxy/events || printf 0"
        ).strip()
    )


def challenge_record_count(zone_id):
    return int(
        cloud(
            f"route53 list-resource-record-sets --hosted-zone-id {zone_id} "
            f"--query \"length(ResourceRecordSets[?Name=='{CHALLENGE_NAME}' "
            "&& Type=='TXT'])\" --output text"
        )
    )


def env_value(node, name):
    return node.succeed(
        f"curl -skf --http1.1 https://127.0.0.1/test/env/{name} | jq -r .value"
    ).strip()


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
aws.wait_for_open_port(8055)
aws.wait_for_open_port(4570)
aws.wait_until_succeeds(
    "curl -fsS --cacert /etc/pebble/ca.crt https://127.0.0.1:14000/dir "
    "| grep -q newOrder"
)

# Create only the AWS resources consumed by the runtime.
cloud(f"s3api create-bucket --bucket {CERT_BUCKET}")
cloud(f"s3api create-bucket --bucket {LEASE_BUCKET}")
cloud(
    f"s3api create-bucket --bucket {INTENT_BUCKET} "
    "--object-lock-enabled-for-bucket"
)
cloud(
    f"s3api put-bucket-versioning --bucket {INTENT_BUCKET} "
    "--versioning-configuration Status=Enabled"
)
cloud(
    "ssm put-parameter --name /dev/testapp/CertBucketName "
    f"--type String --value {CERT_BUCKET}"
)
cloud(
    "ssm put-parameter --name /dev/testapp/LeaseBucketName "
    f"--type String --value {LEASE_BUCKET}"
)
route53_zone_id = cloud(
    f"route53 create-hosted-zone --name {FQDN}. --caller-reference enclave-e2e "
    "--query HostedZone.Id --output text"
).rsplit("/", 1)[-1]
cloud(
    "ssm put-parameter --name /dev/testapp/Route53ZoneID "
    f"--type String --value {route53_zone_id}"
)
put_env("E2E_OVERRIDE", "override-from-ssm")
put_env("ENCLAVE_NITRIDING_FQDN", FQDN)

BLUES = (blue, blue_peer)
kms_keys_before_genesis = kms_key_count()

# Both blues boot into genesis together: exactly one wins the lease and mints
# the key, the other resumes onto it. start() is asynchronous, so issuing both
# before any wait is what creates the overlap.
blue.start()
blue_peer.start()
for node in BLUES:
    node.wait_for_unit("multi-user.target")
    node.wait_for_unit("mock-imds-forward.service")
    node.wait_until_succeeds("curl -fsS http://169.254.169.254/health")
    node.wait_for_unit("enclave-start.service")
    wait_healthy(node)

for node in BLUES:
    assert env_value(node, "E2E_OVERRIDE") == "override-from-ssm"
    node.succeed(
        "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
        f"| jq -e --arg p '{BLUE_PCR0}' "
        "'.previous_pcr0 == \"genesis\" and .migration.state == \"none\" "
        "and .migration.source_pcr0 == $p'"
    )
blue_secret = secret_value(blue)
assert secret_value(blue_peer) == blue_secret

for node in BLUES:
    leaf_issuer = served_leaf(node, "-noout -issuer")
    assert "AWS Nitro enclave application" in leaf_issuer, leaf_issuer
    leaf_subject = served_leaf(node, "-noout -subject")
    assert "AWS Nitro enclave application" in leaf_subject, leaf_subject
    leaf_san = served_leaf(node, "-noout -ext subjectAltName")
    assert f"DNS:{FQDN}" in leaf_san, leaf_san

# The fleet shares one self-signed certificate: a client that pinned the leaf
# from either enclave must reach the other.
blue_leaf_sha = served_leaf_sha(blue)
assert served_leaf_sha(blue_peer) == blue_leaf_sha
assert len(console_owners(BLUES, "renewed the fleet certificate")) == 1

# One stored object for the whole fleet, not one per enclave.
cache_keys = cloud(
    f"s3api list-objects-v2 --bucket {CERT_BUCKET} "
    "--query 'Contents[].Key' --output text"
)
assert cache_keys == SELF_SIGNED_KEY, cache_keys
for node in BLUES:
    status, out = enclave_curl(node, BLUE_PCR0)
    assert status == 0, out
    assert "WARNING" in out, out

log_groups = cloud(
    "logs describe-log-groups --log-group-name-prefix /enclave/dev/testapp "
    "--query 'logGroups[].logGroupName' --output text"
).split()
assert sorted(log_groups) == [
    "/enclave/dev/testapp/logs",
    "/enclave/dev/testapp/metrics",
    "/enclave/dev/testapp/traces",
], log_groups

shipped = cloud(
    "logs describe-log-streams --log-group-name /enclave/dev/testapp/logs "
    "--query 'logStreams[].storedBytes' --output text"
)
assert shipped not in ("", "None"), shipped

# The buffers are gone, so their read-back endpoints are too.
blue.succeed(
    'test "$(curl -sk -o /dev/null -w %{http_code} --http1.1 '
    'https://127.0.0.1/v1/enclave-logs)" = 404'
)

# The app's own OTLP reaches CloudWatch through the runtime's ingest endpoints,
# emitted by the stock OpenTelemetry exporters.
blue.succeed("curl -skf --http1.1 https://127.0.0.1/test/health >/dev/null")


def wait_for_shipped(group, needle, timeout=90):
    deadline = time.time() + timeout
    while True:
        events = cloud(
            f"logs filter-log-events --log-group-name /enclave/dev/testapp/{group} "
            "--query 'events[].message' --output text"
        )
        if needle in events:
            return
        if time.time() > deadline:
            raise Exception(f"{needle!r} never reached /enclave/dev/testapp/{group}")
        time.sleep(2)


wait_for_shipped("logs", "handled health")
wait_for_shipped("traces", '"name":"health"')
wait_for_shipped("metrics", "testapp_requests_total")

genesis_key = get_param(key_param(BLUE_PCR0))
assert genesis_key not in ("", "UNSET", "None")
# Green's commit pointer is created by blue at finalise; it must not exist yet.
assert get_param(key_param(GREEN_PCR0)) == ""

# Once present, the Object-Locked deployment-genesis object decides that the
# deployment exists independently of KMSKeyID. Its fixed, identity-independent
# key means deleting the parameter cannot reopen genesis, and one enclave's
# completed genesis vetoes every later one.
genesis_records = cloud(
    f"s3api list-object-versions --bucket {INTENT_BUCKET} "
    "--prefix deployment-genesis "
    "--query 'Versions[].Key' --output text"
).split()
assert genesis_records == ["deployment-genesis"], genesis_records

# Exactly one enclave ran genesis; the other resumed onto its key.
minted = console_owners(BLUES, "created primary KMS key")
resumed = console_owners(BLUES, "genesis completed by a peer")
assert len(minted) == 1, minted
assert len(resumed) <= 1, resumed
assert not set(minted) & set(resumed), (minted, resumed)
assert kms_key_count() == kms_keys_before_genesis + 1
print(f"genesis race: minted={minted} resumed={resumed}")

# And it is not a migration intent: the creator's own intent chain stays empty.
intent_records = cloud(
    f"s3api list-object-versions --bucket {INTENT_BUCKET} "
    f"--prefix migration-intent/{BLUE_PCR0}/ "
    "--query 'Versions[].Key' --output text"
).split()
assert intent_records in ([], ["None"]), intent_records

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
migration_key = ""
finalise_output = ""
committed = False
for attempt in range(30):
    if not committed:
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
        # Finalising is not idempotent: once it commits, a retry is a 409. Stop
        # POSTing and just wait for the pointer to be readable.
        committed = finalise_status == 0
    if committed or attempt % 3 == 2:
        migration_key = get_param(key_param(GREEN_PCR0))
        if migration_key != "":
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
assert migration_key not in ("", "UNSET", "None")
assert migration_key != genesis_key
# The handoff writes only into green's scope: blue's pointer is untouched, which
# is what lets blue keep serving and reboot without any rollback machinery.
assert get_param(key_param(BLUE_PCR0)) == genesis_key
# Blue is genesis-born, so its own lineage is unchanged by having finalised.
blue.succeed(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    "| jq -e '.previous_pcr0 == \"genesis\"'"
)
# The migration key admits green alone: blue can write under it but not read.
aws.succeed(
    f"{CLOUD} kms get-key-policy --key-id {migration_key} --policy-name default "
    "--query Policy --output text > /tmp/migration-key-policy.json"
)
aws.succeed(
    f"jq -e --arg g {shlex.quote(GREEN_PCR0)} "
    "'[.Statement[].Condition.StringEqualsIgnoreCase"
    '."kms:RecipientAttestation:PCR0"] | map(select(. != null)) | flatten '
    "| . == [$g]' /tmp/migration-key-policy.json"
)

# The blue fleet outlives the handoff it performed. Only `blue` was asked to
# finalise, so exactly one migration key exists; `blue_peer` keeps serving from
# state it established under the retired key. Both now report themselves as
# their own predecessor, because finalise records the finalising PCR0 and the
# fleet shares it — so "genesis" is no longer the expected value here.
for node in BLUES:
    wait_healthy(node)
    assert secret_value(node) == blue_secret
    assert served_leaf_sha(node) == blue_leaf_sha
    node.wait_until_succeeds(
        "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
        f"| jq -e --arg p '{BLUE_PCR0}' --arg t '{GREEN_PCR0}' "
        "'.previous_pcr0 == $p and .migration.state == \"eligible\" "
        "and .migration.target_pcr0 == $t'"
    )
assert kms_key_count() == kms_keys_before_genesis + 2

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
# DNS-01 issuance is part of boot, not triggered by the first TLS request.
aws.wait_until_succeeds(
    "test -s /var/lib/route53-dns-proxy/events",
    timeout=900,
)
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

# The ancestor-key audit must name blue as the one prior generation and report
# its key as live: blue's key was never deleted, so anything else -- and
# "deleted" above all -- would be a false retirement receipt.
green.wait_until_succeeds(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    f"| jq -e --arg prev '{BLUE_PCR0}' "
    "'.ancestry.checked_at != null "
    "and .ancestry.complete == true "
    "and (.ancestry.generations | length) == 1 "
    "and .ancestry.generations[0].pcr0 == $prev "
    "and (.ancestry.generations[0].key_id | length) > 0 "
    "and .ancestry.generations[0].state == \"exists\" "
    "and (.ancestry | has(\"genesis\") | not)'",
    timeout=60,
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
status, _ = aws.execute(
    f"openssl s_client -connect {FQDN}:443 -servername other.example "
    "-verify_hostname other.example -verify_return_error "
    "-CAfile /tmp/pebble-root.pem </dev/null >/dev/null 2>&1"
)
assert status != 0

cache_keys = cloud(
    f"s3api list-objects-v2 --bucket {CERT_BUCKET} "
    "--query 'Contents[].Key' --output text"
).split()
assert sorted(cache_keys) == sorted(
    [CERT_KEY, ACCOUNT_KEY, SELF_SIGNED_KEY]
), cache_keys
aws.succeed("rm -rf /tmp/tls-cache")
cloud(f"s3 cp s3://{CERT_BUCKET} /tmp/tls-cache --recursive")
_, pem_hits = aws.execute(
    "grep -rl 'BEGIN CERTIFICATE' /tmp/tls-cache 2>/dev/null; "
    "grep -rl 'PRIVATE KEY' /tmp/tls-cache 2>/dev/null; true"
)
assert pem_hits.strip() == "", pem_hits
assert challenge_record_count(route53_zone_id) == 0

# Snapshot the established fleet state before a same-EIF peer joins.
leaf_sha_before = served_leaf_sha(green)
leaf_serial_before = leaf_serial
cert_etag_before = cert_etag()
challenge_events_before = challenge_event_count()
kms_keys_before = kms_key_count()
assert cloud(
    f"ssm get-parameter --name {key_param} --query Parameter.Value --output text"
) == migration_key

green_peer.start()
green_peer.wait_for_unit("multi-user.target")
green_peer.wait_for_unit("mock-imds-forward.service")
green_peer.wait_until_succeeds("curl -fsS http://169.254.169.254/health")
green_peer.wait_for_unit("enclave-start.service")
wait_healthy(green_peer)

# Joining must resume the committed state, not perform genesis or issue a cert.
assert cloud(
    f"ssm get-parameter --name {key_param} --query Parameter.Value --output text"
) == migration_key
assert kms_key_count() == kms_keys_before
assert secret_value(green_peer) == blue_secret
assert env_value(green_peer, "E2E_OVERRIDE") == "override-from-ssm"
green_peer.succeed(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    f"| jq -e --arg prev '{BLUE_PCR0}' --arg current '{GREEN_PCR0}' "
    "'.previous_pcr0 == $prev "
    "and (.previous_pcr0_attestation | length) > 0 "
    "and .migration.state == \"none\" "
    "and .migration.source_pcr0 == $current'"
)
assert served_leaf_sha(green_peer) == leaf_sha_before
assert served_leaf_sha(green) == leaf_sha_before
assert cert_etag() == cert_etag_before
assert challenge_event_count() == challenge_events_before
assert challenge_record_count(route53_zone_id) == 0

for node in (green, green_peer):
    status, out = enclave_curl(node, GREEN_PCR0, "/test/health")
    assert status == 0, out
    for _ in range(5):
        node.succeed(
            "curl -skf --http1.1 https://127.0.0.1/test/health >/dev/null; "
            "curl -skf --http1.1 https://127.0.0.1/test/env/E2E_SIGNING_KEY >/dev/null; "
            "curl -skf --http1.1 https://127.0.0.1/test/env/E2E_OVERRIDE >/dev/null"
        )
    node.succeed(
        "pids=''; for _ in $(seq 1 5); do "
        "curl -skf --http1.1 https://127.0.0.1/test/health >/dev/null & "
        "pids=\"$pids $!\"; done; "
        "for pid in $pids; do wait \"$pid\"; done"
    )

# Scale one node in while its peer remains live, then rejoin the same fleet.
green.succeed("kill $(cat /run/enclave-qemu.pid)")
green.wait_until_fails(
    "curl --connect-timeout 1 --max-time 2 -skf https://127.0.0.1/health",
    timeout=60,
)
wait_healthy(green_peer)
assert secret_value(green_peer) == blue_secret
assert served_leaf_sha(green_peer) == leaf_sha_before
status, out = enclave_curl(green_peer, GREEN_PCR0, "/test/health")
assert status == 0, out

green.succeed("systemctl restart enclave-start")
wait_healthy(green)
assert served_leaf_sha(green) == leaf_sha_before
assert served_leaf(green, "-noout -serial").split("=", 1)[1].lower() == leaf_serial_before
assert secret_value(green) == blue_secret
assert cloud(
    f"ssm get-parameter --name {key_param} --query Parameter.Value --output text"
) == migration_key
assert kms_key_count() == kms_keys_before
assert cert_etag() == cert_etag_before
assert challenge_event_count() == challenge_events_before
assert challenge_record_count(route53_zone_id) == 0
status, out = enclave_curl(green, GREEN_PCR0, "/test/health")
assert status == 0, out

# Green and green_peer were checked immediately above. Recheck that their
# kill/rejoin did not disturb the still-running blue fleet.
for node in (blue, blue_peer, green, green_peer):
    wait_healthy(node)

for node in BLUES:
    assert served_leaf_sha(node) == blue_leaf_sha
    assert secret_value(node) == blue_secret

# Blue reboots onto its own untouched key long after handing off to green. This
# is what makes rollback machinery unnecessary: a failed successor is survived by
# leaving the predecessor running, and the predecessor is always restartable.
blue.succeed("kill $(cat /run/enclave-qemu.pid)")
blue.succeed("systemctl restart enclave-start")
wait_healthy(blue)
assert secret_value(blue) == blue_secret
assert get_param(key_param(BLUE_PCR0)) == genesis_key
blue.succeed(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    "| jq -e '.previous_pcr0 == \"genesis\"'"
)
status, out = enclave_curl(blue, BLUE_PCR0)
assert status == 0, out

for node in (blue, blue_peer, green, green_peer):
    wait_healthy(node)

# KMS deletion has a mandatory waiting period. Scheduling the retired blue key
# must therefore appear as pending_deletion in green's ancestry.
cloud(
    f"kms schedule-key-deletion --key-id {shlex.quote(genesis_key)} "
    "--pending-window-in-days 7"
)
green.succeed("kill $(cat /run/enclave-qemu.pid)")
green.succeed("systemctl restart enclave-start")
wait_healthy(green)
green.wait_until_succeeds(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    f"| jq -e --arg key {shlex.quote(genesis_key)} "
    "'.ancestry.complete == true "
    "and (.ancestry.generations | length) == 1 "
    "and .ancestry.generations[0].key_id == $key "
    "and .ancestry.generations[0].state == \"pending_deletion\" "
    "and .ancestry.generations[0].deletion_date != null'",
    timeout=60,
)
