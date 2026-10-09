# default.nix prepends PCR0s, AWS_NODE_IP, and MIGRATION_COOLDOWN_SECONDS.
# default.nix also prepends helpers.py.
# The NixOS test driver injects aws, blue, blue_peer, green, and green_peer.

from datetime import datetime, timedelta, timezone

CERT_KEY = f"ark/e2e/dev/testapp/data/acme/{FQDN}/cert"
SELF_SIGNED_KEY = f"ark/e2e/dev/testapp/data/self-signed/{FQDN}/cert"
CHALLENGE_NAME = f"_acme-challenge.{FQDN}."
LOG_PREFIX = "/ark/e2e/dev/testapp/enclave"
INSTANCE_ID = "i-0e2ce2ce2ce2ce2ce"
BACKDATE_SECONDS = 48 * 3600
REPLAY_OBSERVATION_SECONDS = 10
INTENT_KEY = f"migration-intent/{BLUE_PCR0}/{1:020d}"
# Scalar 2 matches Blue's baked publicKey pin in default.nix.
BLUE_THIRD_SECRET = "00" * 31 + "02"
# Scalar 1 matches Green's baked publicKey pin in default.nix.
REPLACEMENT_SECRET = "00" * 31 + "01"
REPLACEMENT_PARAM = "/ark/e2e/dev/testapp/enclave/inherit/e2e-second-key-replacement"


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


def secret_ciphertexts(key_id):
    # Filter by the committed key: a losing concurrent handoff may leave an
    # orphan KMS key and its artifacts behind.
    prefix = "/ark/e2e/dev/testapp/enclave/unlocked"
    parameters = json.loads(
        cloud(f"ssm get-parameters-by-path --path {prefix}/ --recursive --output json")
    )["Parameters"]
    ciphertexts = {
        p["Name"]: p["Value"]
        for p in parameters
        if p["Name"].endswith(f"/Ciphertext/{key_id}")
    }
    expected = {
        f"{prefix}/MasterSeed/Ciphertext/{key_id}",
        f"{prefix}/TLSKey/Ciphertext/{key_id}",
    }
    assert set(ciphertexts) == expected, (
        f"committed snapshot must contain only MasterSeed and TLSKey ciphertexts: "
        f"{sorted(ciphertexts)}"
    )
    assert all(ciphertexts.values()), "committed secret ciphertexts must be nonempty"
    return ciphertexts


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


def intent_versions():
    out = json.loads(
        cloud(
            f"s3api list-object-versions --bucket {INTENT_BUCKET} "
            f"--prefix {INTENT_KEY} --output json"
        )
    )
    return [v for v in out.get("Versions", []) if v["Key"] == INTENT_KEY]


setup_aws()

# A hostile host starts a multipart upload before any genuine migration intent
# exists. AWS dates completed multipart objects from initiation; the ministack
# patch preserves that behavior. Only the AWS node's clock moves, before any
# enclaves start. The predictable first intent key lets us replay its future
# body and attestation with a timestamp older than the cooldown.
aws.succeed("systemctl stop systemd-timesyncd 2>/dev/null || true")
real_epoch = int(aws.succeed("date +%s").strip())
retain_until = (datetime.now(timezone.utc) + timedelta(days=30)).strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)
aws.succeed(f"date -u -s @{real_epoch - BACKDATE_SECONDS}")
try:
    upload_id = cloud(
        f"s3api create-multipart-upload --bucket {INTENT_BUCKET} "
        f"--key {INTENT_KEY} --content-type application/json "
        "--object-lock-mode COMPLIANCE "
        f"--object-lock-retain-until-date {retain_until} "
        "--query UploadId --output text"
    )
finally:
    aws.succeed(f"date -u -s @{real_epoch}")
assert upload_id, "multipart upload was not initiated"

aws.wait_for_open_port(14000)
aws.wait_for_open_port(8055)
aws.wait_for_open_port(4570)
aws.wait_until_succeeds(
    "curl -fsS --cacert /etc/pebble/ca.crt https://127.0.0.1:14000/dir "
    "| grep -q newOrder"
)

route53_zone_id = cloud(
    f"route53 create-hosted-zone --name {FQDN}. --caller-reference enclave-e2e "
    "--query HostedZone.Id --output text"
).rsplit("/", 1)[-1]
cloud(
    "ssm put-parameter --name /ark/e2e/dev/testapp/enclave/Route53ZoneID "
    f"--type String --value {route53_zone_id}"
)
put_env("E2E_OVERRIDE", "override-from-ssm")
cloud(
    "ssm put-parameter --name /ark/e2e/dev/testapp/enclave/inherit/e2e-third-key "
    f"--type String --value {BLUE_THIRD_SECRET}"
)

BLUES = (blue, blue_peer)
GREENS = (green, green_peer)
kms_keys_before_genesis = kms_key_count()

# Preflight runs before any durable write. With kms:CreateKey denied, both
# blues report the failure over /enclave/v1/info and leave no state behind.
aws.succeed("echo kms:CreateKey > /var/lib/awsmocks/iam-deny")
blue.start()
blue_peer.start()
for node in BLUES:
    node.wait_for_unit("multi-user.target")
    node.wait_for_unit("mock-imds-forward.service")
    node.wait_until_succeeds("curl -fsS http://169.254.169.254/health")
    node.wait_for_unit("enclave-start.service")
    node.wait_until_succeeds(
        "curl --connect-timeout 2 --max-time 5 -sk --http1.1 "
        "https://127.0.0.1/enclave/v1/info | jq -e '.status == \"failed\" "
        "and (.error | contains(\"kms:CreateKey\"))'",
        timeout=900,
    )
assert get_param(key_param(BLUE_PCR0)) == ""
assert kms_key_count() == kms_keys_before_genesis

# Both blues boot into genesis together: exactly one wins the lease and mints
# the key, the other resumes onto it. Restarting both before any wait is what
# creates the overlap.
aws.succeed("rm /var/lib/awsmocks/iam-deny")
for node in BLUES:
    node.succeed("kill $(cat /run/enclave-qemu.pid)")
    node.succeed("systemctl restart enclave-start")
for node in BLUES:
    wait_enclave_healthy(node)

for node in BLUES:
    assert env_value(node, "E2E_OVERRIDE") == "override-from-ssm"
    assert env_value(node, "E2E_INHERITED") == INHERITED
    assert env_value(node, "E2E_CUTOFF") == INHERITED
    assert env_value(node, "E2E_EXPIRED") == ""
    assert env_value(node, "E2E_THIRD_KEY") == BLUE_THIRD_SECRET
    second = env_value(node, "E2E_SECOND_KEY")
    assert len(second) == 64, second
    assert all(c in "0123456789abcdef" for c in second), second
    node.succeed(
        "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
        f"| jq -e --arg p '{BLUE_PCR0}' --arg bucket '{INTENT_BUCKET}' "
        "'.previous_pcr0 == \"genesis\" and .migration.state == \"none\" "
        "and .migration.source_pcr0 == $p "
        "and .migration_intent_bucket == $bucket'"
    )
blue_secret = secret_value(blue)
assert secret_value(blue_peer) == blue_secret
blue_second_secret = env_value(blue, "E2E_SECOND_KEY")
assert env_value(blue_peer, "E2E_SECOND_KEY") == blue_second_secret
assert REPLACEMENT_SECRET != blue_second_secret

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
tls_public_key = served_leaf(blue, "-noout -pubkey")
assert served_leaf(blue_peer, "-noout -pubkey") == tls_public_key
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

# Verify the CloudWatch Logs destinations.
log_groups = cloud(
    f"logs describe-log-groups --log-group-name-prefix {LOG_PREFIX} "
    "--query 'logGroups[].logGroupName' --output text"
).split()
assert sorted(log_groups) == [
    f"{LOG_PREFIX}/logs/app",
    f"{LOG_PREFIX}/logs/runtime",
], log_groups
streams = cloud(
    f"logs describe-log-streams --log-group-name {LOG_PREFIX}/logs/app "
    "--query 'logStreams[].logStreamName' --output text"
).split()
assert streams == [INSTANCE_ID], streams

# The buffers are gone, so their read-back endpoints are too.
blue.succeed(
    'test "$(curl -sk -o /dev/null -w %{http_code} --http1.1 '
    'https://127.0.0.1/v1/enclave-logs)" = 404'
)

# Verify application and runtime telemetry reaches each AWS endpoint.
blue.succeed("curl -skf --http1.1 https://127.0.0.1/test/health >/dev/null")


def otlp(signal):
    return json.loads(aws.succeed(f"curl -fsS http://127.0.0.1:4318/_otlp/{signal}"))


def wait_for_otlp(signal, needle, group=None, timeout=90):
    deadline = time.time() + timeout
    while True:
        for record in otlp(signal):
            if group is not None and record["group"] != group:
                continue
            if needle in json.dumps(record["body"], separators=(",", ":")):
                return record
        if time.time() > deadline:
            print(aws.execute("journalctl -u awsmocks --no-pager -n 50")[1])
            raise Exception(f"{needle!r} never reached the {signal} endpoint")
        time.sleep(2)


wait_for_otlp("logs", "handled health", f"{LOG_PREFIX}/logs/app")
wait_for_otlp("logs", "child started", f"{LOG_PREFIX}/logs/runtime")
wait_for_otlp("traces", '"name":"health"')
wait_for_otlp("traces", '"name":"init"')
wait_for_otlp("metrics", "testapp_requests_total")
wait_for_otlp("metrics", "enclave_http_requests_total")

for signal in ("logs", "traces", "metrics"):
    name = f"enclave_otlp_{signal}_forward_duration_seconds"
    record = wait_for_otlp("metrics", name)
    metric = next(
        m
        for resource in record["body"]["resourceMetrics"]
        for scope in resource["scopeMetrics"]
        for m in scope["metrics"]
        if m["name"] == name
    )
    assert metric["unit"] == "s", metric
    histogram = metric["histogram"]
    assert histogram["aggregationTemporality"] == "AGGREGATION_TEMPORALITY_CUMULATIVE", histogram
    assert histogram["dataPoints"], histogram
    for point in histogram["dataPoints"]:
        assert int(point["count"]) > 0, point
        assert point["sum"] > 0, point
        assert len(point["bucketCounts"]) == len(point["explicitBounds"]) + 1, point
        assert sum(int(n) for n in point["bucketCounts"]) == int(point["count"]), point

for record in otlp("logs"):
    assert record["stream"] == INSTANCE_ID, record
    body = json.dumps(record["body"], separators=(",", ":"))
    if record["group"] == f"{LOG_PREFIX}/logs/app":
        assert "enclave-runtime" not in body, body
        assert "child started" not in body, body

genesis_key = get_param(key_param(BLUE_PCR0))
assert genesis_key not in ("", "UNSET", "None")
blue_ciphertexts = secret_ciphertexts(genesis_key)
# Green's commit pointer is created by a blue when it commits; not yet.
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
wait_enclave_healthy(blue)

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
wait_enclave_healthy(blue)

# ACME settings are read when the runtime starts. The blues are already up and
# stay self-signed; green reads these as it boots and applies them once it
# promotes.
put_env("ENCLAVE_USE_ACME", "true")
put_env("ENCLAVE_ACME_DIRECTORY", f"https://{AWS_NODE_IP}:14000/dir")
put_env("ENCLAVE_ACME_EMAIL", f"acme-test@{FQDN}")
put_env("ENCLAVE_ACME_CA", aws.succeed("cat /etc/pebble/ca.crt"))

kms_keys_before_handoff = kms_key_count()

# Booting a candidate is the whole trigger: there is no admin endpoint and no
# request to send. The blues publish a challenge over SSM, green answers it, and
# a blue commits once the cooldown elapses.
green.start()
green.wait_for_unit("multi-user.target")
green.wait_for_unit("mock-imds-forward.service")
green.wait_until_succeeds("curl -fsS http://169.254.169.254/health")
green.wait_for_unit("enclave-start.service")

# Candidates serve neither the app nor attestation.
green.wait_until_succeeds(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    f"| jq -e --arg bucket '{INTENT_BUCKET}' "
    "'.status == \"candidate\" and .migration_intent_bucket == $bucket'",
    timeout=900,
)
health_status, _ = green.execute("curl -skf --http1.1 https://127.0.0.1/health")
assert health_status != 0, "a candidate must not report healthy"
secret_status, _ = green.execute(
    "curl -skf --http1.1 https://127.0.0.1/test/env/E2E_SIGNING_KEY"
)
assert secret_status != 0, "a candidate must serve no application request"
attestation_code = green.succeed(
    "curl -sk -o /dev/null -w '%{http_code}' --http1.1 "
    f"'https://127.0.0.1/enclave/attestation?nonce={'ab' * 20}'"
).strip()
assert attestation_code == "503", attestation_code

# Check transient candidate details before the AWS calls below, while Green
# is still awaiting the handoff.
green.wait_until_succeeds(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    f"| jq -e --arg b '{BLUE_PCR0}' "
    "'.candidate.awaiting_handoff_from == $b'",
    timeout=120,
)

# A blue records an intent naming green, derived from green's attestation. No
# operator wrote that PCR0 anywhere. The blues share one intent chain, so both
# report it whichever of them adopted green's answer.
for node in BLUES:
    node.wait_until_succeeds(
        "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
        f"| jq -e --arg p '{GREEN_PCR0}' "
        "'.migration.state == \"cooling_down\" and .migration.target_pcr0 == $p'",
        timeout=180,
    )
assert get_param(key_param(GREEN_PCR0)) == ""

# Both blues may publish the same request. Replay the earliest genuine version
# byte-for-byte; it is the one that determines the cooldown's start.
genuine = intent_versions()
assert genuine, "no genuine migration intent was published"
first_intent = min(genuine, key=lambda v: datetime.fromisoformat(v["LastModified"]))
genuine_last_modified = datetime.fromisoformat(first_intent["LastModified"])
eligible_at = genuine_last_modified + timedelta(seconds=MIGRATION_COOLDOWN_SECONDS)
genuine_ids = {v["VersionId"] for v in genuine}

cloud(
    f"s3api get-object --bucket {INTENT_BUCKET} --key {INTENT_KEY} "
    f"--version-id {first_intent['VersionId']} /tmp/replayed-intent.json >/dev/null"
)
part_etag = cloud(
    f"s3api upload-part --bucket {INTENT_BUCKET} --key {INTENT_KEY} "
    f"--upload-id {upload_id} --part-number 1 "
    "--body /tmp/replayed-intent.json --query ETag --output text"
)
complete_request = json.dumps({"Parts": [{"PartNumber": 1, "ETag": part_etag}]})
cloud(
    f"s3api complete-multipart-upload --bucket {INTENT_BUCKET} "
    f"--key {INTENT_KEY} --upload-id {upload_id} "
    f"--multipart-upload {shlex.quote(complete_request)}"
)

# The replay must really be backdated and identifiable as multipart even with
# one part. Read part 1 of each exact version, as the runtime does when scanning.
versions = intent_versions()
assert len(versions) == len(genuine) + 1, versions
for version in versions:
    metadata = json.loads(
        cloud(
            f"s3api get-object --bucket {INTENT_BUCKET} "
            f"--key {INTENT_KEY} --version-id {version['VersionId']} "
            "--part-number 1 --output json /dev/null"
        )
    )
    is_replay = version["VersionId"] not in genuine_ids
    assert ("PartsCount" in metadata) == is_replay, metadata
    if is_replay:
        assert metadata["PartsCount"] == 1, metadata
        backdated = datetime.fromisoformat(version["LastModified"])
        skew = (genuine_last_modified - backdated).total_seconds()
        assert skew >= BACKDATE_SECONDS - 60, (backdated, genuine_last_modified)

with subtest("multipart replay preserves the migration cooldown"):
    deadline = time.monotonic() + REPLAY_OBSERVATION_SECONDS
    try:
        for node in BLUES:
            node.succeed(
                "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
                f"| jq -e '.migration.remaining_seconds > {REPLAY_OBSERVATION_SECONDS}'"
            )
        while time.monotonic() < deadline:
            for node in BLUES:
                migration = json.loads(
                    node.succeed("curl -skf --http1.1 https://127.0.0.1/enclave/v1/info")
                )["migration"]
                assert migration["state"] == "cooling_down", (
                    f"{node.name}: multipart replay bypassed the migration cooldown: {migration}"
                )
                assert migration["target_pcr0"] == GREEN_PCR0, migration
                assert migration["remaining_seconds"] > 0, migration
                assert (
                    datetime.fromisoformat(migration["published_at"])
                    == genuine_last_modified
                ), migration
                assert (
                    datetime.fromisoformat(migration["eligible_at"]) == eligible_at
                ), migration
            assert get_param(key_param(GREEN_PCR0)) == "", (
                "handoff committed during cooldown"
            )
            green.succeed(
                "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
                "| jq -e '.status == \"candidate\"'"
            )
            time.sleep(1)
        for node in BLUES:
            assert console_has(node, "ignoring multipart migration intent"), node.name
    except Exception:
        for node in (*BLUES, green):
            print_enclave_diagnostics(node)
        raise

print("e2e-summary: multipart replay preserved the migration cooldown on both blues")

# A blue commits on its own once eligible.
migration_key = ""
for _ in range(MIGRATION_COOLDOWN_SECONDS + 120):
    migration_key = get_param(key_param(GREEN_PCR0))
    if migration_key not in ("", "UNSET", "None"):
        break
    time.sleep(1)
else:
    for node in BLUES:
        print_enclave_diagnostics(node)
    raise Exception("no blue committed the handoff")

assert migration_key != genesis_key
green_ciphertexts = secret_ciphertexts(migration_key)
assert secret_ciphertexts(genesis_key) == blue_ciphertexts
# The handoff writes only into green's scope: blue's pointer is untouched, which
# is what lets blue keep serving and reboot without any rollback machinery.
assert get_param(key_param(BLUE_PCR0)) == genesis_key
# Blue is genesis-born, so its own lineage is unchanged by handing off.
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

# The handoff receipt lives at the PCR0-scoped path, not the legacy key-only one.
# A create-only write onto it must be refused: that is exactly the collision a
# competing predecessor would hit. (This does not prove an *overwriting* write
# is refused — that is an IAM property, which LocalStack does not model.)
receipt_param = migration_receipt_param(migration_key, GREEN_PCR0)
assert get_param(receipt_param) not in ("", "UNSET", "None")
assert get_param(f"/ark/e2e/dev/testapp/enclave/MigrationStateOriginReceipt/{migration_key}") == ""
receipt_before = get_param(receipt_param)
create_only_status, _ = aws.execute(
    f"{CLOUD} ssm put-parameter --name {receipt_param} "
    "--type String --value tampered"
)
assert create_only_status != 0, "a create-only write must lose to the published receipt"
assert get_param(receipt_param) == receipt_before

# `blue_peer` shares BLUE_PCR0, so both blues run the control loop against the
# same intent chain and both reach the commit. The create-only write elects
# exactly one; the other observes an already-finalised migration and must not
# displace the pointer green is about to adopt.
assert len(console_owners(BLUES, "committed successor KMSKeyID")) == 1
assert get_param(key_param(GREEN_PCR0)) == migration_key
assert get_param(receipt_param) == receipt_before

# The blue fleet outlives the handoff it performed. Exactly one generation is
# committed for green; `blue_peer` keeps serving from state it established under
# the original key. The handoff writes predecessor information only into green's
# scope, so both blue nodes retain their genesis ancestry while reporting the
# migration intent targeting green.
for node in BLUES:
    wait_enclave_healthy(node)
    assert secret_value(node) == blue_secret
    assert env_value(node, "E2E_SECOND_KEY") == blue_second_secret
    assert env_value(node, "E2E_THIRD_KEY") == BLUE_THIRD_SECRET
    assert served_leaf_sha(node) == blue_leaf_sha
    node.wait_until_succeeds(
        "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
        f"| jq -e --arg t '{GREEN_PCR0}' "
        "'.previous_pcr0 == \"genesis\" and .migration.state == \"eligible\" "
        "and .migration.target_pcr0 == $t'"
    )
# A replica that raced past the pointer guard mints a key before losing the
# commit. It is an orphan, never referenced, but it does exist.
assert kms_key_count() in (
    kms_keys_before_handoff + 1,
    kms_keys_before_handoff + 2,
), (kms_key_count(), kms_keys_before_handoff)

# Green promotes in-process the moment a blue commits: no restart, and the host
# does nothing. Its real TLS configuration, with DNS-01 issuance, is applied then.
aws.wait_until_succeeds(
    "test -s /var/lib/route53-dns-proxy/events",
    timeout=900,
)
wait_enclave_healthy(green)
# Health and status share one lifecycle.
green.succeed(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    "| jq -e '.status == \"ready\"'"
)
assert secret_value(green) == blue_secret
assert env_value(green, "E2E_SECOND_KEY") == ""
green_third_secret = env_value(green, "E2E_THIRD_KEY")
assert len(green_third_secret) == 64, green_third_secret
assert all(c in "0123456789abcdef" for c in green_third_secret), green_third_secret
# Green derives its own value even while Blue's inherited value remains in SSM.
assert green_third_secret not in (blue_secret, blue_second_secret, BLUE_THIRD_SECRET)
assert served_leaf(green, "-noout -pubkey") == tls_public_key
green.succeed(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    f"| jq -e --arg prev '{BLUE_PCR0}' --arg current '{GREEN_PCR0}' "
    f"--arg bucket '{INTENT_BUCKET}' "
    "'.previous_pcr0 == $prev "
    "and (.previous_pcr0_attestation | length) > 0 "
    "and .migration.state == \"none\" "
    "and .migration.source_pcr0 == $current "
    "and .migration_intent_bucket == $bucket'"
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
# The ACME account key is derived; only encrypted certificates are stored.
assert sorted(cache_keys) == sorted([CERT_KEY, SELF_SIGNED_KEY]), cache_keys
aws.succeed("rm -rf /tmp/tls-cache")
cloud(f"s3 cp s3://{CERT_BUCKET} /tmp/tls-cache --recursive")
_, pem_hits = aws.execute(
    "grep -rl 'BEGIN CERTIFICATE' /tmp/tls-cache 2>/dev/null; "
    "grep -rl 'PRIVATE KEY' /tmp/tls-cache 2>/dev/null; true"
)
assert pem_hits.strip() == "", pem_hits
assert challenge_record_count(route53_zone_id) == 0

# Green omitted inherited B because its replacement was not available at boot.
# Populate it before the existing peer join and Green resume; the running
# Green keeps the omitted value until it resumes its established state.
assert get_param(REPLACEMENT_PARAM) == ""
assert env_value(green, "E2E_SECOND_KEY") == ""
cloud(
    f"ssm put-parameter --name {REPLACEMENT_PARAM} "
    f"--type String --value {REPLACEMENT_SECRET}"
)
assert env_value(green, "E2E_SECOND_KEY") == ""

# Snapshot the established fleet state before a same-EIF peer joins.
leaf_sha_before = served_leaf_sha(green)
leaf_serial_before = leaf_serial
cert_etag_before = cert_etag()
challenge_events_before = challenge_event_count()
kms_keys_before = kms_key_count()
assert cloud(
    f"ssm get-parameter --name {key_param(GREEN_PCR0)} --query Parameter.Value --output text"
) == migration_key

green_peer.start()
green_peer.wait_for_unit("multi-user.target")
green_peer.wait_for_unit("mock-imds-forward.service")
green_peer.wait_until_succeeds("curl -fsS http://169.254.169.254/health")
green_peer.wait_for_unit("enclave-start.service")
wait_enclave_healthy(green_peer)

# Joining must resume the committed state, not perform genesis or issue a cert.
assert cloud(
    f"ssm get-parameter --name {key_param(GREEN_PCR0)} --query Parameter.Value --output text"
) == migration_key
assert kms_key_count() == kms_keys_before
assert secret_value(green_peer) == blue_secret
assert env_value(green_peer, "E2E_SECOND_KEY") == REPLACEMENT_SECRET
assert env_value(green_peer, "E2E_THIRD_KEY") == green_third_secret
assert served_leaf(green_peer, "-noout -pubkey") == tls_public_key
assert env_value(green_peer, "E2E_OVERRIDE") == "override-from-ssm"
assert env_value(green_peer, "E2E_INHERITED") == INHERITED
assert env_value(green_peer, "E2E_CUTOFF") == INHERITED
assert env_value(green_peer, "E2E_EXPIRED") == ""
green_peer.succeed(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    f"| jq -e --arg prev '{BLUE_PCR0}' --arg current '{GREEN_PCR0}' "
    f"--arg bucket '{INTENT_BUCKET}' "
    "'.previous_pcr0 == $prev "
    "and (.previous_pcr0_attestation | length) > 0 "
    "and .migration.state == \"none\" "
    "and .migration.source_pcr0 == $current "
    "and .migration_intent_bucket == $bucket'"
)
assert served_leaf_sha(green_peer) == leaf_sha_before
assert served_leaf_sha(green) == leaf_sha_before
assert cert_etag() == cert_etag_before
assert challenge_event_count() == challenge_events_before
assert challenge_record_count(route53_zone_id) == 0

for node in GREENS:
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
green_origin_param = f"/ark/e2e/dev/testapp/enclave/StateOriginReceipt/{migration_key}/{GREEN_PCR0}"
green_origin_receipt = get_param(green_origin_param)
assert green_origin_receipt not in ("", "UNSET", "None")
green.succeed("kill $(cat /run/enclave-qemu.pid)")
green.wait_until_fails(
    "curl --connect-timeout 1 --max-time 2 -skf https://127.0.0.1/health",
    timeout=60,
)
wait_enclave_healthy(green_peer)
assert secret_value(green_peer) == blue_secret
assert env_value(green_peer, "E2E_SECOND_KEY") == REPLACEMENT_SECRET
assert env_value(green_peer, "E2E_THIRD_KEY") == green_third_secret
assert served_leaf_sha(green_peer) == leaf_sha_before
status, out = enclave_curl(green_peer, GREEN_PCR0, "/test/health")
assert status == 0, out

green.succeed("systemctl restart enclave-start")
wait_enclave_healthy(green)
assert served_leaf_sha(green) == leaf_sha_before
assert served_leaf(green, "-noout -serial").split("=", 1)[1].lower() == leaf_serial_before
assert secret_value(green) == blue_secret
assert env_value(green, "E2E_SECOND_KEY") == REPLACEMENT_SECRET
assert env_value(green, "E2E_THIRD_KEY") == green_third_secret
assert secret_ciphertexts(migration_key) == green_ciphertexts
assert cloud(
    f"ssm get-parameter --name {key_param(GREEN_PCR0)} --query Parameter.Value --output text"
) == migration_key
assert get_param(receipt_param) == receipt_before
assert get_param(green_origin_param) == green_origin_receipt
assert kms_key_count() == kms_keys_before
assert cert_etag() == cert_etag_before
assert challenge_event_count() == challenge_events_before
assert challenge_record_count(route53_zone_id) == 0
status, out = enclave_curl(green, GREEN_PCR0, "/test/health")
assert status == 0, out

# Green and green_peer were checked immediately above. Recheck that their
# kill/rejoin did not disturb the still-running blue fleet.
for node in (blue, blue_peer, green, green_peer):
    wait_enclave_healthy(node)

for node in BLUES:
    assert served_leaf_sha(node) == blue_leaf_sha
    assert secret_value(node) == blue_secret
    assert env_value(node, "E2E_SECOND_KEY") == blue_second_secret
    assert env_value(node, "E2E_THIRD_KEY") == BLUE_THIRD_SECRET

# Blue reboots onto its own untouched key long after handing off to green. This
# is what makes rollback machinery unnecessary: a failed successor is survived by
# leaving the predecessor running, and the predecessor is always restartable.
blue.succeed("kill $(cat /run/enclave-qemu.pid)")
blue.succeed("systemctl restart enclave-start")
wait_enclave_healthy(blue)
assert secret_value(blue) == blue_secret
assert env_value(blue, "E2E_SECOND_KEY") == blue_second_secret
assert env_value(blue, "E2E_THIRD_KEY") == BLUE_THIRD_SECRET
assert secret_ciphertexts(genesis_key) == blue_ciphertexts
assert served_leaf(blue, "-noout -pubkey") == tls_public_key
assert get_param(key_param(BLUE_PCR0)) == genesis_key
blue.succeed(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    "| jq -e '.previous_pcr0 == \"genesis\"'"
)
status, out = enclave_curl(blue, BLUE_PCR0)
assert status == 0, out

for node in (blue, blue_peer, green, green_peer):
    wait_enclave_healthy(node)

# Later declarations and the inherited replacement cannot change earlier fleets.
for node in (*BLUES, *GREENS):
    wait_enclave_healthy(node)
    assert env_value(node, "E2E_SIGNING_KEY") == blue_secret
    assert env_value(node, "E2E_SECOND_KEY") == (
        blue_second_secret if node in BLUES else REPLACEMENT_SECRET
    )
    assert env_value(node, "E2E_THIRD_KEY") == (
        BLUE_THIRD_SECRET if node in BLUES else green_third_secret
    )
    assert served_leaf(node, "-noout -pubkey") == tls_public_key
assert get_param(key_param(BLUE_PCR0)) == genesis_key
assert get_param(key_param(GREEN_PCR0)) == migration_key
assert get_param(receipt_param) == receipt_before
assert secret_ciphertexts(genesis_key) == blue_ciphertexts
assert secret_ciphertexts(migration_key) == green_ciphertexts

# KMS deletion has a mandatory waiting period. Scheduling the retired blue key
# must therefore appear as pending_deletion in green's ancestry.
cloud(
    f"kms schedule-key-deletion --key-id {shlex.quote(genesis_key)} "
    "--pending-window-in-days 7"
)
green.succeed("kill $(cat /run/enclave-qemu.pid)")
green.succeed("systemctl restart enclave-start")
wait_enclave_healthy(green)
green.wait_until_succeeds(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    f"| jq -e --arg key {shlex.quote(genesis_key)} "
    "'.ancestry.complete == true "
    "and (.ancestry.generations | length) == 1 "
    "and .ancestry.generations[0].key_id == $key "
    "and .ancestry.generations[0].state == \"pending_deletion\"'",
    timeout=60,
)

# The deletion is reversible. Blue cannot cold-start while its key is pending
# deletion, nor once cancelled, since cancelling leaves the key disabled; enabling
# it brings blue back on the same key and secret. The emulator does not evaluate
# key policies, so this proves the recovery, not the role's right to perform it.
restart_expecting_boot_failure(blue, "KMSInvalidStateException")
cloud(f"kms cancel-key-deletion --key-id {shlex.quote(genesis_key)}")
restart_expecting_boot_failure(blue, "DisabledException")
cloud(f"kms enable-key --key-id {shlex.quote(genesis_key)}")
blue.succeed("kill $(cat /run/enclave-qemu.pid) 2>/dev/null || true")
blue.succeed("systemctl restart enclave-start")
wait_enclave_healthy(blue)
assert secret_value(blue) == blue_secret
assert get_param(key_param(BLUE_PCR0)) == genesis_key

# An inherited secret reaching its cutoff while the app runs. The cutoff is
# baked into the image, so the node's clock is stepped to a minute before it
# and the enclave follows through /dev/ptp0. Last on purpose: from here this
# node disagrees with its peers about the time.
green_peer.succeed("systemctl stop systemd-timesyncd 2>/dev/null || true")
green_peer.succeed("date -u -s '2039-12-31 23:59:00'")
green_peer.wait_until_succeeds(
    "test $(curl -skf --http1.1 https://127.0.0.1/test/clock | jq .unix) -ge 2208988740",
    timeout=30,
)
assert env_value(green_peer, "E2E_CUTOFF") == INHERITED
green_peer.wait_until_succeeds(
    "grep 'inherited secret reached its cutoff' /var/log/enclave-console.log "
    "| grep -q e2e-cutoff",
    timeout=150,
)
# The runtime relaunches the app; the second "child started" is the new process.
green_peer.wait_until_succeeds(
    "test \"$(tr -d '\\000' </var/log/enclave-console.log "
    "| grep -c 'child started')\" -ge 2",
    timeout=60,
)
wait_upstream_healthy(green_peer)
assert env_value(green_peer, "E2E_CUTOFF") == ""
# It still holds everything that was not cut off.
assert secret_value(green_peer) == blue_secret
assert env_value(green_peer, "E2E_SECOND_KEY") == REPLACEMENT_SECRET
assert env_value(green_peer, "E2E_THIRD_KEY") == green_third_secret
assert env_value(green_peer, "E2E_INHERITED") == INHERITED
green_peer.succeed(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    "| jq -e '.status == \"ready\" and .upstream_app.exited == false'"
)
