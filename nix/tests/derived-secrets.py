# default.nix supplies measurements and helpers.py; the driver supplies nodes.
import hmac

EXTERNAL_KEY = "00" * 31 + "01"
DERIVED_NAME = "e2e-derived-signing-key"


def env_value(node, name):
    return node.succeed(
        f"curl -skf --http1.1 https://127.0.0.1/test/env/{name} | jq -r .value"
    ).strip()


def derive(seed, name):
    # Independent RFC 5869 implementation. CBOR is one UTF-8 text string;
    # these fixture names cross the shortest-length encoding boundary at 24.
    encoded = name.encode("utf-8")
    assert len(encoded) < 256
    prefix = (
        bytes([0x60 + len(encoded)])
        if len(encoded) < 24
        else bytes([0x78, len(encoded)])
    )
    prk = hmac.new(b"enclave.derived-secret.v1", bytes.fromhex(seed), hashlib.sha256).digest()
    return hmac.new(prk, prefix + encoded + b"\x01", hashlib.sha256).hexdigest()


def put_parameter(name, value):
    cloud(
        f"ssm put-parameter --name {name} --type String "
        f"--value {shlex.quote(value)} --overwrite"
    )


def start_node(node):
    node.start()
    node.wait_for_unit("enclave-start.service")
    wait_enclave_healthy(node)


def restart(node):
    node.succeed("kill $(cat /run/enclave-qemu.pid)")
    node.wait_until_fails(
        "curl --connect-timeout 1 --max-time 2 -skf https://127.0.0.1/health"
    )
    node.succeed("systemctl restart enclave-start")
    wait_enclave_healthy(node)


def seed_path(key):
    return f"/dev/testapp/unlocked/e2e-signing-key/Ciphertext/{key}"


def assert_persisted(pcr0):
    key = get_param(key_param(pcr0))
    assert key
    assert get_param(seed_path(key))
    names = json.loads(cloud("ssm describe-parameters --query 'Parameters[].Name' --output json"))
    assert not any(f"/{DERIVED_NAME}" in name for name in names), names
    return key


def wait_handoff(pcr0, nodes):
    try:
        aws.wait_until_succeeds(
            f"{CLOUD} ssm get-parameter --name {key_param(pcr0)}", timeout=120
        )
    except Exception:
        for node in nodes:
            print_enclave_diagnostics(node)
        raise


aws.start()
aws.wait_for_unit("multi-user.target")
for port in (4566, 4000, 1338):
    aws.wait_for_open_port(port)
aws.wait_until_succeeds("curl -fsS http://127.0.0.1:4566/_ministack/health")
cloud(f"s3api create-bucket --bucket {CERT_BUCKET}")
cloud(f"s3api create-bucket --bucket {LEASE_BUCKET}")
cloud(f"s3api create-bucket --bucket {INTENT_BUCKET} --object-lock-enabled-for-bucket")
cloud(
    f"s3api put-bucket-versioning --bucket {INTENT_BUCKET} "
    "--versioning-configuration Status=Enabled"
)
put_parameter("/dev/testapp/CertBucketName", CERT_BUCKET)
put_parameter("/dev/testapp/LeaseBucketName", LEASE_BUCKET)
put_parameter("/dev/testapp/env/ENCLAVE_FQDN", FQDN)
# Both paths are needed while predecessor and successor use different names.
for name in ("e2e-old-external-key", "e2e-external-signing-key"):
    put_parameter(f"/dev/testapp/inherit/{name}", EXTERNAL_KEY)

with subtest("untyped passthrough genesis"):
    start_node(blue)
    seed = secret_value(blue)
    assert seed != EXTERNAL_KEY
    assert env_value(blue, "E2E_DEPRECATED_KEYS") == EXTERNAL_KEY
    genesis_key = assert_persisted(BLUE_PCR0)

with subtest("passthrough handoff to hidden seed and concurrent derived replicas"):
    # Both candidates race to adopt the same passthrough predecessor's snapshot.
    green.start()
    green_peer.start()
    for node in (green, green_peer):
        node.wait_for_unit("enclave-start.service")
    wait_handoff(GREEN_PCR0, (blue, green, green_peer))
    for node in (green, green_peer):
        wait_enclave_healthy(node)
        assert secret_value(node) == derive(seed, DERIVED_NAME)
        assert secret_value(node) not in (seed, EXTERNAL_KEY)
        assert env_value(node, "E2E_HIDDEN_SEED") == ""
        assert env_value(node, "E2E_DEPRECATED_KEYS") == EXTERNAL_KEY
    green_key = assert_persisted(GREEN_PCR0)
    assert green_key != genesis_key
    # Crash/rejoin each predecessor after its handoff. Crashing before a new
    # handoff can leave a five-minute migration lease held by the dead process.
    restart(blue)
    assert secret_value(blue) == seed
    assert get_param(key_param(BLUE_PCR0)) == genesis_key
    blue.shutdown()

with subtest("third generation removes derivation and renames inherited secret"):
    start_node(third)
    assert secret_value(third) == EXTERNAL_KEY
    assert env_value(third, "E2E_HIDDEN_SEED") == ""
    assert env_value(third, "E2E_DEPRECATED_KEYS") == ""
    third_key = assert_persisted(THIRD_PCR0)
    assert third_key != green_key
    # Old replicas still use the old inherited name and the original derivation.
    restart(green)
    assert secret_value(green) == derive(seed, DERIVED_NAME)
    assert secret_value(green_peer) == secret_value(green)
    assert get_param(key_param(GREEN_PCR0)) == green_key
    assert env_value(green, "E2E_DEPRECATED_KEYS") == EXTERNAL_KEY
    green.shutdown()
    green_peer.shutdown()

with subtest("restore derivation remap export and rotate by name"):
    start_node(restored)
    assert env_value(restored, "E2E_RESTORED_KEY") == derive(seed, DERIVED_NAME)
    rotated = derive(seed, DERIVED_NAME + "-v2")
    assert secret_value(restored) == rotated
    assert rotated != env_value(restored, "E2E_RESTORED_KEY")
    assert env_value(restored, "E2E_DEPRECATED_KEYS") == EXTERNAL_KEY
    assert env_value(restored, "E2E_HIDDEN_SEED") == ""
    restored_key = assert_persisted(RESTORED_PCR0)
    restart(third)
    assert secret_value(third) == EXTERNAL_KEY
    assert get_param(key_param(THIRD_PCR0)) == third_key
    restart(restored)
    assert secret_value(restored) == rotated
    assert env_value(restored, "E2E_RESTORED_KEY") == derive(seed, DERIVED_NAME)
    assert get_param(key_param(RESTORED_PCR0)) == restored_key

print("e2e-summary: untyped passthrough -> seed/derived replicas -> inherited -> restored/name-rotated passed")
