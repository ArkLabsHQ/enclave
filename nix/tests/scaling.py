# default.nix prepends LEADER_IP and helpers.py.
# The NixOS test driver injects aws, leader, follower_a and follower_b.

SCALING_APPS = ("leader", "follower-a", "follower-b")
# A share is a secp256k1 scalar in [1, N).
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SHARE_URL = "https://127.0.0.1/test/env/SCALING_KEY"


def setup_scaling_app(app):
    """The per-app resources setup_aws creates for testapp."""
    digest = hashlib.sha256(f"ark/e2e/dev\x00{app}".encode()).digest()[:8].hex()
    bucket = f"enclave-{AWS_ACCOUNT_ID}-{digest}-migration-intents"
    cloud(f"s3api create-bucket --bucket {bucket} --object-lock-enabled-for-bucket")
    cloud(
        f"s3api put-bucket-versioning --bucket {bucket} "
        "--versioning-configuration Status=Enabled"
    )
    for name, value in (("CertBucketName", CERT_BUCKET), ("LeaseBucketName", LEASE_BUCKET)):
        cloud(
            f"ssm put-parameter --name /ark/e2e/dev/{app}/enclave/{name} "
            f"--type String --value {value}"
        )


def share(node):
    value = node.succeed(f"curl -skf --http1.1 {SHARE_URL} | jq -r .value").strip()
    assert len(value) == 64 and 0 < int(value, 16) < SECP256K1_N, value
    return value


def wait_share_change(node, old):
    """Wait until a reshare has restarted node's app with a share other than old."""
    node.wait_until_succeeds(
        f"curl -skf --http1.1 {SHARE_URL} | jq -e '.value != \"{old}\"'",
        timeout=300,
    )
    return share(node)


setup_aws()
for app in SCALING_APPS:
    setup_scaling_app(app)
for app in ("follower-a", "follower-b"):
    cloud(
        f"ssm put-parameter --name /ark/e2e/dev/{app}/enclave/env/ENCLAVE_SCALING_LEADER_ADDR "
        f"--type String --value https://{LEADER_IP}"
    )

# Alone, the leader signs with its leader secret and serves admission.
leader.start()
wait_enclave_healthy(leader)
leader_solo = share(leader)
leader.succeed("curl -skf https://127.0.0.1/enclave/handshake/nonce | base64 -d >/dev/null")

# The first follower boots only once it holds a share; the leader now signs with
# its own share instead of the leader secret.
follower_a.start()
wait_enclave_healthy(follower_a)
follower_a_v1 = share(follower_a)
wait_share_change(leader, leader_solo)

# The second join reshares the whole group: the first follower's share changes.
follower_b.start()
wait_enclave_healthy(follower_b)
follower_a_v2 = wait_share_change(follower_a, follower_a_v1)
follower_b_share = share(follower_b)
leader_share = share(leader)
assert len({leader_share, follower_a_v2, follower_b_share}) == 3, "shares must differ"
for node in (follower_a, follower_b):
    node.fail("curl -skf https://127.0.0.1/enclave/handshake/nonce")
print("scaling-summary: leader and two followers each hold a distinct share")

# A silent follower is evicted, and the survivors reshare without it.
follower_b.succeed("kill $(cat /run/enclave-qemu.pid)")
wait_share_change(follower_a, follower_a_v2)
leader.succeed(
    "tr -d '\\000' </var/log/enclave-console.log | tr '\\r' '\\n' "
    "| grep -qF 'threshold leader banned follower'"
)
print("scaling-summary: the leader evicted the silent follower and the survivors reshared")
