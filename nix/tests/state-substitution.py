# default.nix prepends BLUE_PCR0, GREEN_PCR0, AWS_NODE_IP, and helpers.py.
# The NixOS test driver injects aws, blue (A), and green (B).
# Establish A -> B, then substitute state under B's existing KMS key via Z.
# Z never runs: ENCLAVE_DEV accepts unsigned attestations but checks their
# PCRs and user_data. B must reject Z before adopting the substituted state.

import base64
import os
from datetime import datetime

import cbor2

SUBSTITUTED_CERT_BUCKET = "enclave-e2e-certificates-substituted"

# Z never runs; any canonical PCR0 distinct from the audited images works.
Z_PCR0 = "5a" * 48
Z_KEY_ID = "00000000-0000-4000-8000-000000000000"


def secret_ciphertext_param(name, key_id):
    return f"/dev/testapp/unlocked/{name}/Ciphertext/{key_id}"


def dek_ciphertext_param(key_id):
    return f"/dev/testapp/unlocked/StorageDEK/Ciphertext/{key_id}"


def tls_key_ciphertext_param(key_id):
    return f"/dev/testapp/unlocked/TLSKey/Ciphertext/{key_id}"


def state_receipt_param(key_id, pcr0):
    return f"/dev/testapp/StateOriginReceipt/{key_id}/{pcr0.lower()}"


def previous_pcr0_param(pcr0):
    return f"/dev/testapp/MigrationPreviousPCR0/{pcr0.lower()}"


def previous_key_param(pcr0):
    return f"/dev/testapp/MigrationPreviousKMSKeyID/{pcr0.lower()}"


def previous_attestation_param(pcr0):
    return f"/dev/testapp/MigrationPreviousPCR0Attestation/{pcr0.lower()}"


def put_param(name, value):
    cloud(
        f"ssm put-parameter --name {name} --type String --overwrite "
        f"--value {shlex.quote(value)}"
    )


def kms_encrypt_b64(key_id, plaintext_b64):
    # Encrypt carries no PCR0 condition in the runtime's generated KMS policy,
    # and the test KMS performs no attestation check for it at all.
    return cloud(
        f"kms encrypt --key-id {key_id} --plaintext {plaintext_b64} "
        "--query CiphertextBlob --output text"
    )


def attestation_b64(pcrs, user_data=None):
    document = {
        "module_id": "z-operator-image",
        "timestamp": int(time.time() * 1000),
        "digest": "SHA384",
        "pcrs": pcrs,
        "certificate": bytes(64),
        "cabundle": [bytes(64)],
    }
    if user_data is not None:
        document["user_data"] = user_data
    envelope = [cbor2.dumps({1: -35}), {}, cbor2.dumps(document), bytes(96)]
    return base64.b64encode(cbor2.dumps(envelope)).decode()


def decode_attestation(attestation):
    envelope = cbor2.loads(base64.b64decode(attestation))
    return cbor2.loads(envelope[2])


def pcr_extend_from_zero(pcr0_hex):
    # One Nitro extend step applied to an all-zero PCR (runtime/nsm.go).
    return hashlib.sha384(bytes(48) + bytes.fromhex(pcr0_hex)).digest()


def intent_user_data(sequence, action, target_pcr0):
    return cbor2.dumps(
        {
            "schema": "enclave.migration_intent.v1",
            "bucket_name": INTENT_BUCKET,
            "sequence": sequence,
            "action": action,
            "target_pcr0": target_pcr0,
        },
        canonical=True,
    )


def transition_user_data(root):
    # Ordinary encoding preserves the runtime's receipt struct field order.
    return cbor2.dumps({
        "purpose": "enclave.state_origin.migration_transition",
        "state_root": root,
    })


def state_root(
    owner_pcr0,
    key_id,
    predecessor_pcr0,
    predecessor_key_id,
    secret_ct_b64,
    dek_ct_b64,
    tls_key_ct_b64,
):
    """Encode the snapshot using the runtime's state-root schema."""
    owner = owner_pcr0.lower()

    def hashed(value_b64):
        return hashlib.sha256(base64.b64decode(value_b64)).digest()

    artifacts = [
        (key_param(owner), ("value", key_id)),
        ("migration-intent-bucket", ("value", INTENT_BUCKET)),
        (previous_pcr0_param(owner), ("value", predecessor_pcr0)),
        (previous_key_param(owner), ("value", predecessor_key_id)),
        (
            secret_ciphertext_param("e2e-signing-key", key_id),
            ("value_sha256", hashed(secret_ct_b64)),
        ),
        (dek_ciphertext_param(key_id), ("value_sha256", hashed(dek_ct_b64))),
        (tls_key_ciphertext_param(key_id), ("value_sha256", hashed(tls_key_ct_b64))),
    ]
    # All map keys are strings, so canonical ordering matches Go's CoreDet.
    encoded = cbor2.dumps(
        {
            "schema": "enclave.state_root.v1",
            "ssm_artifacts": [
                {"name": name, field: value} for name, (field, value) in artifacts
            ],
        },
        canonical=True,
    )
    digest = hashlib.sha256(b"enclave.state_root.v1\x00" + encoded).digest()
    return cbor2.dumps({"version": 1, "hash": digest}, canonical=True)


def boot_enclave_node(node):
    node.start()
    node.wait_for_unit("multi-user.target")
    node.wait_for_unit("mock-imds-forward.service")
    node.wait_until_succeeds("curl -fsS http://169.254.169.254/health")
    node.wait_for_unit("enclave-start.service")
    wait_healthy(node)


def expect_migration_rejection(node, key_id, expected_error):
    # The previous attempt may already have shut down after rejecting the state.
    node.succeed("systemctl stop enclave-start")
    node.wait_until_fails("kill -0 $(cat /run/enclave-qemu.pid)", timeout=60)
    log_offset = int(node.succeed("wc -c < /var/log/enclave-console.log"))
    node.succeed("systemctl start enclave-start")

    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        log = node.succeed(
            f"tail -c +{log_offset + 1} /var/log/enclave-console.log "
            "| tr -d '\\000' | tr '\\r' '\\n'"
        )
        events = []
        for line in log.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(event)
        failures = [event for event in events if event.get("msg") == "runtime failed"]
        if failures:
            error = failures[0].get("error", "")
            # Require the rejection specific to this attempt; unrelated startup
            # errors must not pass either the retention or authorization check.
            assert expected_error in error, (
                f"B failed for an unexpected reason: {error}"
            )
            assert not any(
                event.get("msg") in ("wrote state-origin receipt", "child started")
                for event in events
            ), "B adopted state or started the application before rejecting Z"
            assert cloud(
                f"ssm get-parameter --name {state_receipt_param(key_id, GREEN_PCR0)} "
                "--query Parameter.Value --output text"
            ) == "UNSET", (
                "B wrote an origin receipt before rejecting Z"
            )
            node.fail(
                "curl --connect-timeout 2 --max-time 5 -skf --http1.1 "
                "https://127.0.0.1/test/health"
            )
            return events
        status, _ = node.execute(
            "curl --connect-timeout 2 --max-time 5 -skf --http1.1 "
            "https://127.0.0.1/health | jq -e '.status == \"ready\"'"
        )
        assert status != 0, (
            "B accepted the unauthorized migration from Z and became ready; "
            "expected rejection before adopting substituted state"
        )
        time.sleep(1)
    print_enclave_diagnostics(node)
    raise AssertionError("B neither rejected Z nor became ready within 180 seconds")


def request_migration(node, target_pcr0):
    for _ in range(30):
        status, _ = node.execute(
            "rm -f /tmp/request-migration.json; "
            "curl --fail-with-body -sS -H 'Content-Type: application/json' "
            f'--data \'{{"action":"requested","target_pcr0":"{target_pcr0}"}}\' '
            "--output /tmp/request-migration.json "
            "http://127.0.0.1:8003/request-migration"
        )
        valid, _ = node.execute(
            f"jq -e --arg p '{target_pcr0}' "
            "'.target_pcr0 == $p and "
            '(.state == "cooling_down" or .state == "eligible")\' '
            "/tmp/request-migration.json"
        )
        if status == 0 and valid == 0:
            break
        time.sleep(1)
    else:
        print(node.execute("cat /tmp/request-migration.json 2>/dev/null || true")[1])
        print_enclave_diagnostics(node)
        raise Exception(f"request-migration to {target_pcr0} did not succeed")
    node.wait_until_succeeds(
        "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
        '| jq -e \'.migration.state == "eligible"\'',
        timeout=120,
    )


def finalise_migration(node, target_pcr0):
    # Finalising is not idempotent: once it commits, a retry is a 409. Stop
    # POSTing as soon as the committed pointer is readable.
    for _ in range(60):
        node.execute(
            "rm -f /tmp/finalise-migration.json; "
            "curl --fail-with-body -sS -H 'Content-Type: application/json' "
            f'--data \'{{"new_pcr0":"{target_pcr0}"}}\' '
            "--output /tmp/finalise-migration.json "
            "http://127.0.0.1:8003/finalise-migration"
        )
        committed_key = get_param(key_param(target_pcr0))
        if committed_key not in ("", "UNSET", "None"):
            return committed_key
        time.sleep(1)
    print(node.execute("cat /tmp/finalise-migration.json 2>/dev/null || true")[1])
    print_enclave_diagnostics(node)
    raise Exception(f"finalise-migration to {target_pcr0} did not commit")


with subtest("AWS fixtures"):
    # Self-signed TLS; the substituted DEK needs a fresh certificate cache.
    aws.start()
    aws.wait_for_unit("multi-user.target")
    aws.wait_for_open_port(4566)
    aws.wait_until_succeeds("curl -fsS http://127.0.0.1:4566/_ministack/health")
    aws.wait_for_open_port(4000)
    aws.wait_for_open_port(1338)

    cloud(f"s3api create-bucket --bucket {CERT_BUCKET}")
    cloud(f"s3api create-bucket --bucket {SUBSTITUTED_CERT_BUCKET}")
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
    cloud(
        "ssm put-parameter --name /dev/testapp/env/ENCLAVE_FQDN "
        f"--type String --value {FQDN}"
    )


with subtest("Establish legitimate A -> B lineage"):
    boot_enclave_node(blue)
    key_a = get_param(key_param(BLUE_PCR0))
    assert key_a not in ("", "UNSET", "None")
    blue_secret = secret_value(blue)

    request_migration(blue, GREEN_PCR0)
    key_b = finalise_migration(blue, GREEN_PCR0)
    assert key_b != key_a

    boot_enclave_node(green)
    green.succeed(
        "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
        f"| jq -e --arg prev '{BLUE_PCR0}' '.previous_pcr0 == $prev'"
    )
    assert secret_value(green) == blue_secret

    # B's genuine origin receipt is the baseline for checking fixture encodings.
    r_ba = get_param(state_receipt_param(key_b, GREEN_PCR0))
    assert r_ba not in ("", "UNSET", "None")


with subtest("Validate fixture encodings against live artifacts"):
    # Byte-compare both encoders with artifacts from the legitimate migration.
    s0_secret_ct = get_param(secret_ciphertext_param("e2e-signing-key", key_b))
    s0_dek_ct = get_param(dek_ciphertext_param(key_b))
    s0_tls_key_ct = get_param(tls_key_ciphertext_param(key_b))
    recomputed_root_ba = state_root(
        GREEN_PCR0, key_b, BLUE_PCR0, key_a, s0_secret_ct, s0_dek_ct, s0_tls_key_ct
    )
    r_ba_payload = cbor2.loads(decode_attestation(r_ba)["user_data"])
    assert r_ba_payload["state_root"] == recomputed_root_ba, (
        "state_root reimplementation mismatch"
    )

    intent_key_ab = f"migration-intent/{BLUE_PCR0}/00000000000000000001"
    cloud(
        f"s3api get-object --bucket {INTENT_BUCKET} --key {intent_key_ab} "
        "/tmp/ab-intent.json >/dev/null"
    )
    ab_intent = json.loads(aws.succeed("cat /tmp/ab-intent.json"))
    ab_intent_doc = decode_attestation(ab_intent["attestation"])
    assert ab_intent_doc["user_data"] == intent_user_data(1, "requested", GREEN_PCR0), (
        "intent encoding mismatch"
    )
    print("encoder validation: recomputed root_BA and the A->B intent payload match")


with subtest("Create operator-chosen replacement state"):
    # New static secret, storage DEK, and TLS key, all chosen by and known to the
    # operator, encrypted under B's *existing* KMS key. KB's policy is not touched.
    s1_secret = os.urandom(32)
    s1_dek = os.urandom(32)
    # genpkey's DER output is SEC1, but the runtime parses PKCS8; convert explicitly.
    aws.succeed(
        "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 "
        "-out /tmp/s1-tls-key.pem && "
        "openssl pkcs8 -topk8 -nocrypt -in /tmp/s1-tls-key.pem "
        "-outform DER -out /tmp/s1-tls-key.der"
    )
    s1_tls_key_der_b64 = aws.succeed("base64 -w0 /tmp/s1-tls-key.der").strip()
    s1_secret_ct = kms_encrypt_b64(key_b, base64.b64encode(s1_secret).decode())
    s1_dek_ct = kms_encrypt_b64(key_b, base64.b64encode(s1_dek).decode())
    s1_tls_key_ct = kms_encrypt_b64(key_b, s1_tls_key_der_b64)


with subtest("Attempt state substitution through Z"):
    # Q_Z: Z's predecessor attestation — PCR0 = Z, PCR31 = extend-from-zero(B),
    # empty user_data (runtime/boot.go predecessorExpectedPCRs).
    q_z = attestation_b64({0: bytes.fromhex(Z_PCR0), 31: pcr_extend_from_zero(GREEN_PCR0)})

    # MayGet treats "UNSET" as absent, forcing migration adoption on B's reboot.
    put_param(state_receipt_param(key_b, GREEN_PCR0), "UNSET")
    put_param(previous_pcr0_param(GREEN_PCR0), Z_PCR0)
    put_param(previous_key_param(GREEN_PCR0), Z_KEY_ID)
    put_param(previous_attestation_param(GREEN_PCR0), q_z)
    put_param(secret_ciphertext_param("e2e-signing-key", key_b), s1_secret_ct)
    put_param(dek_ciphertext_param(key_b), s1_dek_ct)
    put_param(tls_key_ciphertext_param(key_b), s1_tls_key_ct)

    # T_ZB: Z's transition receipt over exactly the snapshot B will read.
    root_bz = state_root(
        GREEN_PCR0, key_b, Z_PCR0, Z_KEY_ID, s1_secret_ct, s1_dek_ct, s1_tls_key_ct
    )
    t_zb = attestation_b64(
        {0: bytes.fromhex(Z_PCR0), 31: pcr_extend_from_zero(GREEN_PCR0)},
        transition_user_data(root_bz),
    )
    put_param(migration_receipt_param(key_b, GREEN_PCR0), t_zb)

    # Reuse this Z -> B intent for both retention and authorization checks.
    z_intent_attestation = attestation_b64(
        {0: bytes.fromhex(Z_PCR0)}, intent_user_data(1, "requested", GREEN_PCR0)
    )
    z_intent_body = json.dumps(
        {
            "schema": "enclave.migration_intent.v1",
            "sequence": 1,
            "action": "requested",
            "target_pcr0": GREEN_PCR0,
            "attestation": z_intent_attestation,
        },
        separators=(",", ":"),
    )
    aws.succeed(f"printf %s {shlex.quote(z_intent_body)} > /tmp/z-intent.json")

    # A substituted DEK cannot open the old certificate cache, and the cached cert
    # would not match the substituted TLS key; point B at a fresh bucket so it
    # issues a replacement self-signed certificate during the adopted boot.
    put_param("/dev/testapp/CertBucketName", SUBSTITUTED_CERT_BUCKET)



with subtest("B rejects Z's intent without compliance retention"):
    z_intent_key = f"migration-intent/{Z_PCR0}/00000000000000000001"
    cloud(
        f"s3api put-object --bucket {INTENT_BUCKET} --key {z_intent_key} "
        "--body /tmp/z-intent.json"
    )
    events = expect_migration_rejection(green, key_b, "migration intent: absent")
    assert any(
        event.get("msg")
        == "ignoring migration intent that is not retained under compliance mode"
        and event.get("key") == z_intent_key
        for event in events
    ), "B did not reject Z's intent for missing compliance retention"


with subtest("B rejects the unauthorized migration from Z with compliance retention"):
    # Publish another version of the same intent with the runtime's dev retention.
    # The unlocked version remains present and must be ignored by the reader.
    retain_until = aws.succeed("date -u -d '+10 minutes' +%Y-%m-%dT%H:%M:%SZ").strip()
    retained = json.loads(cloud(
        f"s3api put-object --bucket {INTENT_BUCKET} --key {z_intent_key} "
        "--body /tmp/z-intent.json --object-lock-mode COMPLIANCE "
        f"--object-lock-retain-until-date {retain_until}"
    ))
    metadata = json.loads(cloud(
        f"s3api get-object --bucket {INTENT_BUCKET} --key {z_intent_key} "
        f"--version-id {shlex.quote(retained['VersionId'])} /tmp/z-intent-retained.json"
    ))
    assert metadata["ObjectLockMode"] == "COMPLIANCE"
    assert datetime.fromisoformat(metadata["ObjectLockRetainUntilDate"]) == (
        datetime.fromisoformat(retain_until)
    ), "Z's intent did not retain the requested compliance deadline"
    expect_migration_rejection(
        green, key_b, "does not match previous PCR0 committed in the EIF"
    )
