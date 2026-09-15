# default.nix prepends image PCR0s and helpers.py; the driver supplies aws/blue/green.
APPS = {
    "appOne": {"port": 8443, "control": 18003, "blue": APP_ONE_PCR0, "green": APP_ONE_PCR0},
    "appTwo": {"port": 9443, "control": 18004, "blue": APP_TWO_PCR0, "green": SUCCESSOR_PCR0},
}
initial = {}
routes = {app: blue for app in APPS}


def fqdn(app):
    return f"{app.lower()}.enclave.test"


def intent_bucket(app):
    digest = hashlib.sha256(f"dev\x00{app}".encode()).digest()[:8].hex()
    return f"enclave-{AWS_ACCOUNT_ID}-{digest}-migration-intents"


def app_json(node, app, path="/enclave/v1/info"):
    return json.loads(node.succeed(
        f"curl --connect-timeout 2 --max-time 10 -skf --http1.1 "
        f"https://127.0.0.1:{APPS[app]['port']}{path}"
    ))


def control_probe(node, app):
    # Invalid JSON is rejected before migration handling; never create a migration intent.
    node.wait_until_succeeds(
        "test \"$(curl --connect-timeout 2 --max-time 8 -s -o /dev/null "
        "-w '%{http_code}' -H 'Content-Type: application/json' --data '{' "
        f"http://127.0.0.1:{APPS[app]['control']}/request-migration)\" = 400",
        timeout=60,
    )


def certificate_key(app):
    return f"dev/{app}/data/acme/{fqdn(app)}/cert"


def stored_etags(app):
    return {
        key: cloud(f"s3api head-object --bucket {CERT_BUCKET} --key {key} --query ETag --output text")
        for key in (certificate_key(app), f"dev/{app}/data/acme/account.key")
    }


def dns_events():
    events = aws.succeed("cat /var/lib/route53-dns-proxy/events").splitlines()
    return {
        app: sum(line.split()[0].rstrip(".") == f"_acme-challenge.{fqdn(app)}" for line in events)
        for app in APPS
    }


def assert_dns_clean():
    for app in APPS:
        records = cloud(
            f"route53 list-resource-record-sets --hosted-zone-id {zone_id} "
            f"--query \"length(ResourceRecordSets[?Name=='_acme-challenge.{fqdn(app)}.' "
            "&& Type=='TXT'])\" --output text"
        )
        assert int(records) == 0, (app, records)


def snapshot(node, app, pcr0):
    port = APPS[app]["port"]
    return {
        "secret": secret_value(node, port),
        "key": get_param(key_param(pcr0, app)),
        "leaf": served_leaf_sha(node, port, fqdn(app)),
        "tls_key": served_leaf(node,
            "-pubkey -noout | openssl pkey -pubin -outform DER "
            "| sha256sum | cut -d' ' -f1", port, fqdn(app)),
        "migration": app_json(node, app)["migration"],
        "objects": stored_etags(app),
    }


def assert_serving(node, app, pcr0, initial):
    port = APPS[app]["port"]
    wait_healthy(node, port, app)
    assert env_value(node, "ENCLAVE_APP_NAME", port) == app
    status, out = enclave_curl(node, pcr0, "/test/health", port)
    assert status == 0, (node.name, app, out)
    assert secret_value(node, port) == initial["secret"]
    assert served_leaf_sha(node, port, fqdn(app)) == initial["leaf"]
    assert served_leaf(node,
        "-pubkey -noout | openssl pkey -pubin -outform DER "
        "| sha256sum | cut -d' ' -f1", port, fqdn(app)) == initial["tls_key"]
    assert stored_etags(app) == initial["objects"]


def client_json(app, path="/health"):
    # Preserve the application's hostname, SNI and public port across cutover.
    target = routes[app]
    port = APPS[app]["port"]
    return json.loads(aws.succeed(
        "curl --connect-timeout 2 --max-time 10 -sf --http1.1 "
        f"--cacert /tmp/pebble-root.pem --connect-to {fqdn(app)}:{port}:{target.name}:{port} "
        f"https://{fqdn(app)}:{port}{path}"
    ))


def assert_app_one_unchanged():
    assert get_param(key_param(APP_ONE_PCR0, "appOne")) == initial["appOne"]["key"]
    for node in (blue, green):
        assert_serving(node, "appOne", APP_ONE_PCR0, initial["appOne"])
        assert app_json(node, "appOne")["migration"] == initial["appOne"]["migration"]
    records = cloud(
        f"s3api list-object-versions --bucket {intent_bucket('appOne')} "
        "--prefix migration-intent/ --query 'Versions[].Key' --output text"
    ).split()
    assert records in ([], ["None"]), records


def migrate(node, app, source_pcr0, target_pcr0, source_key):
    # As in the original E2E, a lost control reply must not cause a committed
    # finalisation to be repeated. The successor pointer is the commit marker.
    payload = shlex.quote(json.dumps({"action": "requested", "target_pcr0": target_pcr0}))
    for _ in range(30):
        status, out = node.execute(
            "curl --connect-timeout 2 --max-time 15 --fail-with-body -sS "
            f"-H 'Content-Type: application/json' --data {payload} "
            f"http://127.0.0.1:{APPS[app]['control']}/request-migration"
        )
        state = app_json(node, app)["migration"]
        if state.get("target_pcr0") == target_pcr0 and state["state"] in ("cooling_down", "eligible"):
            if status == 0:
                assert json.loads(out)["target_pcr0"] == target_pcr0
            break
        time.sleep(1)
    else:
        raise AssertionError(f"{app} request-migration failed: {out}")
    info = app_json(node, app)
    assert info["migration_cooldown_seconds"] == 2, info
    from datetime import datetime
    assert (
        datetime.fromisoformat(state["eligible_at"].replace("Z", "+00:00"))
        - datetime.fromisoformat(state["published_at"].replace("Z", "+00:00"))
    ).total_seconds() == 2
    node.wait_until_succeeds(
        f"curl -skf --http1.1 https://127.0.0.1:{APPS[app]['port']}/enclave/v1/info "
        "| jq -e '.migration.state == \"eligible\"'", timeout=120,
    )
    for _ in range(30):
        committed_key = get_param(key_param(target_pcr0, app))
        if committed_key:
            break
        status, out = node.execute(
            "curl --connect-timeout 2 --max-time 30 --fail-with-body -sS "
            f"-X POST http://127.0.0.1:{APPS[app]['control']}/finalise-migration"
        )
        if status == 0:
            result = json.loads(out)
            assert result["pcr0"] == source_pcr0, result
            assert "e2e-signing-key" in result["exported"], result
        time.sleep(1)
    else:
        raise AssertionError(f"{app} finalise-migration failed: {out}")
    assert committed_key not in ("", "UNSET", "None", source_key)
    assert get_param(key_param(source_pcr0, app)) == source_key
    receipt = get_param(migration_receipt_param(committed_key, target_pcr0, app))
    assert receipt not in ("", "UNSET", "None")
    policy = json.loads(cloud(
        f"kms get-key-policy --key-id {committed_key} --policy-name default --query Policy --output text"
    ))
    recipients = []
    for statement in policy["Statement"]:
        value = statement.get("Condition", {}).get("StringEqualsIgnoreCase", {}).get("kms:RecipientAttestation:PCR0")
        if value is not None:
            recipients.extend(value if isinstance(value, list) else [value])
    assert recipients == [target_pcr0], policy
    return committed_key


try:
    aws.start()
    aws.wait_for_unit("multi-user.target")
    for port in (4566, 4000, 1338, 14000, 8055, 4570):
        aws.wait_for_open_port(port)
    aws.wait_until_succeeds("curl -fsS http://127.0.0.1:4566/_ministack/health")
    aws.wait_until_succeeds(
        "curl -fsS --cacert /etc/pebble/ca.crt https://127.0.0.1:14000/dir | grep -q newOrder"
    )
    cloud(f"s3api create-bucket --bucket {CERT_BUCKET}")
    cloud(f"s3api create-bucket --bucket {LEASE_BUCKET}")
    zone_id = cloud(
        "route53 create-hosted-zone --name enclave.test. --caller-reference multi-enclave "
        "--query HostedZone.Id --output text"
    ).rsplit("/", 1)[-1]
    ca = aws.succeed("cat /etc/pebble/ca.crt")
    for app in APPS:
        bucket = intent_bucket(app)
        cloud(f"s3api create-bucket --bucket {bucket} --object-lock-enabled-for-bucket")
        cloud(f"s3api put-bucket-versioning --bucket {bucket} --versioning-configuration Status=Enabled")
        for name, value in {
            "CertBucketName": CERT_BUCKET, "LeaseBucketName": LEASE_BUCKET, "Route53ZoneID": zone_id,
        }.items():
            cloud(f"ssm put-parameter --name /dev/{app}/{name} --type String --value {value}")
        for name, value in {
            "ENCLAVE_FQDN": fqdn(app),
            "ENCLAVE_USE_ACME": "true",
            "ENCLAVE_ACME_DIRECTORY": f"https://{AWS_NODE_IP}:14000/dir",
            "ENCLAVE_ACME_EMAIL": f"acme-test@{fqdn(app)}",
            "ENCLAVE_ACME_CA": ca,
        }.items():
            put_env(name, value, app)

    with subtest("Blue startup and independent issuance"):
        blue.start()
        blue.wait_for_unit("multi-user.target")
        # Both launch units start at boot, before readiness is awaited for either app.
        for app, config in APPS.items():
            blue.wait_for_unit(f"enclave-start-{app}.service")
            wait_healthy(blue, config["port"], app)
            assert env_value(blue, "ENCLAVE_APP_NAME", config["port"]) == app
            status, out = enclave_curl(blue, config["blue"], port=config["port"])
            assert status == 0, out
            control_probe(blue, app)
        print("transport proof: both CIDs reach gvproxy, IMDS, heartbeat and independent control port 8003")
        assert APP_ONE_PCR0 != APP_TWO_PCR0
        assert APP_TWO_PCR0 != SUCCESSOR_PCR0
        aws.succeed("curl -ks https://127.0.0.1:15000/roots/0 -o /tmp/pebble-root.pem")
        for app, config in APPS.items():
            initial[app] = snapshot(blue, app, config["blue"])
            assert initial[app]["key"] not in ("", "UNSET", "None")
            assert initial[app]["migration"]["state"] == "none"
            assert initial[app]["migration"]["source_pcr0"] == config["blue"]
            assert app_json(blue, app)["previous_pcr0"] == "genesis"
            assert "Pebble" in served_leaf(blue, "-noout -issuer", config["port"], fqdn(app))
            assert client_json(app)["status"] == "ready"
            assert client_json(app, "/test/env/ENCLAVE_APP_NAME")["value"] == app
        for field in ("secret", "key", "leaf", "tls_key"):
            assert initial["appOne"][field] != initial["appTwo"][field], field
        objects = cloud(
            f"s3api list-objects-v2 --bucket {CERT_BUCKET} --query 'Contents[].Key' --output text"
        ).split()
        assert sorted(objects) == sorted(key for app in APPS for key in initial[app]["objects"]), objects
        issued = dns_events()
        assert all(count > 0 for count in issued.values()), issued
        assert_dns_clean()
        assert kms_key_count() == 2

    with subtest("appOne replica on green"):
        green.start()
        green.wait_for_unit("multi-user.target")
        green.wait_for_unit("enclave-start-appOne.service")
        green.fail("systemctl is-active --quiet enclave-start-appTwo")
        assert_serving(green, "appOne", APP_ONE_PCR0, initial["appOne"])
        assert_app_one_unchanged()
        assert kms_key_count() == 2
        assert dns_events() == issued
        assert_dns_clean()
        assert not console_has(green, "renewed the fleet certificate", "appOne")
        assert get_param(key_param(SUCCESSOR_PCR0, "appTwo")) == ""

    with subtest("appTwo migration"):
        successor_key = migrate(blue, "appTwo", APP_TWO_PCR0, SUCCESSOR_PCR0, initial["appTwo"]["key"])
        assert kms_key_count() == 3
        assert_app_one_unchanged()
        green.fail("systemctl is-active --quiet enclave-start-appTwo")
        assert_serving(blue, "appTwo", APP_TWO_PCR0, initial["appTwo"])
        # Only start the successor after its predecessor has committed the successor artifacts.
        green.succeed("systemctl start enclave-start-appTwo")

    with subtest("Successor adoption"):
        assert_serving(green, "appTwo", SUCCESSOR_PCR0, initial["appTwo"])
        assert get_param(key_param(SUCCESSOR_PCR0, "appTwo")) == successor_key
        info = app_json(green, "appTwo")
        assert info["previous_pcr0"] == APP_TWO_PCR0, info
        assert info["previous_pcr0_attestation"], info
        assert info["migration"]["state"] == "none", info
        assert info["migration"]["source_pcr0"] == SUCCESSOR_PCR0, info
        green.wait_until_succeeds(
            "curl -skf --http1.1 https://127.0.0.1:9443/enclave/v1/info "
            f"| jq -e --arg p '{APP_TWO_PCR0}' --arg k '{initial['appTwo']['key']}' "
            "'.ancestry.complete == true and (.ancestry.generations | length) == 1 "
            "and .ancestry.generations[0].pcr0 == $p "
            "and .ancestry.generations[0].key_id == $k "
            "and .ancestry.generations[0].state == \"exists\"'", timeout=60,
        )
        assert_app_one_unchanged()
        assert dns_events() == issued
        assert_dns_clean()
        assert not console_has(green, "renewed the fleet certificate", "appTwo")
        # Validate both green certificates against the CA before moving client routes.
        for app in APPS:
            port = APPS[app]["port"]
            aws.succeed(
                f"openssl s_client -connect green:{port} -servername {fqdn(app)} "
                f"-verify_hostname {fqdn(app)} -CAfile /tmp/pebble-root.pem "
                "-verify_return_error </dev/null >/dev/null 2>&1"
            )

    with subtest("Routing and independent lifecycle"):
        for app in APPS:
            control_probe(green, app)
        app_two_pid = green.succeed("cat /run/enclave-appTwo-qemu.pid").strip()
        green.succeed("systemctl stop enclave-start-appOne")
        green.wait_until_fails(
            "curl --connect-timeout 1 --max-time 2 -skf https://127.0.0.1:8443/health", timeout=30,
        )
        green.fail(
            "curl --connect-timeout 1 --max-time 8 -s -H 'Content-Type: application/json' "
            "--data '{' http://127.0.0.1:18003/request-migration"
        )
        assert_serving(green, "appTwo", SUCCESSOR_PCR0, initial["appTwo"])
        control_probe(green, "appTwo")
        assert green.succeed("cat /run/enclave-appTwo-qemu.pid").strip() == app_two_pid
        green.succeed("systemctl start enclave-start-appOne")
        assert_serving(green, "appOne", APP_ONE_PCR0, initial["appOne"])
        control_probe(green, "appOne")
        assert_app_one_unchanged()

        # Poll appTwo continuously while appOne's gvproxy restarts and reconnects.
        green.succeed(
            "systemd-run --unit=appTwo-health-probe --property=RemainAfterExit=yes "
            "bash -c 'for i in $(seq 1 30); do "
            "curl --connect-timeout 1 --max-time 2 -skf --http1.1 "
            "https://127.0.0.1:9443/test/health >/dev/null || exit 1; sleep 0.5; done'"
        )
        green.succeed("systemctl restart gvproxy-appOne")
        assert_serving(green, "appOne", APP_ONE_PCR0, initial["appOne"])
        green.wait_until_succeeds(
            "test \"$(systemctl show appTwo-health-probe -p SubState --value)\" = exited "
            "&& test \"$(systemctl show appTwo-health-probe -p Result --value)\" = success", timeout=60,
        )
        assert_serving(green, "appTwo", SUCCESSOR_PCR0, initial["appTwo"])
        control_probe(green, "appTwo")
        assert dns_events() == issued
        assert_dns_clean()
        assert kms_key_count() == 3

    with subtest("Cutover and retirement"):
        routes = {app: green for app in APPS}
        for app in APPS:
            assert client_json(app)["status"] == "ready"
            assert client_json(app, "/test/env/ENCLAVE_APP_NAME")["value"] == app
        blue.shutdown()
        for app, config in APPS.items():
            assert client_json(app)["status"] == "ready"
            assert client_json(app, "/test/health")["status"] == "ok"
            assert client_json(app, "/test/env/E2E_SIGNING_KEY")["value"] == initial[app]["secret"]
            assert_serving(routes[app], app, config["green"], initial[app])
            control_probe(routes[app], app)
        assert app_json(green, "appOne")["migration"] == initial["appOne"]["migration"]
        assert dns_events() == issued
        assert_dns_clean()
        print("e2e-summary: two apps cut over; appOne EIF reused; appTwo migrated; blue retired")
except Exception:
    for node in (blue, green):
        if node.is_up():
            for app in APPS:
                print_enclave_diagnostics(node, app)
    print(aws.execute("journalctl -u ministack -u awsmocks -u pebble -u route53-dns-proxy --no-pager -n 100")[1])
    raise
