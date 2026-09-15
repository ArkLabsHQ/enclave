# Prepended to each test script by default.nix. The driver supplies aws.

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


def cloud(command):
    return aws.succeed(f"{CLOUD} {command}").strip()


def key_param(pcr0, app="testapp"):
    return f"/dev/{app}/unlocked/KMSKeyID/{pcr0}"


def migration_receipt_param(key_id, pcr0, app="testapp"):
    return f"/dev/{app}/MigrationStateOriginReceipt/{key_id}/{pcr0.lower()}"


def get_param(name):
    status, out = aws.execute(
        f"{CLOUD} ssm get-parameter --name {name} --query Parameter.Value --output text"
    )
    return out.strip() if status == 0 else ""


def instance_suffix(instance):
    return "" if instance == "enclave" else f"-{instance}"


def print_enclave_diagnostics(node, instance="enclave"):
    suffix = instance_suffix(instance)
    units = [f"{unit}{suffix}" for unit in (
        "vhost-device-vsock", "gvproxy", "migration-proxy", "enclave-start"
    )] + ["enclave-heartbeat", "imds-proxy", "mock-imds-forward"]
    print(f"diagnostics: {node.name}/{instance}")
    print(node.execute("systemctl status --no-pager " + " ".join(units))[1])
    print(node.execute(
        "journalctl --no-pager -n 150 " + " ".join(f"-u {unit}" for unit in units)
        + f" -u 'vsock-bridge{suffix}-*'"
    )[1])
    print(node.execute(f"tail -n 160 /var/log/enclave{suffix}-console.log")[1])
    print(node.execute(
        f"cat /run/enclave{suffix}-qemu.pid; "
        "ps -eo pid,ppid,stat,pcpu,comm,args | grep '[q]emu-system'"
    )[1])


def wait_healthy(node, port=443, instance="enclave"):
    try:
        node.wait_until_succeeds(
            "curl --connect-timeout 2 --max-time 5 -skf --http1.1 "
            f'https://127.0.0.1:{port}/health | jq -e ".status == \\"ready\\""',
            timeout=900,
        )
        node.wait_until_succeeds(
            "curl --connect-timeout 2 --max-time 5 -skf --http1.1 "
            f'https://127.0.0.1:{port}/test/health | jq -e ".status == \\"ok\\""',
            timeout=300,
        )
    except Exception:
        print_enclave_diagnostics(node, instance)
        print(
            aws.execute(
                "journalctl -u ministack -u awsmocks --no-pager -n 100"
            )[1]
        )
        raise


def secret_value(node, port=443):
    value = env_value(node, "E2E_SIGNING_KEY", port)
    assert len(value) == 64, value
    assert all(c in "0123456789abcdef" for c in value), value
    return value


def env_value(node, name, port=443):
    return node.succeed(
        f"curl -skf --http1.1 https://127.0.0.1:{port}/test/env/{name} | jq -r .value"
    ).strip()


def kms_key_count():
    return int(cloud("kms list-keys --query 'length(Keys)' --output text"))


def enclave_curl(node, pcr0, path="/health", port=443):
    # QEMU's NSM cannot sign or supply an AWS chain. PCR0, nonce, the exact
    # 39-byte TLS binding, and live certificate pinning remain checked.
    return node.execute(
        f"enclave curl {path} --base-url https://127.0.0.1:{port} "
        f"--expected-pcr0 {pcr0} --insecure-skip-cose-verify 2>&1"
    )


def console_has(node, needle, instance="enclave"):
    status, _ = node.execute(
        f"tr -d '\\000' </var/log/enclave{instance_suffix(instance)}-console.log | tr '\\r' '\\n' "
        f"| grep -F {shlex.quote(needle)} >/dev/null"
    )
    return status == 0


def served_leaf_sha(node, port=443, fqdn=FQDN):
    return served_leaf(node, "-outform DER | sha256sum | cut -d' ' -f1", port, fqdn)


def served_leaf(node, x509_args, port=443, fqdn=FQDN):
    return node.succeed(
        f"openssl s_client -connect 127.0.0.1:{port} -servername {fqdn} "
        f"</dev/null 2>/dev/null | openssl x509 {x509_args}"
    ).strip()


def put_env(name, value, app="testapp"):
    cloud(
        f"ssm put-parameter --name /dev/{app}/env/{name} "
        f"--type String --value {shlex.quote(value)}"
    )
