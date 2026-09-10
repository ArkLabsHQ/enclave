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


def key_param(pcr0):
    return f"/dev/testapp/unlocked/KMSKeyID/{pcr0}"


def migration_receipt_param(key_id, pcr0):
    return f"/dev/testapp/MigrationStateOriginReceipt/{key_id}/{pcr0.lower()}"


def get_param(name):
    status, out = aws.execute(
        f"{CLOUD} ssm get-parameter --name {name} --query Parameter.Value --output text"
    )
    return out.strip() if status == 0 else ""


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
