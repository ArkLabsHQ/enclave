# default.nix prepends BLUE_PCR0 and helpers.py. The driver injects aws, blue, and green.
# Blue runs previous-release's runtime, green this revision's: green must adopt blue's
# state, or a fleet on that release can only move by a fresh genesis.

setup_aws()

blue.start()
wait_enclave_healthy(blue)
blue_secret = secret_value(blue)

# Booting green is the whole trigger; blue commits after the cooldown and green promotes.
green.start()
try:
    wait_enclave_healthy(green)
except Exception:
    print_enclave_diagnostics(blue)
    raise

assert secret_value(green) == blue_secret
green.succeed(
    "curl -skf --http1.1 https://127.0.0.1/enclave/v1/info "
    f"| jq -e --arg prev '{BLUE_PCR0}' '.previous_pcr0 == $prev'"
)
