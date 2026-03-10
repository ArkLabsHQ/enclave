#!/usr/bin/env bash
# Deploy the local test CDK stack to localstack using cdklocal.
#
# This replaces seed-ssm.sh with a proper CDK deployment that creates the same
# AWS resources as production: KMS key, SSM parameters, S3 bucket, IAM role.
#
# Prerequisites:
#   npm install -g aws-cdk-local aws-cdk  (or: npm install --prefix /tmp/cdklocal aws-cdk-local aws-cdk)
#   docker compose up -d (localstack running on port 4566)
#
# Usage:
#   ./deploy-local.sh                    # default: reads test/app/enclave/enclave.yaml
#   ./deploy-local.sh /path/to/enclave.yaml
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG="${1:-${SCRIPT_DIR}/app/enclave/enclave.yaml}"
OUT_DIR="${SCRIPT_DIR}/cdk-local.out"

export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export CDK_DISABLE_LEGACY_EXPORT_WARNING=1

echo "=== Synthesizing local CDK stack ==="
(cd "$REPO_ROOT" && go run ./cmd/synth-local -config "$CONFIG" -outdir "$OUT_DIR") 2>&1 | grep -v "^!!"

# Find cdklocal: global install, local install at /tmp/cdklocal, or fall back to cdk.
if command -v cdklocal >/dev/null 2>&1; then
  CDK_CMD="cdklocal"
elif [ -x /tmp/cdklocal/node_modules/.bin/cdklocal ]; then
  CDK_CMD="/tmp/cdklocal/node_modules/.bin/cdklocal"
else
  echo "cdklocal not found. Installing to /tmp/cdklocal..."
  npm install --prefix /tmp/cdklocal aws-cdk-local aws-cdk 2>&1 | tail -1
  CDK_CMD="/tmp/cdklocal/node_modules/.bin/cdklocal"
fi

echo ""
echo "=== Bootstrapping CDK ==="
$CDK_CMD bootstrap --app "$OUT_DIR" aws://000000000000/us-east-1 2>&1 \
  | grep -v "Warning:" | grep -v "^!!" | grep -v "NOTICES" | grep -v "^$" || true

echo ""
echo "=== Deploying local stack ==="
OUTPUTS_FILE="${SCRIPT_DIR}/cdk-local-outputs.json"
$CDK_CMD deploy --app "$OUT_DIR" \
  --require-approval never \
  --outputs-file "$OUTPUTS_FILE" \
  2>&1 | grep -v "Warning:" | grep -v "^!!" | grep -v "NOTICES"

echo ""
echo "=== Deploy complete ==="
if [ -f "$OUTPUTS_FILE" ]; then
  echo "Outputs:"
  cat "$OUTPUTS_FILE"
fi
