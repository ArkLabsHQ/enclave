#!/usr/bin/env bash
# Seed mock AWS services with the parameters the enclave supervisor expects.
#
# Defaults match SDK defaults: ENCLAVE_DEPLOYMENT=dev, ENCLAVE_APP_NAME=app.
# Override with environment variables if your enclave.yaml uses different values.
set -euo pipefail

ENDPOINT="${LOCALSTACK_ENDPOINT:-http://localhost:4566}"
DEPLOYMENT="${ENCLAVE_DEPLOYMENT:-dev}"
APP_NAME="${ENCLAVE_APP_NAME:-app}"
BUCKET_NAME="${STORAGE_BUCKET_NAME:-test-enclave-storage}"

export AWS_PAGER=""
# Localstack doesn't validate credentials, but the CLI requires them.
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
AWS="aws --endpoint-url=$ENDPOINT --region us-east-1"

echo "=== Creating KMS key ==="
# Use JSON output + jq for reliable extraction (AWS CLI v1 --query can be flaky).
KMS_KEY_ARN=""
CREATE_OUTPUT=$($AWS kms create-key --description "Test enclave key" --output json 2>&1) || true
if [ -n "$CREATE_OUTPUT" ]; then
  KMS_KEY_ARN=$(echo "$CREATE_OUTPUT" | jq -r '.KeyMetadata.Arn // empty' 2>/dev/null) || true
fi
if [ -z "${KMS_KEY_ARN:-}" ]; then
  echo "  create-key output: ${CREATE_OUTPUT:0:200}"
  # Key may already exist from a previous run; list and use the first one.
  LIST_OUTPUT=$($AWS kms list-keys --output json 2>&1) || true
  if [ -n "$LIST_OUTPUT" ]; then
    KMS_KEY_ARN=$(echo "$LIST_OUTPUT" | jq -r '.Keys[0].KeyArn // empty' 2>/dev/null) || true
  fi
fi
if [ -z "${KMS_KEY_ARN:-}" ]; then
  echo "  list-keys output: ${LIST_OUTPUT:0:200}" >&2
  echo "  ERROR: could not create or find a KMS key" >&2
  exit 1
fi
echo "  Key: $KMS_KEY_ARN"

echo ""
echo "=== Seeding SSM parameters ==="

# KMS key ID — read by getKMSKeyID() in sdk/kms_ssm.go
$AWS ssm put-parameter \
  --name "/${DEPLOYMENT}/${APP_NAME}/KMSKeyID" \
  --value "$KMS_KEY_ARN" \
  --type String \
  --overwrite 2>/dev/null || true
echo "  /${DEPLOYMENT}/${APP_NAME}/KMSKeyID = $KMS_KEY_ARN"

# Storage bucket name — read by initStorage() in sdk/storage.go
$AWS ssm put-parameter \
  --name "/${DEPLOYMENT}/${APP_NAME}/StorageBucketName" \
  --value "$BUCKET_NAME" \
  --type String \
  --overwrite 2>/dev/null || true
echo "  /${DEPLOYMENT}/${APP_NAME}/StorageBucketName = $BUCKET_NAME"

echo ""
echo "=== Creating S3 bucket ==="
$AWS s3 mb "s3://${BUCKET_NAME}" 2>/dev/null || echo "  (bucket already exists)"
echo "  s3://${BUCKET_NAME}"

echo ""
echo "=== Seeding complete ==="
echo ""
echo "Note: Secret ciphertexts are NOT pre-seeded."
echo "The supervisor will call GenerateDataKey to create them on first boot."
