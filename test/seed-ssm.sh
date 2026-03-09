#!/usr/bin/env bash
# Seed mock AWS services with the parameters the enclave supervisor expects.
#
# Defaults match SDK defaults: ENCLAVE_DEPLOYMENT=dev, ENCLAVE_APP_NAME=app.
# Override with environment variables if your enclave.yaml uses different values.
set -euo pipefail

ENDPOINT="${LOCALSTACK_ENDPOINT:-http://localhost:4566}"
DEPLOYMENT="${ENCLAVE_DEPLOYMENT:-dev}"
APP_NAME="${ENCLAVE_APP_NAME:-app}"
KMS_KEY_ARN="arn:aws:kms:us-east-1:123456789012:key/test-key-id"
BUCKET_NAME="${STORAGE_BUCKET_NAME:-test-enclave-storage}"

AWS="aws --endpoint-url=$ENDPOINT --region us-east-1 --no-cli-pager"

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
