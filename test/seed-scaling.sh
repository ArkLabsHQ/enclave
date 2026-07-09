#   ./seed-scaling.sh dev-follower-1
set -euo pipefail

DEPLOYMENT="${1:?usage: seed-scaling.sh <deployment>}"
APP_NAME="${ENCLAVE_APP_NAME:-my-app}"
LOCALSTACK="${LOCALSTACK_ENDPOINT:-http://localhost:4566}"
LOCK="${LOCK_SEGMENT:-unlocked}"   # matches lockSegment() default (kmsKeyLocked=false)
REGION="${ENCLAVE_AWS_REGION:-us-east-1}"

AWS=(aws --endpoint-url "$LOCALSTACK" --region "$REGION")

echo "=== Seeding KMS placeholder: /${DEPLOYMENT}/${APP_NAME}/${LOCK}/KMSKeyID ==="
"${AWS[@]}" ssm put-parameter \
  --name "/${DEPLOYMENT}/${APP_NAME}/${LOCK}/KMSKeyID" \
  --value "UNSET" --type String --overwrite >/dev/null
echo "  done"


BUCKET="${DEPLOYMENT}-${APP_NAME}-storage"
echo "=== Provisioning storage bucket: ${BUCKET} ==="
"${AWS[@]}" s3 mb "s3://${BUCKET}" >/dev/null 2>&1 || true
"${AWS[@]}" ssm put-parameter \
  --name "/${DEPLOYMENT}/${APP_NAME}/StorageBucketName" \
  --value "${BUCKET}" --type String --overwrite >/dev/null
echo "  done"
