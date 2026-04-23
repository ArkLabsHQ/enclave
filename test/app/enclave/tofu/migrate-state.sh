#!/usr/bin/env bash
# Migrate OpenTofu state from the flat layout (resources at root)
# to the module layout (resources under module.enclave).
#
# Run this ONCE after upgrading to the module-based structure.
# Requires: tofu CLI, initialized state backend.
#
# Usage:
#   cd enclave/tofu
#   bash migrate-state.sh

set -euo pipefail

echo "=== OpenTofu State Migration ==="
echo "Moving resources from root to module.enclave"
echo ""

# Helper: move a resource, skip if it doesn't exist in state.
move() {
  local from="$1" to="$2"
  if tofu state show "$from" &>/dev/null; then
    echo "  $from -> $to"
    tofu state mv "$from" "$to"
  else
    echo "  (skip) $from not in state"
  fi
}

echo "--- KMS ---"
move "aws_kms_key.encryption"        "module.enclave.aws_kms_key.encryption"
move "aws_kms_key_policy.encryption"  "module.enclave.aws_kms_key_policy.encryption"

echo ""
echo "--- IAM ---"
move "aws_iam_role.instance"                      "module.enclave.aws_iam_role.instance"
move "aws_iam_instance_profile.instance"           "module.enclave.aws_iam_instance_profile.instance"
move "aws_iam_role_policy_attachment.ssm_core[0]"  "module.enclave.aws_iam_role_policy_attachment.ssm_core[0]"
move "aws_iam_role_policy.enclave"                 "module.enclave.aws_iam_role_policy.enclave"

echo ""
echo "--- S3 ---"
move "aws_s3_bucket.assets"                    "module.enclave.aws_s3_bucket.assets"
move "aws_s3_bucket_public_access_block.assets" "module.enclave.aws_s3_bucket_public_access_block.assets"
move "aws_s3_object.enclave_eif"               "module.enclave.aws_s3_object.enclave_eif"
move "aws_s3_object.enclave_init"              "module.enclave.aws_s3_object.enclave_init"
move "aws_s3_object.watchdog_systemd"          "module.enclave.aws_s3_object.watchdog_systemd"
move "aws_s3_object.imds_systemd"              "module.enclave.aws_s3_object.imds_systemd"
move "aws_s3_object.gvproxy_systemd"           "module.enclave.aws_s3_object.gvproxy_systemd"
move "aws_s3_object.supervisor_binary"         "module.enclave.aws_s3_object.supervisor_binary"
move "aws_s3_object.supervisor_systemd"        "module.enclave.aws_s3_object.supervisor_systemd"
move "aws_s3_bucket.storage"                   "module.enclave.aws_s3_bucket.storage"
move "aws_s3_bucket_public_access_block.storage" "module.enclave.aws_s3_bucket_public_access_block.storage"
move "aws_s3_bucket_policy.storage_ssl[0]"     "module.enclave.aws_s3_bucket_policy.storage_ssl[0]"

echo ""
echo "--- SSM ---"
# Dynamic per-secret parameters — enumerate from state.
for addr in $(tofu state list 2>/dev/null | grep '^aws_ssm_parameter\.'); do
  move "$addr" "module.enclave.$addr"
done

echo ""
echo "--- VPC ---"
move "aws_vpc.main[0]"                          "module.enclave.aws_vpc.main[0]"
move "aws_subnet.public[0]"                     "module.enclave.aws_subnet.public[0]"
move "aws_subnet.private[0]"                    "module.enclave.aws_subnet.private[0]"
move "aws_subnet.private_b[0]"                  "module.enclave.aws_subnet.private_b[0]"
move "aws_internet_gateway.main[0]"             "module.enclave.aws_internet_gateway.main[0]"
move "aws_eip.nat[0]"                           "module.enclave.aws_eip.nat[0]"
move "aws_nat_gateway.main[0]"                  "module.enclave.aws_nat_gateway.main[0]"
move "aws_route_table.public[0]"                "module.enclave.aws_route_table.public[0]"
move "aws_route_table_association.public[0]"    "module.enclave.aws_route_table_association.public[0]"
move "aws_route_table.private[0]"               "module.enclave.aws_route_table.private[0]"
move "aws_route_table_association.private[0]"   "module.enclave.aws_route_table_association.private[0]"
move "aws_route_table_association.private_b[0]" "module.enclave.aws_route_table_association.private_b[0]"
move "aws_vpc_endpoint.kms[0]"                  "module.enclave.aws_vpc_endpoint.kms[0]"
move "aws_vpc_endpoint.ssm[0]"                  "module.enclave.aws_vpc_endpoint.ssm[0]"
move "aws_vpc_endpoint.ecr[0]"                  "module.enclave.aws_vpc_endpoint.ecr[0]"
move "aws_vpc_endpoint.s3[0]"                   "module.enclave.aws_vpc_endpoint.s3[0]"

echo ""
echo "--- EC2 ---"
move "aws_security_group.nitro[0]"              "module.enclave.aws_security_group.nitro[0]"
move "aws_security_group_rule.https_ingress[0]" "module.enclave.aws_security_group_rule.https_ingress[0]"
move "aws_security_group_rule.self_tcp[0]"      "module.enclave.aws_security_group_rule.self_tcp[0]"
move "aws_security_group_rule.self_icmp[0]"     "module.enclave.aws_security_group_rule.self_icmp[0]"
move "aws_security_group_rule.all_egress[0]"    "module.enclave.aws_security_group_rule.all_egress[0]"
move "aws_instance.nitro[0]"                    "module.enclave.aws_instance.nitro[0]"
move "aws_eip.instance[0]"                      "module.enclave.aws_eip.instance[0]"
move "aws_eip_association.instance[0]"          "module.enclave.aws_eip_association.instance[0]"

echo ""
echo "=== Migration complete ==="
echo "Run 'tofu plan' to verify no changes are needed."
