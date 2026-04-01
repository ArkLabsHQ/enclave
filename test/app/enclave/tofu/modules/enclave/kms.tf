# KMS encryption key for enclave secrets.
#
# The enclave self-applies a PCR0-locked key policy at first boot, removing
# PutKeyPolicy from everyone. After locking, only the enclave (via the mgmt
# server) can schedule key deletion. The instance destroy provisioner handles
# this automatically. The KMS key is then removed from state so tofu destroy
# doesn't try (and fail) to delete it.

resource "aws_kms_key" "encryption" {
  enable_key_rotation = true
  description         = "${local.prefix} enclave encryption key"
}

# Remove KMS key from state on destroy. The key policy is locked to PCR0
# after first boot, so tofu cannot delete it. Key deletion is scheduled
# by the instance's destroy provisioner via the mgmt server.
resource "null_resource" "kms_state_cleanup" {
  triggers = {
    key_id = aws_kms_key.encryption.id
  }

  provisioner "local-exec" {
    when       = destroy
    command    = "tofu state rm module.enclave.aws_kms_key.encryption module.enclave.aws_kms_key_policy.encryption 2>/dev/null || true"
    on_failure = continue
  }
}

# Initial key policy: grants the EC2 instance role encrypt/decrypt + policy
# management. The enclave replaces this policy at runtime with a PCR0-locked
# version via selfApplyKMSPolicy().
resource "aws_kms_key_policy" "encryption" {
  key_id = aws_kms_key.encryption.id

  policy = data.aws_iam_policy_document.kms_key_policy.json
}

data "aws_iam_policy_document" "kms_key_policy" {
  # Allow the account root full key management (required by AWS).
  statement {
    sid    = "AllowRootAccount"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Allow the EC2 instance role to encrypt/decrypt and manage key policy.
  statement {
    sid    = "AllowInstanceRole"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.instance.arn]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
      "kms:PutKeyPolicy",
      "kms:GetKeyPolicy",
    ]
    resources = ["*"]
  }
}
