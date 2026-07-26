{ tofunix }:
{
  pkgs,
  app,
  deployment,
  local ? false,
  region ? "us-east-1",
}:
let
  lib = import tofunix { inherit pkgs; };

  prefix = "${deployment}-${app}";

  tf = expr: "\${${expr}}";

  localProviderFlags = {
    access_key = "test";
    secret_key = "test";
    s3_use_path_style = true; # bucket.localhost doesn't resolve
    skip_credentials_validation = true;
    skip_metadata_api_check = "true"; # string, not bool (provider schema quirk)
    skip_requesting_account_id = true;
  };

  mkLocalWrapper =
    cli:
    pkgs.writeShellScriptBin "tofunix" ''
      export AWS_ENDPOINT_URL="''${AWS_ENDPOINT_URL:-http://localhost:4566}"
      export AWS_ENDPOINT_URL_S3="''${AWS_ENDPOINT_URL_S3:-$AWS_ENDPOINT_URL}"
      export AWS_ENDPOINT_URL_DYNAMODB="''${AWS_ENDPOINT_URL_DYNAMODB:-$AWS_ENDPOINT_URL}"
      export AWS_ACCESS_KEY_ID=test
      export AWS_SECRET_ACCESS_KEY=test
      export AWS_REGION=${region}
      exec ${cli}/bin/tofunix "$@"
    ''
    // {
      inherit (cli) module tfjson;
    };

  mkCli = if local then (attrs: mkLocalWrapper lib.mkCliAio attrs) else (attrs: lib.mkCliAio attrs);

in
mkCli {
  plugins = [
    lib.mkOpentofuProvider
    {
      owner = "hashicorp";
      repo = "aws";
      version = "6.56.0";
      hash = pkgs.lib.fakeHash;
    }
  ];
  moduleConfig =
    { ref, lib, ... }:
    {
      variable.instances = {
        type = "map(object({ami_id = string, instance_type = string}))";
        description = "Map of slot name to {ami_id, instance_type} for blue/green.";
        default = { };
      };

      variable.active_slot = {
        type = "string";
        description = "Which slot's EIP Route53 points at.";
        default = "blue";
      };

      variable.account = {
        type = "string";
        description = "The AWS account";
      };

      provider.aws.default = {
        region = region;
      } // lib.optionalAttrs local localProviderFlags;

      terraform.backend.s3 =
        {
          key = "enclave.tfstate";
          encrypt = true;
        }
        // lib.optionalAttrs local {
          use_path_style = true;
          skip_credentials_validation = true;
          skip_requesting_account_id = true;
        };

      resource = {
        aws_iam_role.instance = {
          name_prefix = "${prefix}-enclave-";
          assume_role_policy = builtins.toJSON {
            Version = "2012-10-17";
            Statement = [
              {
                Effect = "Allow";
                Principal = {
                  Service = "ec2.amazonaws.com";
                };
                Action = "sts:AssumeRole";
              }
            ];
          };
        };

        aws_iam_instance_profile.instance = {
          name_prefix = "${prefix}-enclave-";
          role = ref.aws_iam_role.instance.name;
        };

        aws_iam_role_policy.enclave = {
          name = "enclave-access";
          role = ref.aws_iam_role.instance.id;
          policy = builtins.toJSON {
            Version = "2012-10-17";
            Statement = [
              {
                Sid = "S3TLSCacheReadWrite";
                Effect = "Allow";
                Action = [
                  "s3:GetObject"
                  "s3:PutObject"
                  "s3:DeleteObject"
                  "s3:ListBucket"
                  "s3:GetBucketLocation"
                ];
                Resource = [
                  "${ref.aws_s3_bucket.tls_cache.arn}"
                  "${ref.aws_s3_bucket.tls_cache.arn}/*"
                ];
              }
              {
                Sid = "S3MigrationIntentLogObjectLock";
                Effect = "Allow";
                Action = [
                  "s3:PutObject"
                  "s3:GetObject"
                  "s3:PutObjectRetention"
                  "s3:ListBucket"
                  "s3:ListBucketVersions"
                  "s3:GetBucketLocation"
                ];
                Resource = [
                  "${ref.aws_s3_bucket.migration_intent_log.arn}"
                  "${ref.aws_s3_bucket.migration_intent_log.arn}/*"
                ];
              }
              {
                Sid = "SSMParams";
                Effect = "Allow";
                Action = [
                  "ssm:GetParameter"
                  "ssm:PutParameter"
                ];
                Resource = [
                  "arn:aws:ssm:${region}:${ref.var.account}:parameter/${deployment}/${app}/*"
                ];
              }
              {
                Sid = "KMSAccess";
                Effect = "Allow";
                Action = [
                  "kms:CreateKey"
                ];
                Resource = [ "*" ];
              }
              {
                Sid = "STSAccess";
                Effect = "Allow";
                Action = [ "sts:GetCallerIdentity" ];
                Resource = [ "*" ];
              }
              {
                Sid = "CloudWatchLogsAccess";
                Effect = "Allow";
                Action = [
                  "logs:CreateLogGroup"
                  "logs:CreateLogStream"
                  "logs:PutLogEvents"
                  "logs:PutRetentionPolicy"
                  "logs:FilterLogEvents"
                  "logs:DescribeLogStreams"
                ];
                Resource = [ "arn:aws:logs:${region}:${ref.var.account}:log-group:/enclave/*" ];
              }
            ];
          };
        };

        aws_iam_role_policy_attachment.ssm_core = {
          role = ref.aws_iam_role.instance.name;
          policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore";
        };

        aws_security_group.nitro = {
          name_prefix = "${prefix}-nitro-";
          description = "SG for Nitro Enclave EC2 instance";
          tags.Name = "${prefix}-nitro-sg";
        };

        aws_security_group_rule.https_ingress = {
          type = "ingress";
          from_port = 443;
          to_port = 443;
          protocol = "tcp";
          cidr_blocks = [ "0.0.0.0/0" ];
          security_group_id = ref.aws_security_group.nitro.id;
        };

        aws_security_group_rule.all_egress = {
          type = "egress";
          from_port = 0;
          to_port = 0;
          protocol = "-1";
          cidr_blocks = [ "0.0.0.0/0" ];
          security_group_id = ref.aws_security_group.nitro.id;
        };

        # S3 Buckets
        aws_s3_bucket.tls_cache = {
          bucket_prefix = "${prefix}-tls-cache-";
          force_destroy = false;
        };

        aws_s3_bucket_public_access_block.tls_cache = {
          bucket = ref.aws_s3_bucket.tls_cache.id;
          block_public_acls = true;
          block_public_policy = true;
          ignore_public_acls = true;
          restrict_public_buckets = true;
        };

        aws_s3_bucket.migration_intent_log = {
          bucket_prefix = "${prefix}-migration-intent-log-";
          object_lock_enabled = true;
          force_destroy = false;
        };

        aws_s3_bucket_versioning.migration_intent_log = {
          bucket = ref.aws_s3_bucket.migration_intent_log.id;
          versioning_configuration.status = "Enabled";
        };

        # Static SSM Params
        aws_ssm_parameter = {
          tls_cache_bucket_name = {
            name = "/${deployment}/${app}/TLSCacheBucketName";
            type = "String";
            value = ref.aws_s3_bucket.tls_cache.id;
          };

          migration_intent_bucket_name = {
            name = "/${deployment}/${app}/MigrationIntentBucketName";
            type = "String";
            value = ref.aws_s3_bucket.migration_intent_log.id;
          };
        };

        # Blue/Green EC2's
        aws_instance.nitro = {
          for_each = ref.var.instances;
          ami = tf "each.value.ami_id";
          instance_type = tf "each.value.instance_type";
          iam_instance_profile = ref.aws_iam_instance_profile.instance.name;
          vpc_security_group_ids = [ ref.aws_security_group.nitro.id ];
          enclave_options = [ { enabled = true; } ];
          root_block_device = [
            {
              volume_size = 32;
              volume_type = "gp2";
              encrypted = true;
            }
          ];
          tags = {
            Name = "${prefix}-nitro-enclave-${tf "each.key"}";
            Region = region;
            Slot = tf "each.key";
          };
          depends_on = [ ref.aws_iam_role_policy.enclave ];
        };

        # One stable Elastic IP shared by all slots
        aws_eip.instance = {
          domain = "vpc";
          tags.Name = "${prefix}-enclave-eip";
        };

        # Cutover / rollback: flip var.active_slot and apply
        aws_eip_association.instance = {
          allocation_id = ref.aws_eip.instance.id;
          instance_id = tf "aws_instance.nitro[var.active_slot].id";
        };
      };

      output = {
        ec2_role_arn = {
          description = "EC2 instance role ARN.";
          value = ref.aws_iam_role.instance.arn;
        };

        instance_ids = {
          description = "Map of slot to EC2 instance ID.";
          value = tf "{for k, v in aws_instance.nitro : k => v.id}";
        };

        instance_ips = {
          description = "Map of slot to auto-assigned public IP (for pre-cutover testing).";
          value = tf "{for k, v in aws_instance.nitro : k => v.public_ip}";
        };

        elastic_ip = {
          description = "Shared Elastic IP; points at the active slot.";
          value = ref.aws_eip.instance.public_ip;
        };

        tls_cache_bucket = {
          description = "S3 tls cache bucket name.";
          value = ref.aws_s3_bucket.tls_cache.id;
        };

        migration_intent_log_bucket = {
          description = "S3 migration intent log bucket name.";
          value = ref.aws_s3_bucket.migration_intent_log.id;
        };
      };
    };
}
