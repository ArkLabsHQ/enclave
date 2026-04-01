terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

locals {
  prefix = "${var.deployment}-${var.app_name}"

  # Availability zones for VPC subnets.
  az_a = "${var.region}a"
  az_b = "${var.region}b"
}
