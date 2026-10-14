data "aws_caller_identity" "me" {}
data "aws_region" "current" {}

# Canonical's published AMI id for the requested Ubuntu version
data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/${var.os_version}/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

data "aws_ssm_parameter" "ubuntu_ctl" {
  # ctl is pinned to 22.04 regardless of the target OS variable (§3).
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

locals {
  # AMI IDs are not secret; the provider marks aws_ssm_parameter.value sensitive,
  # so unwrap here to keep the resolved_amis output readable (needed for versions.lock).
  base_ami_target = nonsensitive(data.aws_ssm_parameter.ubuntu.value)
  base_ami_ctl    = nonsensitive(data.aws_ssm_parameter.ubuntu_ctl.value)

  ami_ctl      = var.golden_ami_ctl != "" ? var.golden_ami_ctl : local.base_ami_ctl
  ami_target   = var.golden_ami_target != "" ? var.golden_ami_target : local.base_ami_target
  ami_attacker = var.golden_ami_attacker != "" ? var.golden_ami_attacker : local.base_ami_target
  ami_dns      = var.golden_ami_dns != "" ? var.golden_ami_dns : local.base_ami_target

  # Static private IPs so cloud-init/dnsmasq/known_hosts can reference hosts
  # before any dynamic discovery exists.
  ips = {
    ctl       = "10.20.0.10"
    dns       = "10.20.10.5"
    bastion   = "10.20.10.10"
    web1      = "10.20.10.11"
    db1       = "10.20.10.12"
    evil_web1 = "10.20.20.10"
  }

  interface_endpoints = [
    "com.amazonaws.${var.region}.ssm",
    "com.amazonaws.${var.region}.ec2messages",
    "com.amazonaws.${var.region}.ssmmessages",
  ]

  # Shared cloud-init inputs for every instance (used across the per-stage
  # instance files). Kept in the foundation so each stage can reference it.
  common_init = {
    os_version  = var.os_version
    arm         = var.arm
    resolver_ip = local.ips.dns
  }
}
