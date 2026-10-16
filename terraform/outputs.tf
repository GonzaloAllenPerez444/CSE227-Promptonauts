

output "private_ips" {
  value = local.ips
}

output "resolved_amis" {
  description = "Record these in versions.lock (pinned AMI IDs)."
  value = {
    ctl      = local.ami_ctl
    target   = local.ami_target
    attacker = local.ami_attacker
    dns      = local.ami_dns
  }
}

output "egress_enabled" {
  description = "MUST be false for any scored run or else bad things could happen lol"
  value       = var.enable_egress
}

output "logs_bucket" {
  value = aws_s3_bucket.logs.bucket
}

output "canary_pubkey_path" {
  value = local_file.canary_pub.filename
}
