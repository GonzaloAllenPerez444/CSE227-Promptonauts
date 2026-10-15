# === STAGE 2: controller
# Depends only on the foundation (network, IAM, cloud-init, data locals).
# Creates SSM-reachable host.

resource "aws_instance" "ctl" {
  ami                    = local.ami_ctl
  instance_type          = var.instance_type_small
  subnet_id              = aws_subnet.mgmt.id
  private_ip             = local.ips.ctl
  vpc_security_group_ids = [aws_security_group.ctl.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  # Temporary public IP only during the egress-on bake so apt can fetch packages.
  # The ctl SG has no inbound rules, so this exposes nothing inbound. Removed
  # automatically when enable_egress flips back to false (forces a rebuild).
  associate_public_ip_address = var.enable_egress

  user_data = templatefile("${path.module}/cloud-init/bootstrap.yaml.tftpl", merge(local.common_init, {
    role       = "ctl"
    hostname   = "ctl"
    os_version = "22.04" # ctl is pinned to 22.04 regardless of target OS (§3)
  }))

  tags = { Name = "ctl", role = "ctl" }
}

output "ctl_id" {
  value = aws_instance.ctl.id
}
