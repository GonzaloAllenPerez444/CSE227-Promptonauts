# === STAGE 4: target hosts (bastion / web1 / db1) ==========================
# The Idea-1 topology: bastion (named + injected), web1 (benign), db1 (lateral
# target, reachable only via bastion). Depends only on the foundation.

resource "aws_instance" "bastion" {
  ami                    = local.ami_target
  instance_type          = var.instance_type_micro
  subnet_id              = aws_subnet.targets.id
  private_ip             = local.ips.bastion
  vpc_security_group_ids = [aws_security_group.bastion.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  # Bake-only public IP so apt can install packages; removed when egress flips off.
  associate_public_ip_address = var.enable_egress

  user_data = templatefile("${path.module}/cloud-init/bootstrap.yaml.tftpl", merge(local.common_init, {
    role = "bastion", hostname = "bastion"
  }))

  tags = { Name = "bastion", role = "bastion" }
}

resource "aws_instance" "web1" {
  ami                    = local.ami_target
  instance_type          = var.instance_type_micro
  subnet_id              = aws_subnet.targets.id
  private_ip             = local.ips.web1
  vpc_security_group_ids = [aws_security_group.targets.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  # Bake-only public IP so apt can install packages; removed when egress flips off.
  associate_public_ip_address = var.enable_egress

  user_data = templatefile("${path.module}/cloud-init/bootstrap.yaml.tftpl", merge(local.common_init, {
    role = "web1", hostname = "web1"
  }))

  tags = { Name = "web1", role = "web1" }
}

resource "aws_instance" "db1" {
  ami                    = local.ami_target
  instance_type          = var.instance_type_micro
  subnet_id              = aws_subnet.targets.id
  private_ip             = local.ips.db1
  vpc_security_group_ids = [aws_security_group.db1.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  # Bake-only public IP so apt can install packages; removed when egress flips off.
  associate_public_ip_address = var.enable_egress

  user_data = templatefile("${path.module}/cloud-init/bootstrap.yaml.tftpl", merge(local.common_init, {
    role = "db1", hostname = "db1"
  }))

  tags = { Name = "db1", role = "db1" }
}

output "bastion_id" {
  value = aws_instance.bastion.id
}
output "web1_id" {
  value = aws_instance.web1.id
}
output "db1_id" {
  value = aws_instance.db1.id
}
