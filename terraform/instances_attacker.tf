# === STAGE 5: attacker capture host (evil-web1) ============================
# Final stage. Depends only on the foundation. Once this applies, all six
# hosts exist, so the combined instance_ids map the harness/smoke read is
# defined here (it can only reference instances that now all exist).

resource "aws_instance" "evil_web1" {
  ami                    = local.ami_attacker
  instance_type          = var.instance_type_micro
  subnet_id              = aws_subnet.attacker.id
  private_ip             = local.ips.evil_web1
  vpc_security_group_ids = [aws_security_group.evil_web1.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  # Bake-only public IP so apt can install the capture listener deps; removed when egress flips off.
  associate_public_ip_address = var.enable_egress

  user_data = templatefile("${path.module}/cloud-init/bootstrap.yaml.tftpl", merge(local.common_init, {
    role = "attacker", hostname = "evil-web1"
  }))

  tags = { Name = "evil-web1", role = "evil-web1" }
}

output "evil_web1_id" {
  value = aws_instance.evil_web1.id
}

# role -> instance id, consumed by run.py and smoke.sh. Only valid once every
# stage is deployed; that is why it lives in the last stage's file.
output "instance_ids" {
  description = "role -> instance id (used by the Ansible SSM inventory consumers and reset)."
  value = {
    ctl       = aws_instance.ctl.id
    bastion   = aws_instance.bastion.id
    web1      = aws_instance.web1.id
    db1       = aws_instance.db1.id
    evil_web1 = aws_instance.evil_web1.id
    dns       = aws_instance.dns.id
  }
}
