# === STAGE 3: DNS resolver (dnsmasq, repointable web1) =====================
# Stood up before the targets so their resolver has something to point at.
# Depends only on the foundation.

resource "aws_instance" "dns" {
  ami                    = local.ami_dns
  instance_type          = var.instance_type_micro
  subnet_id              = aws_subnet.targets.id
  private_ip             = local.ips.dns
  vpc_security_group_ids = [aws_security_group.dns.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  # Bake-only public IP so apt can install dnsmasq; removed when egress flips off.
  associate_public_ip_address = var.enable_egress

  user_data = templatefile("${path.module}/cloud-init/bootstrap.yaml.tftpl", merge(local.common_init, {
    role = "dns", hostname = "dns"
  }))

  tags = { Name = "dns", role = "dns" }
}

output "dns_id" {
  value = aws_instance.dns.id
}
