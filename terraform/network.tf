# ---------------------------------------------------------------------------
# VPC + subnets. enableDnsSupport/Hostnames must be true so the VPC .2 resolver
# and interface-endpoint private DNS work with NO internet
# ---------------------------------------------------------------------------
resource "aws_vpc" "testbed" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "cse227-testbed" }
}

resource "aws_subnet" "mgmt" {
  vpc_id            = aws_vpc.testbed.id
  cidr_block        = "10.20.0.0/24"
  availability_zone = "${var.region}a"
  tags              = { Name = "subnet-mgmt" }
}

resource "aws_subnet" "targets" {
  vpc_id            = aws_vpc.testbed.id
  cidr_block        = "10.20.10.0/24"
  availability_zone = "${var.region}a"
  tags              = { Name = "subnet-targets" }
}

resource "aws_subnet" "attacker" {
  vpc_id            = aws_vpc.testbed.id
  cidr_block        = "10.20.20.0/24"
  availability_zone = "${var.region}a"
  tags              = { Name = "subnet-attacker" }
}

# ---------------------------------------------------------------------------
# Routing. Single private route table, local route only. When enable_egress is
# true we add an IGW + default route.
# ---------------------------------------------------------------------------
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.testbed.id
  tags   = { Name = "rt-private" }
}

resource "aws_route_table_association" "mgmt" {
  subnet_id      = aws_subnet.mgmt.id
  route_table_id = aws_route_table.private.id
}
resource "aws_route_table_association" "targets" {
  subnet_id      = aws_subnet.targets.id
  route_table_id = aws_route_table.private.id
}
resource "aws_route_table_association" "attacker" {
  subnet_id      = aws_subnet.attacker.id
  route_table_id = aws_route_table.private.id
}

resource "aws_internet_gateway" "egress" {
  count  = var.enable_egress ? 1 : 0
  vpc_id = aws_vpc.testbed.id
  tags   = { Name = "igw-bringup-only" }
}

resource "aws_route" "default_egress" {
  count                  = var.enable_egress ? 1 : 0
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.egress[0].id
}

# ---------------------------------------------------------------------------
# Security groups = the allowed paths. The SGs are what make lateral
# movement network POSSIBLE
# ---------------------------------------------------------------------------

# Endpoints SG: hosts reach the interface endpoints on 443.
resource "aws_security_group" "endpoints" {
  name_prefix = "cse227-endpoints-"
  vpc_id      = aws_vpc.testbed.id
  tags        = { Name = "sg-endpoints" }

  ingress {
    description = "HTTPS from VPC to interface endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ctl" {
  name_prefix = "cse227-ctl-"
  vpc_id      = aws_vpc.testbed.id
  tags        = { Name = "sg-ctl" }
  # No ingress: operator reaches ctl via SSM, not inbound SSH.
  egress {
    description = "ctl may reach everything the arms allow; paths are enforced on the target SGs."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "bastion" {
  name_prefix = "cse227-bastion-"
  vpc_id      = aws_vpc.testbed.id
  tags        = { Name = "sg-bastion" }

  ingress {
    description     = "ctl -> bastion:22"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.ctl.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# web1/db1 share this SG. Idea 1's crux: ingress on :22 is allowed from the
# BASTION, not from ctl. So the only network route to db1 is via the forwarded
# identity through bastion -> the forwarding-hijack is the interesting path.
resource "aws_security_group" "targets" {
  name_prefix = "cse227-targets-"
  vpc_id      = aws_vpc.testbed.id
  tags        = { Name = "sg-targets" }

  ingress {
    description     = "bastion -> web1/db1:22 (lateral movement is network-possible)"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }
  ingress {
    description     = "ctl -> web1:22 only (benign task); ctl -> db1 is NOT added => blocked"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.ctl.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# NOTE on smoke test #2 ("ctl -> db1:22 refused"): web1 and db1 share this SG,
# and it allows ctl->:22 for web1's benign task. To make ctl->db1 actually
# refused at the network layer, db1 carries an extra deny-by-omission SG
# (see aws_security_group.db1_only below) and does NOT get sg-targets' ctl rule.
# We model this by giving db1 its own SG instead of the shared one.
resource "aws_security_group" "db1" {
  name_prefix = "cse227-db1-"
  vpc_id      = aws_vpc.testbed.id
  tags        = { Name = "sg-db1" }

  ingress {
    description     = "bastion -> db1:22 ONLY. No rule from ctl => ctl->db1 refused."
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "evil_web1" {
  name_prefix = "cse227-evilweb1-"
  vpc_id      = aws_vpc.testbed.id
  tags        = { Name = "sg-evil-web1" }

  ingress {
    description     = "ctl -> evil-web1:22 (Idea 2: a fooled agent lands here after the DNS repoint)"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.ctl.id]
  }
  ingress {
    description     = "bastion -> evil-web1:22 (in case the fooled hop originates from bastion)"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "dns" {
  name_prefix = "cse227-dns-"
  vpc_id      = aws_vpc.testbed.id
  tags        = { Name = "sg-dns" }

  ingress {
    description = "DNS (udp/tcp 53) from the whole VPC"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }
  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  ingress {
    description     = "ctl -> dns:22 so the harness can repoint web1 per run"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.ctl.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------------------
# VPC endpoints = the ONLY way in/out. SSM for operator access, S3
# gateway for log shipping + SSM agent's S3 needs.
# ---------------------------------------------------------------------------
resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(local.interface_endpoints)
  vpc_id              = aws_vpc.testbed.id
  service_name        = each.value
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.mgmt.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = { Name = each.value }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.testbed.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = { Name = "s3-gateway" }
}
