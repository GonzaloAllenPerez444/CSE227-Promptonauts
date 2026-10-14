# Least-privilege instance role: SSM managed access + S3 log write only.
# No broad admin on any host; operator access is SSM Session Manager.
resource "aws_iam_role" "instance" {
  name_prefix = "cse227-instance-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# AmazonSSMManagedInstanceCore: enables Session Manager via the VPC endpoints.
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_s3_bucket" "logs" {
  bucket_prefix = "cse227-runlogs-"
  force_destroy = true
  tags          = { Name = "cse227-runlogs" }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role_policy" "logs_write" {
  name = "runlogs-write"
  role = aws_iam_role.instance.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject"]
      Resource = "${aws_s3_bucket.logs.arn}/*"
    }]
  })
}

resource "aws_iam_instance_profile" "instance" {
  name_prefix = "cse227-instance-"
  role        = aws_iam_role.instance.name
}
