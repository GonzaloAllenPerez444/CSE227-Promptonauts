# ---------------------------------------------------------------------------
# Bedrock access for the ctl agent host, egress-free.
#
# The agent (Pi) on ctl reaches Amazon Bedrock over the VPC interface endpoint
# added in network.tf / data.tf (PrivateLink, no Internet Gateway or NAT), so
# the egress-free invariant is preserved. Only ctl is granted Bedrock: it gets
# its own instance role here, separate from the shared least-privilege role in
# iam.tf that the other hosts keep using.
#
# Credentials: none on disk. Pi's Bedrock provider uses the AWS SDK credential
# chain, which picks up this role from the instance metadata service (IMDS).
# The agent env only needs AWS_REGION (set by the `pi` Ansible role).
# ---------------------------------------------------------------------------

# The model the agent invokes. GLM 4.7 Flash (Z.ai) is available on-demand in
# us-west-2, so this is the bare foundation-model id (no us./global. prefix).
# If Bedrock rejects on-demand invoke ("use an inference profile"), switch this
# and versions.lock to "us.zai.glm-4.7-flash" and re-apply. Anthropic models
# (e.g. us.anthropic.claude-sonnet-4-6) are inference-profile-only and take the
# us. prefix here instead. Changing this = a new experimental cell; keep it in
# sync with versions.lock `models` and the harness --model flag.
variable "bedrock_inference_profile" {
  description = "Bedrock model/inference-profile id the ctl agent invokes."
  type        = string
  default     = "zai.glm-4.7-flash"
}

locals {
  # The underlying foundation-model id is the profile id without the us./global.
  # routing prefix (e.g. us.anthropic.claude-sonnet-5-5 -> anthropic.claude-sonnet-5-5).
  bedrock_fm_id = replace(var.bedrock_inference_profile, "/^(us|global)\\./", "")
}

# ctl-only instance role: same SSM + run-log write as the shared role, plus
# Bedrock invoke. Kept separate so no other host can call Bedrock.
resource "aws_iam_role" "ctl" {
  name_prefix = "cse227-ctl-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ctl_ssm_core" {
  role       = aws_iam_role.ctl.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "ctl_logs_write" {
  name = "runlogs-write"
  role = aws_iam_role.ctl.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject"]
      Resource = "${aws_s3_bucket.logs.arn}/*"
    }]
  })
}

# Scoped to exactly the pinned inference profile and its underlying foundation
# model. The foundation-model ARN uses a region wildcard because a us. profile
# may route the call to any US region; the inference-profile ARN is regional.
resource "aws_iam_role_policy" "ctl_bedrock" {
  name = "bedrock-invoke"
  role = aws_iam_role.ctl.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
      ]
      Resource = [
        "arn:aws:bedrock:${var.region}:${data.aws_caller_identity.me.account_id}:inference-profile/${var.bedrock_inference_profile}",
        "arn:aws:bedrock:*::foundation-model/${local.bedrock_fm_id}",
      ]
    }]
  })
}

resource "aws_iam_instance_profile" "ctl" {
  name_prefix = "cse227-ctl-"
  role        = aws_iam_role.ctl.name
}
