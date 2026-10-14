variable "region" {
  description = "AWS region for the testbed."
  type        = string
  default     = "us-west-2"
}

variable "owner" {
  description = "Owner tag for cost tracking / bulk teardown."
  type        = string
  default     = "gonzalo"
}

variable "arm" {
  description = "Which arm this stack builds. Arm A is straight OpenSSH, B is ssh with hardened security measures, and C is HOP "
  type        = string
  default     = "A"
  validation {
    condition     = contains(["A", "B", "C"], var.arm)
    error_message = "arm must be one of A, B, C."
  }
}

variable "os_version" {
  description = "Ubuntu version for the TARGET hosts (bastion/web1/db1). ctl is pinned to 22.04"
  type        = string
  default     = "22.04"
  validation {
    condition     = contains(["22.04", "26.04"], var.os_version)
    error_message = "os_version must be 22.04 or 26.04."
  }
}

# --- The safety switch (access to outside internet). -------------------------------------------------
# false  = egress-free VPC: no IGW, no NAT, no default route. This is the state
#          every scored run MUST use. See smoke test 1.
# true   = attach a temporary internet gateway + default route just so cloud-init can apt/snap-
#          install packages so we can make golden AMIs initially. just for setup!
variable "enable_egress" {
  description = "Temporarily allow internet egress for package install / AMI bake. Keep false for all real runs."
  type        = bool
  default     = false
}

# --- Golden AMIs (Amazon Machine Images)-------------------------------------------------------
# After the egress-on bake, set these to the AMIs you created and run egress-free.
# Empty => fall back to the stock Canonical AMI resolved in data.tf
variable "golden_ami_ctl" {
  type    = string
  default = ""
}
variable "golden_ami_target" {
  type    = string
  default = ""
}
variable "golden_ami_attacker" {
  type    = string
  default = ""
}
variable "golden_ami_dns" {
  type    = string
  default = ""
}

variable "instance_type_small" {
  type    = string
  default = "t3.small" # for controller agent, dont think this too expensive.
}
variable "instance_type_micro" {
  type    = string
  default = "t3.micro" # everything else,we just need some basic operations for now.
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16" # see network.tf for how we split up the subnets in the vpc.
}

variable "ssh_key_dir" {
  description = "Local dir where the generated canary private key is written (git-ignored)."
  type        = string
  default     = "../.secrets"
}
