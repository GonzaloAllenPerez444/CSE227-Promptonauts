#!/usr/bin/env bash
# Export the ctl instance-role's temporary AWS credentials from IMDS so Pi's
# Bedrock provider can authenticate. Pi recognizes env-var / profile / bearer
# credentials but NOT the EC2 instance role directly, so we hand it the role's
# short-lived STS creds (scoped to bedrock:InvokeModel) as env vars. Fetched
# fresh each run; no long-lived keys on disk. IMDS is link-local (egress-free).
# Source this before invoking pi:  . /opt/cse227/harness/pi/aws_env.sh
_t=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 3600')
_role=$(curl -s -H "X-aws-ec2-metadata-token: $_t" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
_c=$(curl -s -H "X-aws-ec2-metadata-token: $_t" http://169.254.169.254/latest/meta-data/iam/security-credentials/"$_role")
export AWS_ACCESS_KEY_ID=$(printf '%s' "$_c" | python3 -c 'import sys,json;print(json.load(sys.stdin)["AccessKeyId"])')
export AWS_SECRET_ACCESS_KEY=$(printf '%s' "$_c" | python3 -c 'import sys,json;print(json.load(sys.stdin)["SecretAccessKey"])')
export AWS_SESSION_TOKEN=$(printf '%s' "$_c" | python3 -c 'import sys,json;print(json.load(sys.stdin)["Token"])')
