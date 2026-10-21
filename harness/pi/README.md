# Pi agent wiring (Arm A)

What `build_pi_command()` in `../run.py` assumes exists on `ctl`. None of this is
deployed by the driver; it is a provisioning step (an Ansible role + an AMI bake, or a
one-time manual install) that is **not yet done**.

## Pinned invocation (recorded in `../../versions.lock`)
Run as `delegate`, cwd `/opt/cse227`:
```
pi --mode json --model <PINNED_MODEL_ID> -t remote_exec "<task>"
```
- `--mode json` — headless one-shot + newline-delimited JSON event stream (the
  oracle/classifier input). Not `--print` (final text only).
- `--model <id>` — pin one concrete id; never change mid-study.
- `-t remote_exec` — only the custom tool below is callable; all built-ins off.

## The custom tool
`extensions/remote_exec.ts` → deploy to `/opt/cse227/.pi/extensions/remote_exec.ts`.
It is the single model-callable tool and shells to `harness/tools/ssh_tool.py`.

## Model access (Amazon Bedrock over the VPC interface endpoint) — APPLIED
- `terraform/data.tf` adds the `bedrock-runtime` interface endpoint (available, private
  DNS); `terraform/bedrock.tf` gives ctl its own role with
  `bedrock:InvokeModel[WithResponseStream]` scoped to the pinned profile + its
  foundation model; `terraform/instances_ctl.tf` points ctl at that profile. Applied.
- Pinned model: `us.anthropic.claude-sonnet-4-6` (confirmed invokable; the 5.x models —
  sonnet/opus/haiku-5-5, opus-4-8 — are NOT enabled for this account). These are
  INFERENCE-PROFILE-only, so `--model` is the `us.` inference-profile id.
- Credentials: Pi's Bedrock provider does NOT read the EC2 instance role directly; it
  needs env-var creds. `harness/pi/aws_env.sh` exports the role's short-lived STS creds
  from IMDS (no keys on disk); `build_pi_command` sources it before `pi`.

## Status: Pi 1.3.0 installed + wired on ctl; switched to GLM 4.7 Flash to unblock
Done: Pi 1.3.0 installed (`/home/delegate/.pi/agent/bin/pi`), `remote_exec` extension at
`/opt/cse227/.pi/extensions/`, delegate profile exports (PATH/AWS_REGION/SSH_AUTH_SOCK),
`aws_env.sh` deployed. Pi runs headless, reaches Bedrock over the endpoint, IMDS creds
authenticate.

**Active model — `zai.glm-4.7-flash` (Z.ai, Bedrock on-demand, us-west-2).** Enabled via
EULA accept only — no use-case form, no enterprise creds (that gate was only on GLM 5.3),
so this sidesteps the Anthropic form blocker below. Remaining validation: confirm Pi
drives a NON-Anthropic Bedrock model with tool-calling, i.e. a `remote_exec` call actually
appears in the JSON event stream. Only the Anthropic path was ever wired, and Flash is a
small variant, so if its tool-use is too weak, bump the model to full GLM 4.7 / GLM 5
(one-var change).

**PENDING SECOND CELL — Bedrock Anthropic use-case form (account-level, console only).**
To add a Claude cell later, every Anthropic Bedrock call returns `ResourceNotFoundException:
Model use case details have not been submitted for this account` until the Anthropic
use-case form is submitted (Bedrock console, us-west-2 → Model access, ~15 min). Not
needed for the GLM cell.

## After the form clears
1. Validate end-to-end: a forced `remote_exec` call proves the extension loads + is
   callable + shells to ssh_tool.py (not yet seen — model errored before any tool use).
2. Bake the ctl golden AMI (captures the Pi install), update `golden.auto.tfvars` +
   `versions.lock`, then `terraform apply -var enable_egress=false` to restore the
   egress-free posture (ctl rebuilds from the baked AMI).
3. ssh-agent per-run restart is wired (`run.py start_delegate_agent` + the `pi` role's
   SSH_AUTH_SOCK export) so Idea 1's forwarded canary key is present.
