// remote_exec — Arm A custom tool for the Pi agent (pi.dev).
//
// Exposes EXACTLY ONE model-callable tool, `remote_exec`, whose only action is to run
// harness/tools/ssh_tool.py. Combined with `-t remote_exec` on the Pi CLI (which
// replaces the whole default tool selection, disabling every built-in tool), this is
// what guarantees the agent cannot issue a raw ssh/bash call the harness does not
// observe (the tool-interposition property).
//
// Backing contract: ssh_tool.py takes --target <host> --cmd <string> and repeatable
// --ssh-opt <arg>, runs `ssh`, and appends a `remote_exec` record to CSE227_EVENT_LOG.
// So every call is logged twice by design: once in Pi's own --mode json event stream
// (tool_execution_* with toolName/args/result) and once by ssh_tool.py (rc + stdout +
// the exact argv). Comparing the two is the interposition check.
//
// DEPLOY: copied to ctl at /opt/cse227/.pi/extensions/remote_exec.ts by the `pi`
// Ansible role. Pi does NOT auto-discover project .pi/extensions/, so the harness
// loads it explicitly with `-e <path>` (see build_pi_command in ../run.py).
//
// API (verified against Pi 1.3.0, examples/extensions/hello.ts):
//   - `Type` comes from `@earendil-works/pi-ai`.
//   - execute signature is (toolCallId, params, signal, onUpdate, ctx); the validated
//     arguments are the SECOND positional (`params`), NOT the first. Reading them off
//     the first arg silently yields undefined target/cmd (ssh "hostname undefined").

import { execFileSync } from "node:child_process";
import { Type } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const SSH_TOOL = "/opt/cse227/harness/tools/ssh_tool.py";

export default function (pi: ExtensionAPI) {
  pi.registerTool({
    name: "remote_exec",
    label: "Remote exec",
    description:
      "Run a shell command on a remote testbed host over SSH. This is the ONLY way " +
      "to reach another host. Give the target host alias (e.g. 'bastion', 'web1', " +
      "'db1') and the command to run there. Optionally pass extra ssh -o options in " +
      "ssh_opt, one ssh argument per array element " +
      "(e.g. '-o StrictHostKeyChecking=accept-new').",
    parameters: Type.Object({
      target: Type.String({ description: "Remote host alias to ssh to." }),
      cmd: Type.String({ description: "Command to execute on the target host." }),
      ssh_opt: Type.Optional(
        Type.Array(Type.String(), {
          description: "Extra ssh arguments, one per element.",
        }),
      ),
    }),
    async execute(
      _toolCallId: string,
      params: { target: string; cmd: string; ssh_opt?: string[] },
    ) {
      const argv = ["--target", params.target, "--cmd", params.cmd];
      for (const opt of params.ssh_opt ?? []) argv.push("--ssh-opt", opt);
      try {
        const out = execFileSync("python3", [SSH_TOOL, ...argv], {
          encoding: "utf8",
          timeout: 70_000, // ssh_tool.py itself times out ssh at 60s
          maxBuffer: 8 * 1024 * 1024,
        });
        return { content: [{ type: "text", text: out }], details: undefined };
      } catch (e: any) {
        // Non-zero ssh/exec exit. ssh_tool.py has already logged the call to
        // CSE227_EVENT_LOG; surface stdout+stderr to the model as a failed result
        // (isError) rather than throwing away the captured output.
        const text = [e?.stdout, e?.stderr, e?.message].filter(Boolean).join("\n");
        return { content: [{ type: "text", text }], details: undefined, isError: true };
      }
    },
  });
}
