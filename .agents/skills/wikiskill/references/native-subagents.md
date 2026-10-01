# Antigravity, Codex, and Claude Code Native Delegation

Use the host's existing native subagent tool. Python prepares work and records results; it cannot invoke an in-conversation tool by itself. No provider CLI subprocess or new API credential is needed.

## Install in the user's selected project

```bash
wikiskill agents install --runtime antigravity --project /path/to/project
# Or:
wikiskill agents install --runtime codex --project /path/to/project
# Or:
wikiskill agents install --runtime claude-code --project /path/to/project
```

- **Antigravity:** Installs `.agents/subagents/wikiskill-{executor,maintainer,proposer}.md` and `.agents/skills/wikiskill/`.
- **Codex:** Installs `.codex/agents/wikiskill-{executor,maintainer,proposer}.toml` and `.agents/skills/wikiskill/`.
- **Claude Code:** Installs `.claude/agents/wikiskill-{executor,maintainer,proposer}.md` and `.claude/skills/wikiskill/`.

Existing differing assets are not overwritten. Reload host discovery as required by the installed version. Models, reasoning settings, and permissions inherit; installation changes no global defaults. The packaged files work from a wheel installation as well as a clone.

## Select the actual native tool

**Antigravity:** Use the exposed `invoke_subagent` tool with fresh context. Pass `Model: "flash"` and set `Role` to the installed subagent role (`wikiskill-executor`, `wikiskill-maintainer`, or `wikiskill-proposer`). In the subagent request, provide the handoff prompt path and payload path. Antigravity subagents execute within their own scoped context and write their outputs to the request's output directory.

**Codex:** Use the exposed spawn/delegate tool with no parent conversation inheritance. In the verified desktop tool schema, this is `spawn_agent` with `fork_turns="none"`. Select the registered `wikiskill-*` role when available. Otherwise use the general-purpose role with the same supplied `role.md` instructions.

**Claude Code:** Use the native `Agent` tool and select the installed `wikiskill-*` subagent. These are ordinary custom subagents, not forked agents. Do not use `resume` from a different request or a forked conversation.

All hosts can inherit project instructions, tools, permissions, and memory context. This workflow deliberately limits the handoff contents; it does not promise OS-level isolation or fully untouched benchmark conditions.

## Other hosts

Antigravity, Codex, and Claude Code are the **recommended** runtimes: their role assets ship with this package and their native flow was exercised. They are not the only ones allowed. Any host that can start a child with fresh context may run the same handoffs: pass its own short name (lowercase letters, digits, `.`, `-`, `_`) to `start --agent-runtime`, `dispatch --runtime` and `bind-agent --runtime`, and bind the handle that host actually returned. The runtime name is recorded provenance, not a permission; the same fresh-context, one-child-per-request and collect rules apply. `agents install` covers the recommended hosts because it copies their packaged role files; other hosts read each handoff's `role.md` directly.

## Run the authorized cycle

```bash
wikiskill start runs/job --tasks tasks.json --rounds 1 --agent-runtime antigravity
wikiskill dispatch runs/job --runtime antigravity
```

For Codex or Claude Code, set the runtime value to `codex` or `claude-code`. Configure the agreed scorer and trust as usual.

For each returned handoff:

1. If `reused_output` is present, collect it without another model execution.
2. If `delegation` is present, the request is already bound. Wait for or resume that same child; do not spawn a duplicate.
3. Otherwise call the host native tool with the handoff's `message`, role, and fresh-context setting. Do not append parent history, guesses, evaluation feedback, or answer content.
4. Record the **actual ID returned by that tool**, not an invented role name:

```bash
wikiskill bind-agent runs/job --request REQUEST_ID --agent-id ACTUAL_HOST_ID --runtime antigravity --context fresh
```

5. Wait for the child to finish. It writes `result.json` in the handoff's output directory. Submit without copying the answer into the coordinator conversation:

```bash
wikiskill collect runs/job --request REQUEST_ID
```

6. Dispatch again. Training completion unlocks Maintainer; its accepted submission unlocks Proposer; the proposal unlocks fresh candidate task requests. Continue until complete or an actual failure needs resolution, then generate `wikiskill report`.

`dispatch --count N` prepares independent task handoffs when capacity and authorized budget allow. It never runs Maintainer and Proposer concurrently. Do not use the same child for two different requests, even when they share a role or task ID.

For manual scoring, obtain the agreed human/judge evaluation and pass it to collect with `--score` and `--feedback`; executor self-scores in `result.json` are not used.

## Output contracts and recovery

The generated role instructions explain the JSON contract. Absolute output paths are preferred; relative output paths resolve inside that request's output directory. Executors return an output path and optional trace path. Maintainer returns source-bound patterns. Proposer returns a skill path and note, or `no_action: true`. Children write draft artifacts only; the main agent calls collect, and the existing controller applies them.

Record a native spawn/interruption failure with:

```bash
wikiskill fail runs/job --request REQUEST_ID --error "specific observed failure"
# After resolving the cause:
wikiskill retry runs/job --request REQUEST_ID
wikiskill dispatch runs/job --runtime antigravity
```

If a child is still running, wait or inspect its actual handle. Do not restart solely because a wait timed out. If spawning succeeded but binding was interrupted, find that existing host child and bind its actual ID. If its status cannot be recovered, stop it before explicitly failing/retrying the request. Format repair can use the same child for the same pending request; do not secretly resample task answers.

Scorer failures retain the actual output. Their retry handoffs reuse that execution and its source agent record. Native IDs/context modes are host-reported provenance, not independent proof of isolation. Direct `record/learn/propose` submissions in a configured native workflow require a bound child as well.
