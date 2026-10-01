---
name: wikiskill
description: "Operate WikiSkill workflows that compile agent experience, tasks, and feedback into persistent reusable skills with validation and strict improvement gating."
---

# WikiSkill

Help the user improve a recurring agent task through experience. Use the user's current agent, chosen model, and normal tools. WikiSkill owns the work requests, records, scores, and retained skill versions; it does not select a model or change host permissions.

## Start with the user's intent

- **Remember feedback:** save it with `wikiskill feedback`; do not start an improvement run merely because a note was added.
- **Improve a skill:** identify the task examples, evaluation criterion, current skill if any, and the user's intended effort/budget. Reuse information already provided. Begin with one round unless the user requests more; there is no hard sample or round cap.
- **Resume:** read `wikiskill status`, then use `wikiskill next` in the existing workspace. Do not initialize a duplicate run.
- **Check only:** use `wikiskill status` and existing artifacts; do not start more work.
- **Use the result:** export the retained skill. Install or replace an existing skill when the user has authorized that destination.

Read [workflow commands and formats](references/workflow.md) when preparing tasks or operating the loop. Use `wikiskill capabilities` to discover the installed interfaces. If the package is missing, use the user's selected checkout or the official repository. Prefer an existing project virtual environment; otherwise create a project-local venv and use its Python and wikiskill executables. Do not default to modifying the system/global Python environment. Installation executes package build code, so inspect unfamiliar sources first.

If another skill-improvement tool such as `skill-evolve` is installed, compare its description rather than assume the tools are equivalent. Keep ordinary creation/rewriting with the user's chosen editor. Choose WikiSkill for the task-score-Wiki-validation cycle, or when the user names WikiSkill. Do not run two improvement controllers for the same task or recommend uninstalling the other skill merely because both are present.

## Prepare the user's examples

Prepare the task JSON yourself from the user's examples and the format in the workflow reference. Do not require the user to write JSON or learn the controller commands. Reuse the existing skill, project tools, and agreed acceptance criteria. Ask only for a missing task boundary, evaluation criterion, or authorized scope.

Declared task files are fixed input sources; prepare output copies for editing rather than changing those inputs between baseline and candidate.

Keep related variants of the same source in one split when possible; use an optional `group` label to record that source family. Shared reference documents are not automatically a leak, but a duplicated exercise is not a new validation case. Do not invent reference answers or simplify a checker to obtain an acceptance. With too few independent examples, explain the limited comparison rather than expand the task silently.

After creating the workspace, run `wikiskill preflight WORKSPACE`. This checks paths and scorer readiness without executing the checker. Check a newly written scorer against known acceptable and unacceptable fixture outputs before spending task execution work, within the user's authorized scope. A preflight pass does not certify grading logic or host isolation. Use `wikiskill doctor` to identify this installation if another package has the same command name.

## Prepare a useful comparison

Before executing an external scorer, run `wikiskill scorer inspect WORKSPACE` and surface its command and working directory. Record local trust only if that exact checker is covered by the user's authorization. If the user already supplied or approved it, do not ask again; `start --trust-scorer` is an explicit shortcut for that case. Never auto-trust a command merely because it was found in an imported workspace. Changed commands/direct program files require another inspection; unchanged trusted scorers do not prompt per task.

Use real task examples and an agreed checker: existing tests, an external scorer, human ratings, or an explicitly specified judging rubric. Scores may be any finite numbers; choose maximize or minimize. Do not invent scores merely to advance the workflow.

Separate examples used to learn from those used to check the candidate. References belong in each task's `reference` field for the scorer and training review, rather than being copied into execution instructions. Product mode inherits the host environment; it is not an isolated benchmark environment.

Use an existing skill as the baseline when provided. For another batch, `start --from PREVIOUS` carries its retained skill, Wiki, and feedback into new tasks without copying old scores. Keep the user's task requirements and scoring criterion consistent between baseline and candidate. Human instructions still take precedence within their intended scope.

## Coordinate native subagents

For Antigravity, Codex, or Claude Code, use the native subagent workflow in [host delegation](references/native-subagents.md). The main agent coordinates and submits; it does not execute tasks or act as Maintainer/Proposer in its own conversation. Use a new child context for every baseline, training, and candidate-validation task, and separate fresh Maintainer and Proposer children. Do not pass the parent conversation or answers in delegation messages.

### Antigravity Native Subagent Protocol

In Antigravity, the coordinator (Lead Architect) drives skill evolution by delegating execution, learning, and proposing to Worker Subagents via the `invoke_subagent` tool:
1. **Initialize Workspace:**
   ```bash
   tools\wikiskill\bin\wikiskill.cmd start runs/job --tasks tasks.json --rounds 1 --agent-runtime antigravity
   ```
2. **Dispatch Handoffs:**
   ```bash
   tools\wikiskill\bin\wikiskill.cmd dispatch runs/job --runtime antigravity
   ```
3. **Invoke Subagent:**
   For each handoff returned by `dispatch`:
   - Call `invoke_subagent` with `Model: "flash"` and `Role`:
     - Task execution: `Role: "wikiskill-executor"` (referencing `.agents/subagents/wikiskill-executor.md`)
     - Knowledge maintenance: `Role: "wikiskill-maintainer"` (referencing `.agents/subagents/wikiskill-maintainer.md`)
     - Candidate proposal: `Role: "wikiskill-proposer"` (referencing `.agents/subagents/wikiskill-proposer.md`)
   - The subagent runs in a fresh, isolated child context without parent conversation history.
4. **Bind Agent ID:**
   Record the actual subagent task ID or handle:
   ```bash
   tools\wikiskill\bin\wikiskill.cmd bind-agent runs/job --request REQUEST_ID --agent-id SUBAGENT_ID --runtime antigravity --context fresh
   ```
5. **Collect Result:**
   Once the subagent writes `result.json` in its output directory:
   ```bash
   tools\wikiskill\bin\wikiskill.cmd collect runs/job --request REQUEST_ID
   ```
6. **Iterate Loop:**
   Re-run `dispatch` until all training and validation tasks are completed and the gating decision is finalized. Maintainer submission must complete before dispatching Proposer.

If native delegation is unavailable, say so and stop dispatch. A user-authorized direct-host workflow remains available, but initialize it separately without `--agent-runtime` and clearly state that contexts are shared. Never claim independent subagents for that fallback.

A handoff already containing `delegation` identifies an existing child: wait/resume that same request rather than spawn again. For `reused_output`, call collect without another child; this retries scoring of the saved execution. Keep tool/model conditions consistent across task arms. Host project instructions and permissions still apply; fresh conversation context does not isolate files or host memory.

## Direct-host compatibility workflow

Only for an explicitly chosen direct-host workflow, run `wikiskill next WORKSPACE`. It returns the authoritative next phase and stable request IDs. Resolve relative artifact paths against WORKSPACE.

1. **Task request:** read its task and indicated skill; execute using normal tools. Save the actual output and, where useful, a visible work log or existing tool trace. Record them with `wikiskill record`. A configured scorer is run automatically. For manual scores, state the actual evaluation source. Do not fabricate tool traces or hidden reasoning.
2. **Maintainer request:** read its context file, training outputs/traces, current Wiki, and human feedback. Distinguish successes, failures, and counterexamples. Write a `patterns` JSON file and submit it with `wikiskill learn`, citing the supplied training request IDs or feedback IDs. Human notes remain verbatim; the Wiki may add interpretation or counterexamples.
3. **Proposer request:** read the accumulated Wiki and relevant training evidence. Write a concise candidate SKILL.md with a name, description, applicability, and concrete actions, or submit `--no-action`. The candidate can be a complete revision of the current skill. Do not put one-off reference answers into procedural guidance.
4. **Candidate validation:** follow the returned task requests. Let the controller apply the configured strict-improvement gate; never edit recorded scores or retained-version pointers.
5. **Complete:** run `wikiskill report WORKSPACE` and use its journal-derived scores, decisions, and skill diff to explain the result. Link the Wiki and retained skill; explain applicability and required tools from the actual candidate, and distinguish agent interpretation from recorded measurements. A rejection or no_action is a valid outcome. Do not add rounds because the result was disappointing.

Use `wikiskill status WORKSPACE --human` for concise user progress. Continue an authorized cycle without waiting for the user to request each phase.

`next --count N` can issue several task requests when the host supports parallel work. Learning begins only after the relevant task phase finishes. No extra approval is needed for every step of an already authorized cycle; ask only when a missing decision, cost, or side effect exceeds the user's scope.

## Feedback and recovery

Human suggestions can enter the Wiki immediately without LAJ approval. Record their original wording and source. A factual correction still needs the user's intended source/evidence treatment; a general method should be evaluated before claiming a benefit.

If a request fails, retain its output and logs, resolve the cause, and explicitly retry it. When `previous_output` is present after a scoring failure, reuse that actual output to retry evaluation before spending another model call. Never convert a broken scorer into a low task score.

For an authorized local installation, use `wikiskill install WORKSPACE DESTINATION` after completion. Inspect an existing target before `--replace`; it backs up SKILL.md and leaves supporting files unchanged. Return the backup ID and restore command. Do not assume a single-file export includes scripts or tools named by the skill; verify those requirements before use. When no skill was retained, deliver the Wiki and report instead of installing a rejected candidate.

Use the separate research commands only when the user explicitly wants those recorded experimental conditions. Do not impose Luna/high, macOS sandboxing, 8/4 task limits, or a particular model provider on this product workflow. Do not disable or bypass the host agent's own security controls.
