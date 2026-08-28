# ModelFusion / HugOS IDE — Fix Memory

## Session: 2026-07-19 → 2026-07-21

### Fix 1: Title Bug — Chat Title Shows Model Answer Instead of User Question
- **Root Cause**: `ChatTitleProvider` in `title.ts` sent the user's question to the LLM and used the LLM's *answer* as the title.
- **Fix**: Replaced LLM-based title generation with direct extraction of the user's first prompt, truncated to 100 chars.
- **File**: `IDE/vscode/extensions/copilot/src/extension/prompt/node/title.ts`
- **Commit**: `11e78dd7`

### Fix 2: Accept/Reject (Keep/Undo) Buttons Not Showing on Code Blocks
- **Root Cause**: Multiple layers of safety filters in `_tryInlineApply()` were rejecting valid code blocks.
- **Fix**: Removed custom `_tryInlineApply()` call. VS Code provides native **Keep/Undo** buttons on all code blocks in chat responses.
- **File**: `IDE/vscode/extensions/copilot/src/extension/byok/vscode-node/modelFusionProvider.ts`
- **Commit**: `4124eee0`

### Fix 3: Token Null Guard
- **Root Cause**: `token.onCancellationRequested()` crashed when `token` was null/undefined.
- **Fix**: Changed to `token?.onCancellationRequested()` (optional chaining).
- **File**: `modelFusionProvider.ts`

### Fix 4: /evolve Slash Command Detection & OpenEvolve LLM Model Initialization
- **Root Cause A**: `/evolve` was registered in `package.json`'s `chatParticipants.commands`, causing VS Code to strip `/evolve` before it reached the model provider. Removed custom slash commands from `package.json`.
- **Root Cause B**: OpenEvolve was spawned without `--primary-model`, resulting in an empty model ensemble and `list index out of range` error.
- **Fix**: Added dynamic model resolution via `_selectModelForSystem()` and passed `--primary-model` to OpenEvolve. Added OpenAI-compatible `/v1/chat/completions` endpoint to Rust CLI server.

### Fix 5: Windows IPv6 Ollama Connection Timeout & Proxy Bypass
- **Root Cause**: Rust core/CLI queried `http://localhost:11434` which resolved to IPv6 (`::1:11434`) first on Windows, causing requests to hang for 10 minutes when Ollama listened on IPv4 (`127.0.0.1:11434`). System `HTTP_PROXY` also hijacked loopback calls.
- **Fix**: Replaced all `http://localhost:11434` occurrences with `http://127.0.0.1:11434` across Rust crates (`main.rs`, `providers.rs`, `memory.rs`) and added `.no_proxy()` to reqwest Client builders.
- **Commits**: `89bd0cf6`, `8381729a`

### Fix 6: Evaluator Import NameError & VRAM / UTF-8 Safety Guards
- **Root Cause A (NameError)**: The LLM generated `evaluator.py` with top-level test calls like `result = evaluate_code(calculate_distance)`. When OpenEvolve imported `evaluator.py`, module-level code executed immediately, causing `NameError: name 'calculate_distance' is not defined`.
- **Fix A**: Updated `evaluatorPrompt` to forbid top-level test calls and added regex sanitization in `modelFusionProvider.ts` to strip module-level execution statements before saving `evaluator.py`.
- **Root Cause B (10-Minute Timeout on 14B)**: `_selectModelForSystem()` selected `qwen2.5:14b` because system RAM was 32GB. But `14b` requires 9GB VRAM, exceeding consumer GPU capacity (8GB) and causing CUDA OOM thrashing / 10-minute timeouts in Ollama.
- **Fix B**: Capped default OpenEvolve model selection to `qwen2.5:7b` (4.6GB VRAM, responds in ~20 seconds), while respecting user explicit `ollamaModel` configuration if set.
- **Root Cause C (UnicodeEncodeError)**: Windows `cp1252` encoding threw `UnicodeEncodeError` when OpenEvolve logged the checkmark emoji (`\u2705`).
- **Fix C**: Set `PYTHONIOENCODING: 'utf-8'` and `PYTHONUTF8: '1'` in OpenEvolve child process `env`.
- **Commits**: `303693f2`, `c0b79fbe`

### Fix 7: Slash Command Transcript Hijacking (`/security --fix` -> `/evolve`)
- **Root Cause**: `allMessageTexts.join(' ')` scanned the entire chat transcript history. If previous assistant turns contained `[Evolve]` or `code evolution`, every subsequent user prompt (e.g. `/security --fix`) was forced into `/evolve`.
- **Fix**: Refactored `slashCommandText` extraction in `modelFusionProvider.ts` to inspect ONLY the latest incoming user message (`lastUserMsg`). Historical turns can no longer hijack new prompts. Expanded `cliCodeCommands` registry (`security`, `fix`, `review`, `explain`, `tests`, `refactor`, `audit`, `optimize`, `doc`, `generate`). All slash commands are case-insensitive.
- **Commits**: `9d03a1d9`, `dfd86c3a`, `fc0f434a`, `b631ba03`

### Fix 8: Hardware Resource Auto-Query & Strict GPU Enforcement
- **Root Cause**: `/orchestrate` requests without explicit GPU flags defaulted to `gpu=false, cpu=true, openvino=true`. Requests for 14B models on consumer GPUs (6GB VRAM) crashed Ollama with CUDA OOM thrashing.
- **Fix**: Added `query_system_resources()` in `crates/cli/src/main.rs` to detect RAM, CPU, total/free VRAM, and disk space. Hard-enforced `gpu=true, ollama=true, cpu=false, openvino=false` in both Rust CLI server and `modelFusionProvider.ts` whenever GPU hardware is present on the computer. Added automatic 14b -> 7b VRAM downscaling for GPUs with <10GB VRAM.
- **Commits**: `853133c6`, `701f87d4`, `7f7d6999`

---

## Git Commit Summary
- `f318d214` — fix: remove custom slash commands from package.json
- `f7a54673` — feat: add /v1/chat/completions OpenAI-compatible endpoint to CLI
- `89bd0cf6` — fix: replace http://localhost:11434 with http://127.0.0.1:11434
- `8381729a` — fix: bypass corporate proxy (.no_proxy()) for local loopback Ollama connections
- `303693f2` — fix: set PYTHONIOENCODING=utf-8 for OpenEvolve env and default to qwen2.5:7b for VRAM safety
- `c0b79fbe` — chore: update IDE/vscode submodule with OpenEvolve UTF-8 and VRAM safety fixes
- `9d03a1d9` — fix: target ONLY latest user message for slash command detection to stop transcript history hijacking
- `853133c6` — feat: query_system_resources hardware summary & auto-enable gpu=true and ollama=true in /orchestrate
- `7f7d6999` — feat: enforce GPU=true, Ollama=true, CPU=false in Rust server and IDE extension when GPU is present
