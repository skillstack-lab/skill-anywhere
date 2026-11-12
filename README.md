# Skill Anywhere

Install one standard [Agent Skills](https://agentskills.io/specification) directory into Claude Code, Codex, and Cursor, then check **behavior**, not just files on disk. This is a thin installer and cold-load verifier, not a registry or a replacement for existing package managers.

## Install the CLI

Python 3.11+ on Linux is required for the tested path. From this project:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

Validation uses the official `skills-ref` Python API, pinned to the source archive at public commit `83021e2be457a9b6679148719c1f6074f0ad975e`, not an unrelated package with the same name. Its [official installation and API instructions](https://github.com/agentskills/agentskills/tree/main/skills-ref) describe a reference implementation, not a production guarantee. Installing this CLI fetches that archive and its dependencies; no harness or sign-in is installed automatically.

## One install line

```sh
skill-anywhere validate examples/canary
project=$(mktemp -d)
skill-anywhere install examples/canary --target claude,codex,cursor --scope project --project "$project"
```

The source must be a directory containing `SKILL.md`, with a matching `name`. Optional scripts, references, assets, and other regular files are copied too. Every file byte and executable flag is retained. A local receipt records SHA-256 digests; it is an integrity record, not a signature.

User scope is `skill-anywhere install examples/canary --target claude,codex,cursor --scope user`. It writes to the current user's home. Do not give `--project` for user scope. A re-install of a skill this CLI already owns (a matching receipt is present) is a no-op when the installed bytes already match the source. If a destination is a leftover symlink, or if file contents have drifted, re-install **refreshes a real copy**. Staleness is decided by SHA-256 digests and executable flags, never mtimes. Foreign skills or receipts this CLI did not write are still refused. Source trees, ancestor paths, and special files may not be symlinks; a leftover destination symlink is replaced on re-install.

### Documented paths

Checked against current official docs on **9 November 2026**:

| Target | Project | User | Official documentation |
|---|---|---|---|
| `claude` | `.claude/skills/<name>/` | `~/.claude/skills/<name>/` | [Claude Code skills](https://code.claude.com/docs/en/skills/) |
| `codex` | `.agents/skills/<name>/` | `~/.agents/skills/<name>/` | [Codex skills](https://learn.chatgpt.com/docs/build-skills.md) |
| `cursor` | `.agents/skills/<name>/` | `~/.agents/skills/<name>/` | [Cursor skills](https://cursor.com/docs/skills) |

Codex and Cursor share one physical copy when requested together. Claude gets a separate byte-identical **real copy**, not a symlink. Open Claude Code bugs report that symlinked skills and commands are not discovered or do not appear in autocomplete, so v0 never installs a symlink for any target. Claude's docs do not list `.agents/skills/`. Cursor also reads Claude compatibility paths: mixed installs can therefore expose duplicate names. v0 does not claim Cursor duplicate-name detection without a list API. Cold tests intentionally isolate each target; they do not prove mixed-project deduplication.

Only the six standard frontmatter fields are accepted: `name`, `description`, `license`, `compatibility`, `metadata`, and experimental `allowed-tools`. Extra tool-specific fields are rejected with their names and an instruction to move them to an external overlay. v0 neither applies overlays nor silently drops fields; successful reports show `isolated_frontmatter: []`. The Markdown body is never rewritten. String lengths, directory-name agreement, YAML types, duplicate keys, and the official reference checker are enforced.

## Verify, explicitly opting into live calls

Once the harness is installed and signed in, and live usage is approved:

```sh
skill-anywhere verify examples/canary --target claude,codex,cursor --project "$project" --case canary --live --evidence "$HOME/skill-anywhere-evidence"
```

Without `--live`, verify can check local integrity and non-model version/auth status, but returns **BLOCKED**, never PASS. Each full live verify makes **at most two cold calls per target**: one trigger, then one unrelated negative. There are no automatic retries or login attempts. There is no model identifier override; harness defaults are used, with low effort requested for Claude. This option is a deliberate usage gate, not a billing cap; provider usage limits still apply.

Exit codes are **0 PASS**, **1 FAIL** (a failed assertion), and **2 BLOCKED** (a missing prerequisite, unqueryable/opaque trace, timeout, explicit hold, or partial test). Every requested target must pass. Exceptions and skips cannot silently produce PASS.

The stages are:

1. Validate the original and installed copies using `skills-ref`; compare complete file inventories and executable flags to the receipt and each other, never mtimes. A leftover symlink or a content mismatch fails closed and tells you to re-run `install`, which refreshes a real copy. Verify itself does not rewrite files, so a tampered install still fails rather than being silently repaired.
2. Check the binary version and authentication using only documented status commands.
3. Create a fresh temporary project for each prompt. For project scope, install the already-verified bytes there through this installer, for that target alone. For user scope, start in an empty temporary project and use the actual user install. No prior conversation is resumed. Existing user-level settings/skills can still affect these processes; this is not a hermetic home or security sandbox.
4. Query discovery when supported. Codex uses the documented local app-server [`skills/list`](https://developers.openai.com/codex/app-server) method without creating a thread or turn. A missing, disabled, duplicated, or wrong-path entry fails. An unavailable query blocks. Claude and Cursor expose interactive menus but no documented non-interactive skill-list command in these adapters, so discovery is explicitly **UNSUPPORTED**, not PASS.
5. Trigger the skill and require the expected output artifact. The canary's marker is never put in either prompt, so the marker demonstrates access to the skill instructions. Custom cases also require an observed invocation/read. The canary prompt is exactly `Run the skill-anywhere canary.`
6. In another fresh process, ask exactly `What is 17 × 19?`. Reject a skill invocation/read or marker emission. A missing completion, unfinished tool action, opaque action, or unstructured trace blocks: the absence of a marker alone is not proof of non-loading.

"Not loaded" here means no body read or invocation **observed in the documented tool trace**, not that the harness never held metadata internally. Future protocol changes may block a run until an adapter is updated. Stub tests prove adapter logic, not real harness skill loading.

The adapters use [Claude print/stream mode](https://code.claude.com/docs/en/headless), [Codex exec JSON events](https://developers.openai.com/codex/noninteractive), and [Cursor headless mode](https://cursor.com/docs/cli/headless) with its [stream format](https://cursor.com/docs/cli/reference/output-format). They do not disable permission checks, auto-approve arbitrary tools, force writes, or read credential files. The Claude Lunch Reel case grants only Read/Skill and narrowly matched known-game `--plan-only` wrapper commands; it never grants unrestricted shell permission. Some script skills need an existing narrow permission grant; a denial is BLOCKED, not an invitation to bypass permissions.

Use `--claude-bin`, `--codex-bin`, or `--cursor-bin` to select an explicit executable. Cursor resolves the officially documented `agent` name first, then `cursor-agent`. An explicit executable can be any program, so only point these options at binaries you trust. `--block-target claude='Usage limit; rerun after reset'` records a hold without invoking that target at all.

Evidence is opt-in. It contains selected, best-effort-redacted prompts, answers, tool arguments, result summaries, version, relative install path, and an America/Chicago timestamp. Raw event streams, account responses, environments, and opaque identifiers are not saved. Evidence directories/files use private permissions. Review it before sharing: arbitrary model text can contain sensitive content that heuristic redaction misses. Keep it outside the source tree.

### A custom skill

```sh
skill-anywhere verify path/to/my-skill --target codex --project "$project" --case custom --live \
  --trigger 'Perform the workflow this skill describes.' \
  --negative 'What is 17 × 19?' --expect-text 'expected output fragment'
```

Install that skill first. The expected fragment must not occur in either prompt. stdout text is the expected artifact in this version; arbitrary file-artifact assertions are not implemented.

## Lunch Reel dogfood

Use a separately obtained, unmodified copy of public [Lunch Reel](https://github.com/skillstack-lab/lunch-reel). Do not copy its source into this project or change its plugin packaging.

```sh
lunch_project=$(mktemp -d)
skill-anywhere validate path/to/lunch-reel/skills/clip-cutter
skill-anywhere install path/to/lunch-reel/skills/clip-cutter --target claude,codex,cursor --project "$lunch_project"
skill-anywhere verify path/to/lunch-reel/skills/clip-cutter --target claude --project "$lunch_project" --case lunch-reel --live --follow-only --evidence "$HOME/skill-anywhere-evidence"
# Repeat that verify line with --target codex and --target cursor.
```

The cold prompt is exactly `I missed the Cubs on Sept 27, give me the 5-minute version.` The test requires an observed `scripts/clip-cutter` or `scripts/reel2.py` command with `--plan-only`, the known game `824705` or date/team `2026-09-27`/`CHC`, plus a non-empty answer with game-ordered innings and headlines (JSON or a simple inning/headline list). Only this known single-game cold test is covered; this is not a general baseball correctness grader.

`CLIP_CUTTER_HOME` points inside the fresh temporary project. Media files in that project and obvious render commands cause FAIL. This is an after-the-fact assertion over the observed trace and local artifacts, not an OS/network guarantee against a malicious skill or bytes written elsewhere. Review skills before permitting their scripts. No video should be downloaded or rendered for this test.

`--follow-only` runs just the single Lunch Reel cold first-win, keeping the three-call-per-harness pattern when combined with the canary's two calls. Its trigger can PASS, but the **overall verify remains BLOCKED/exit 2** because no Lunch Reel negative ran. Omit that flag for a full two-call Lunch Reel verify, only after approving the extra call. Do not turn this partial result into a full verification claim.

The existing `claude plugin install lunch-reel --marketplace skillstack-lab/lunch-reel` path is untouched. Preserving it structurally is not a claim that it has been live-tested here.

## Tests and current limits

```sh
python -m unittest discover -s tests -v
python -m unittest discover -s tests -v
```

Unit tests invoke only explicit offline fixture executables, never a real harness. They cover all three event adapters, official schema validation, clean processes, inventory/body tampering, missing binaries/auth, negative-trigger failures, opaque/incomplete traces, Codex discovery failures, and plan-only assertions. CI runs those unit tests twice and makes no model calls.

Layout-only sketches for Copilot, Gemini CLI, Antigravity, and OpenCode are in `SKETCHES` in `skill_anywhere/core.py`; they are not accepted install or verify targets. Their cited official docs are pointers, not runtime support claims.

v0 does **not** port always-on rules: `.mdc`, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, or Copilot instructions. It does not rewrite skill bodies into dialects, manage credentials, publish skills, or guarantee future harness API compatibility. A successful copy is **not** a passing load until verify passes. No three-harness live acceptance or independent first-use success is claimed by this source distribution.

MIT licensed; dependencies retain their own licenses.
