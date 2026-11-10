"""Offline executable fixture: emits CLI-shaped events, never calls a service."""
import json
import os
from pathlib import Path
import sys
import time

args = sys.argv[1:]
mode = os.environ.get("SA_STUB_MODE", "pass")
log = os.environ.get("SA_STUB_LOG")
if log:
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"args": args, "cwd": str(Path.cwd())}) + "\n")

def emit(value):
    print(json.dumps(value), flush=True)

if args == ["--version"]:
    print("fixture-1.0")
    raise SystemExit(0)
if args == ["auth", "status"]:
    emit({"loggedIn": mode != "unauth"})
    raise SystemExit(0)
if args in (["login", "status"], ["status"]):
    print("Not logged in" if mode == "unauth" else "Logged in using fixture")
    raise SystemExit(0)
if args == ["app-server"]:
    for line in sys.stdin:
        obj = json.loads(line)
        if obj["method"] == "initialize":
            emit({"id": obj["id"], "result": {}})
        elif obj["method"] == "skills/list":
            cwd = obj["params"]["cwds"][0]
            skills = [{"name": p.parent.name, "path": str(p), "enabled": mode != "disabled"}
                      for p in Path(cwd).glob(".agents/skills/*/SKILL.md")]
            if mode == "discovery-missing":
                skills = []
            if mode == "duplicate":
                skills *= 2
            if mode == "wrong-path":
                for skill in skills:
                    skill["path"] = str(Path(cwd) / "elsewhere" / "SKILL.md")
            if mode == "discovery-error":
                emit({"id": obj["id"], "error": {"message": "unsupported"}})
            else:
                emit({"id": obj["id"], "result": {"data": [{"cwd": cwd, "skills": skills, "errors": []}]}})
    raise SystemExit(0)
if mode == "timeout":
    time.sleep(2)
if mode == "exit-error":
    raise SystemExit(1)
if mode == "unstructured":
    print("not a structured trace")
    raise SystemExit(0)
kind = "codex" if args and args[0] == "exec" else ("claude" if "--verbose" in args else "cursor")
prompt = args[args.index("-p") + 1] if "-p" in args else args[-1]
negative = "17" in prompt
skills = list(Path.cwd().glob((".claude" if kind == "claude" else ".agents") + "/skills/*/SKILL.md"))
# User-scope tests use an explicit fixture root rather than real home state.
if not skills and os.environ.get("SA_STUB_USER_ROOT"):
    skills = list(Path(os.environ["SA_STUB_USER_ROOT"]).glob((".claude" if kind == "claude" else ".agents") + "/skills/*/SKILL.md"))
if not skills:
    raise SystemExit(3)
skill = skills[0]
name = skill.parent.name
marker = "CANARY_SKILL_ANYWHERE_V0_7F3D9A2E"
text = "323" if negative else marker
if mode == "wrong-artifact" and not negative:
    text = "no artifact"
if mode == "negative-marker" and negative:
    text = marker
load = not negative or mode == "negative-load"
lunch = name == "clip-cutter" and not negative
command = str(skill.parent / "scripts" / "clip-cutter") + " 824705 --plan-only --max-seconds 300" if lunch else "cat " + str(skill)
if lunch:
    clips = [{"inning": "T1", "headline": "Opening hit"}, {"inning": "B3", "headline": "Run-scoring double"}]
    if mode == "unordered":
        clips.reverse()
    text = json.dumps({"clips": clips})
    if mode == "render":
        command = command.replace(" --plan-only", "")
    if mode == "video":
        (Path.cwd() / "out.mp4").write_bytes(b"fixture-video")
if kind == "codex":
    emit({"type": "thread.started"})
    emit({"type": "turn.started"})
    if load:
        item = {"id": "read", "type": "command_execution", "command": command, "aggregated_output": text, "exit_code": 0}
        emit({"type": "item.started", "item": item})
        emit({"type": "item.completed", "item": item})
    if mode == "opaque" and negative:
        emit({"type": "item.completed", "item": {"type": "mcp_tool_call"}})
    emit({"type": "item.completed", "item": {"type": "agent_message", "text": text}})
    if mode != "no-terminal":
        emit({"type": "turn.completed"})
else:
    emit({"type": "system", "subtype": "init"})
    if load:
        if kind == "claude":
            tool = {"type": "tool_use", "id": "read", "name": "Bash" if lunch else "Read", "input": {"command": command} if lunch else {"file_path": str(skill)}}
            emit({"type": "assistant", "message": {"content": [tool]}})
            emit({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "read", "content": text}]}})
        else:
            call = {"shellToolCall" if lunch else "readToolCall": {"args": {"command": command} if lunch else {"path": str(skill)}, "result": {"success": {"content": text}}}}
            emit({"type": "tool_call", "subtype": "started", "call_id": "read", "tool_call": call})
            emit({"type": "tool_call", "subtype": "completed", "call_id": "read", "tool_call": call})
    if mode == "opaque" and negative:
        emit({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "unknown", "input": {}}]}})
    if mode != "no-terminal":
        emit({"type": "result", "subtype": "success", "is_error": False, "result": text})
