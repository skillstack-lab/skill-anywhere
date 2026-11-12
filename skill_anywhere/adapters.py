"""Documented CLI entry points; never authenticate or silently retry."""
import json
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time

from .core import Problem

CANARY_MARKER = "CANARY_SKILL_ANYWHERE_V0_7F3D9A2E"


def redact(text):
    text = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "[email]", str(text))
    text = re.sub(r"(?i)(?:sk-|gh[pousr]_|github_pat_|xox[baprs]-)[A-Za-z0-9_-]{10,}", "[credential]", text)
    text = re.sub(r"(?i)Bearer\s+\S+", "Bearer [credential]", text)
    text = re.sub(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b", "[identifier]", text)
    text = re.sub(r"(?:/home/|/Users/)[^\s\"']+", "[home-path]", text)
    text = re.sub(r"[A-Za-z]:\\Users\\[^\s\"']+", "[home-path]", text)
    return text


def run(argv, cwd, timeout, env=None):
    try:
        completed = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise Problem("Harness query timed out; no retry attempted", "BLOCKED") from exc
    except OSError as exc:
        raise Problem("Harness binary unavailable or not executable", "BLOCKED") from exc
    if len(completed.stdout) + len(completed.stderr) > 16 * 1024 * 1024:
        raise Problem("Harness output exceeded 16 MiB", "BLOCKED")
    return completed


def resolve_binary(target, override=None):
    candidates = [override] if override else ({"claude": ["claude"], "codex": ["codex"],
                                               "cursor": ["agent", "cursor-agent"]}[target])
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    raise Problem("Requested harness binary missing: " + target, "BLOCKED")


def preflight(target, binary, cwd, timeout):
    version = run([binary, "--version"], cwd, timeout)
    if version.returncode != 0 or not version.stdout.strip():
        raise Problem("Harness version cannot be queried", "BLOCKED")
    auth_args = {"claude": ["auth", "status"], "codex": ["login", "status"], "cursor": ["status"]}[target]
    auth = run([binary, *auth_args], cwd, timeout)
    if target == "claude":
        try:
            valid = json.loads(auth.stdout).get("loggedIn") is True
        except (ValueError, AttributeError):
            valid = False
    else:
        text = auth.stdout + "\n" + auth.stderr
        denied = re.search(r"not\s+(?:logged\s+in|authenticated)|unauthenticated", text, re.I)
        valid = bool(re.search(r"\b(?:logged\s+in|authenticated)\b", text, re.I)) and not denied
    if auth.returncode != 0 or not valid:
        command = {"claude": "claude auth login", "codex": "codex login --device-auth", "cursor": "agent login"}[target]
        error = Problem("Harness unauthenticated or status unrecognized; sign in manually with " + command, "BLOCKED")
        error.version = redact(version.stdout.strip())
        raise error
    return redact(version.stdout.strip())


def cold_command(target, binary, prompt, expected_path=None, case=None):
    if target == "claude":
        allowed = "Read,Skill"
        if case == "lunch-reel" and expected_path is not None:
            base = Path(expected_path).parent / "scripts"
            allowed += ",Bash(" + str(base / "clip-cutter") + " 824705 --plan-only *)"
            allowed += ",Bash(" + str(base / "clip-cutter") + " --date 2026-09-27 --team CHC --plan-only *)"
            allowed += ",Bash(python3 " + str(base / "reel2.py") + " 824705 --plan-only *)"
        return [binary, "-p", prompt, "--output-format", "stream-json", "--verbose",
                "--no-session-persistence", "--permission-mode", "dontAsk", "--effort", "low",
                "--allowedTools", allowed]
    if target == "codex":
        return [binary, "exec", "--json", "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", prompt]
    # --trust is required for a non-interactive start in the throwaway temp project.
    # Do not pass --force/--yolo: those auto-approve command execution.
    return [binary, "-p", prompt, "--output-format", "stream-json", "--mode", "ask", "--trust"]


def discover(target, binary, cwd, name, expected, timeout):
    if target != "codex":
        return {"status": "UNSUPPORTED", "reason": "No documented non-interactive skill-list command in this adapter"}
    # Local stdio only. No thread/start or turn/start, and thus no model call.
    with tempfile.TemporaryFile(mode="w+") as errors:
        try:
            proc = subprocess.Popen([binary, "app-server"], cwd=cwd, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=errors, text=True, bufsize=1)
        except OSError as exc:
            raise Problem("Codex discovery unavailable", "BLOCKED") from exc
        inbox = queue.Queue()
        def read_lines():
            try:
                for line in proc.stdout:
                    inbox.put(line)
            finally:
                inbox.put(None)
        reader = threading.Thread(target=read_lines, daemon=True)
        reader.start()
        deadline = time.monotonic() + timeout
        def send(value):
            try:
                proc.stdin.write(json.dumps(value) + "\n")
                proc.stdin.flush()
            except (OSError, ValueError) as exc:
                raise Problem("Codex discovery pipe closed", "BLOCKED") from exc
        def receive(identity):
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Problem("Codex discovery timed out", "BLOCKED")
                try:
                    line = inbox.get(timeout=remaining)
                except queue.Empty as exc:
                    raise Problem("Codex discovery timed out", "BLOCKED") from exc
                if line is None:
                    raise Problem("Codex discovery ended before response", "BLOCKED")
                try:
                    obj = json.loads(line)
                except ValueError as exc:
                    raise Problem("Codex discovery returned invalid JSON", "BLOCKED") from exc
                if obj.get("id") == identity:
                    if "error" in obj or "result" not in obj:
                        raise Problem("Codex skills/list query refused or unsupported", "BLOCKED")
                    return obj["result"]
        try:
            send({"method": "initialize", "id": 1, "params": {"clientInfo": {"name": "skill_anywhere", "version": "0.1.0"}}})
            receive(1)
            send({"method": "initialized", "params": {}})
            send({"method": "skills/list", "id": 2, "params": {"cwds": [str(cwd)], "forceReload": True}})
            result = receive(2)
            if not isinstance(result, dict) or not isinstance(result.get("data"), list):
                raise Problem("Codex skills/list schema unrecognized", "BLOCKED")
            entries = [entry for entry in result["data"] if isinstance(entry, dict) and entry.get("cwd") == str(cwd)]
            if len(entries) != 1 or entries[0].get("errors"):
                raise Problem("Codex discovery reports errors or ambiguous roots", "BLOCKED")
            if not isinstance(entries[0].get("skills"), list):
                raise Problem("Codex skill list missing", "BLOCKED")
            matches = [s for s in entries[0]["skills"] if isinstance(s, dict) and s.get("name") == name and s.get("enabled") is True]
            if len(matches) != 1:
                raise Problem("Codex skill missing, disabled, or duplicated")
            listed_path = matches[0].get("path")
            if listed_path is not None and Path(listed_path).resolve() != Path(expected).resolve():
                raise Problem("Codex discovered a different skill copy")
            return {"status": "PASS", "method": "skills/list", "matches": 1}
        finally:
            if proc.stdin:
                proc.stdin.close()
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            reader.join(timeout=3)
            if proc.stdout:
                proc.stdout.close()


def parse_trace(target, stdout):
    """Keep only documented output, tool arguments, and terminal completion."""
    tools, texts, outputs = [], [], []
    terminal = False
    opaque = False
    initialized = False
    turn_started = False
    pending = set()
    events = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except ValueError as exc:
            raise Problem("Unstructured harness output; load cannot be observed", "BLOCKED") from exc
        if not isinstance(value, dict):
            raise Problem("Invalid harness event", "BLOCKED")
        events.append(value)
    if not events:
        raise Problem("Empty harness trace", "BLOCKED")
    for value in events:
        kind = value.get("type")
        if terminal and kind in ("assistant", "tool_call", "item.started", "item.completed", "result", "turn.completed"):
            raise Problem("Events after terminal completion", "BLOCKED")
        if target == "codex":
            if kind == "thread.started":
                initialized = True
            if kind == "turn.started":
                turn_started = True
            if kind == "item.started" and value.get("item", {}).get("type") == "command_execution":
                pending.add(str(value["item"].get("id", "unknown")))
            if kind in ("error", "turn.failed"):
                raise Problem("Harness reported failed turn", "BLOCKED")
            if kind == "turn.completed":
                terminal = True
            elif kind == "item.completed":
                item = value.get("item", {})
                itype = item.get("type")
                if itype == "agent_message":
                    texts.append(str(item.get("text", "")))
                elif itype == "command_execution":
                    pending.discard(str(item.get("id", "unknown")))
                    tools.append({"name": "Bash", "args": {"command": str(item.get("command", ""))}})
                    outputs.append(str(item.get("aggregated_output", "")))
                elif itype not in ("reasoning", "plan_update"):
                    opaque = True
            elif kind not in ("thread.started", "turn.started", "item.started", "item.updated"):
                opaque = True
        else:
            if kind == "result":
                if value.get("is_error") is not False or value.get("subtype") != "success":
                    raise Problem("Harness reported failed result", "BLOCKED")
                terminal = True
                texts.append(str(value.get("result", "")))
            elif kind == "assistant":
                for block in value.get("message", {}).get("content", []):
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        pending.add(str(block.get("id", "unknown")))
                        tools.append({"name": block.get("name", ""), "args": block.get("input", {})})
            elif kind == "user":
                for block in value.get("message", {}).get("content", []):
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        pending.discard(str(block.get("tool_use_id", "unknown")))
                        outputs.append(str(block.get("content", "")))
            elif kind == "tool_call":
                if target != "cursor":
                    opaque = True
                    continue
                if value.get("subtype") == "started":
                    pending.add(str(value.get("call_id", "unknown")))
                    continue
                if value.get("subtype") != "completed":
                    opaque = True
                    continue
                pending.discard(str(value.get("call_id", "unknown")))
                call = value.get("tool_call", {})
                for key, tool in call.items():
                    if key == "readToolCall":
                        tools.append({"name": "Read", "args": tool.get("args", {})})
                        outputs.append(str(tool.get("result", {}).get("success", {}).get("content", "")))
                    elif key == "shellToolCall":
                        tools.append({"name": "Bash", "args": tool.get("args", {})})
                        outputs.append(str(tool.get("result", "")))
                    elif key == "function":
                        args = tool.get("arguments", {})
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except ValueError:
                                opaque = True
                                args = {}
                        tools.append({"name": tool.get("name", ""), "args": args})
                    else:
                        opaque = True
            elif kind in ("system", "rate_limit_event"):
                if kind == "system" and value.get("subtype") == "init":
                    initialized = True
                if value.get("subtype") in ("api_retry", "error"):
                    raise Problem("Harness retry/error observed; stop and inspect", "BLOCKED")
            elif kind == "thinking" and value.get("subtype") in ("delta", "completed"):
                # Cursor emits thinking events on some turns. They are not tools or answers.
                pass
            else:
                opaque = True
    if not terminal or not initialized or (target == "codex" and not turn_started):
        raise Problem("Harness trace lacks initialization or terminal completion", "BLOCKED")
    if pending:
        raise Problem("Tool actions missing completion events", "BLOCKED")
    for tool in tools:
        if tool["name"] not in ("Read", "read_file", "Skill", "Bash", "shell", "run_terminal_cmd"):
            opaque = True
        if not isinstance(tool["args"], dict):
            raise Problem("Tool arguments cannot be observed", "BLOCKED")
    return {"text": "\n".join(texts), "outputs": "\n".join(outputs), "tools": tools, "opaque": opaque}


def load_observed(trace, name, expected):
    expected = Path(expected)
    for tool in trace["tools"]:
        args = tool["args"]
        if tool["name"] == "Skill" and str(args.get("skill", "")).split(":")[-1] == name:
            return True
        if tool["name"] in ("Read", "read_file"):
            path = str(args.get("file_path", args.get("path", "")))
            if path:
                actual = Path(path)
                if not actual.is_absolute():
                    # Both supported project layouts are three levels below root.
                    actual = expected.parents[3] / actual
                if actual.resolve() == expected.resolve():
                    return True
        command = str(args.get("command", ""))
        if tool["name"] in ("Bash", "shell", "run_terminal_cmd"):
            full = expected.as_posix()
            rel = "/".join(expected.parts[-4:])
            if full in command or rel in command:
                return True
    return False
