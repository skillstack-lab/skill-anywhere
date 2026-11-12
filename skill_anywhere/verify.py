"""Separate path integrity, discovery, cold follow, and non-trigger checks."""
from datetime import datetime
import json
import os
from pathlib import Path
import re
import tempfile
from zoneinfo import ZoneInfo

from . import adapters
from .core import DOCS, Problem, TARGET_PATHS, install, static_verify

MEDIA = {".mp4", ".m4v", ".mov", ".webm", ".mkv", ".m4s"}
TRIGGER = "Run the skill-anywhere canary."
NEGATIVE = "What is 17 × 19?"
LUNCH_PROMPT = "I missed the Cubs on Sept 27, give me the 5-minute version."


def stamp():
    return datetime.now(ZoneInfo("America/Chicago")).isoformat()


def contract(skill, case, trigger=None, negative=None, expected=None):
    if case == "canary":
        if skill["name"] != "canary" or adapters.CANARY_MARKER.encode() not in skill["body"]:
            raise Problem("Canary case requires the bundled canary skill")
        trigger, negative, expected = TRIGGER, NEGATIVE, adapters.CANARY_MARKER
    elif case == "lunch-reel":
        if skill["name"] != "clip-cutter":
            raise Problem("Lunch Reel case requires clip-cutter")
        trigger, negative = LUNCH_PROMPT, NEGATIVE
    elif not trigger or not negative or not expected:
        raise Problem("Custom case needs --trigger, --negative and --expect-text")
    if expected and (expected in trigger or expected in negative):
        raise Problem("Expected artifact must not appear in either prompt")
    return trigger, negative, expected


def negative_check(trace, name, expected_path, expected):
    if adapters.load_observed(trace, name, expected_path):
        raise Problem("Negative prompt loaded the skill")
    if expected and expected in trace["text"] + trace["outputs"]:
        raise Problem("Negative prompt emitted the expected artifact")
    if trace["opaque"]:
        raise Problem("Negative trace contains opaque actions; non-loading unproven", "BLOCKED")
    if not trace["text"].strip():
        raise Problem("Negative prompt returned no answer", "BLOCKED")
    return {"status": "PASS", "loaded": False, "artifact_emitted": False}


def inning_key(value):
    if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 30:
        return value * 2
    if isinstance(value, str):
        match = re.fullmatch(r"\s*(T|B|Top|Bottom)?\s*(\d{1,2})(?:st|nd|rd|th)?\s*", value, re.I)
        if match and 1 <= int(match[2]) <= 30:
            return int(match[2]) * 2 + (1 if (match[1] or "").lower() in ("b", "bottom") else 0)
    raise Problem("Plan has an unrecognized inning")


def json_objects(text):
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            value, _ = decoder.raw_decode(text[match.start():])
        except ValueError:
            continue
        if isinstance(value, dict):
            yield value


def ordered_clips(clips):
    if not isinstance(clips, list) or not clips:
        return False
    keys = []
    for clip in clips:
        if not isinstance(clip, dict) or not isinstance(clip.get("headline"), str) or not clip["headline"].strip():
            return False
        try:
            keys.append(inning_key(clip.get("inning")))
        except Problem:
            return False
    return keys == sorted(keys)


def answer_has_plan(text):
    for value in json_objects(text):
        if ordered_clips(value.get("clips")):
            return True
        if isinstance(value.get("games"), list) and value["games"] and all(
            isinstance(game, dict) and ordered_clips(game.get("clips")) for game in value["games"]
        ):
            return True
    items = []
    for line in text.splitlines():
        match = re.match(r"\s*(?:[-*]\s*)?(T\d{1,2}|B\d{1,2}|(?:Top|Bottom)\s+\d{1,2}|\d{1,2}(?:st|nd|rd|th)?)\s*[:—–-]\s*(\S.+)", line, re.I)
        if match:
            items.append(inning_key(match[1]))
    return bool(items) and items == sorted(items)


CUTTER_PATH = re.compile(r"(?:scripts/clip-cutter|scripts/reel2\.py)\b")
INSPECT_COMMAND = re.compile(r"\s*(?:cat|head|less|more|tail|wc|file|rg|grep|ls|stat)\b")


def clip_subcommands(command):
    """Return shell parts that invoke clip-cutter or reel2.py, not inspect-only mentions."""
    parts = re.split(r"\s*(?:&&|\|\||[;\n]|\|)\s*", command)
    return [part for part in parts if CUTTER_PATH.search(part) and not INSPECT_COMMAND.match(part)]


def lunch_check(trace):
    planned = False
    for tool in trace["tools"]:
        if tool["name"] not in ("Bash", "shell", "run_terminal_cmd"):
            continue
        command = str(tool["args"].get("command", ""))
        for part in clip_subcommands(command):
            if "--plan-only" in part and (
                "824705" in part or ("2026-09-27" in part and ("CHC" in part or "112" in part))
            ):
                planned = True
            # A render invocation is a failure even if no video remains at the end.
            if "--plan-only" not in part:
                raise Problem("Clip command without --plan-only observed")
    if not planned:
        raise Problem("No observed known-game plan-only command")
    if not answer_has_plan(trace["text"]):
        raise Problem("Answer lacks a non-empty, game-ordered inning/headline plan")
    if trace["opaque"]:
        raise Problem("Opaque actions prevent plan-only verification", "BLOCKED")
    return {"status": "PASS", "plan_only_command": True, "game_ordered_answer": True}


def trigger_check(trace, case, name, expected_path, expected):
    if case == "lunch-reel":
        return lunch_check(trace)
    if not expected or expected not in trace["text"]:
        raise Problem("Trigger did not emit the expected artifact")
    observed = adapters.load_observed(trace, name, expected_path)
    if case != "canary" and not observed:
        raise Problem("Expected text appeared but skill loading was not observed", "BLOCKED")
    # The bundled marker is deliberately never included in a model prompt.
    return {"status": "PASS", "load_evidence": "tool trace" if observed else "marker absent from prompt"}


def assert_no_media(root):
    if any(p.is_file() and p.suffix.lower() in MEDIA for p in Path(root).rglob("*")):
        raise Problem("Video artifact found; plan-only assertion failed")


def cold(target, binary, installed, scope, name, prompt, timeout, case):
    with tempfile.TemporaryDirectory(prefix="skill-anywhere-cold-") as folder:
        root = Path(folder)
        if scope == "project":
            install(installed, [target], root)
            expected_path = root / TARGET_PATHS[target] / name / "SKILL.md"
        else:
            expected_path = installed / "SKILL.md"
        discovery = adapters.discover(target, binary, root, name, expected_path, min(timeout, 20))
        if target == "cursor" and case == "lunch-reel":
            adapters.write_cursor_lunch_permissions(root)
        env = dict(os.environ)
        # Deliberately NOT created: the skill's wrapper must create its own data home on a cold start.
        env["CLIP_CUTTER_HOME"] = str(root / ".clip-cutter-data")
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        proc = adapters.run(adapters.cold_command(target, binary, prompt, expected_path, case), root, timeout, env)
        if proc.returncode != 0:
            raise Problem("Cold harness query failed; no retry attempted", "BLOCKED")
        trace = adapters.parse_trace(target, proc.stdout)
        assert_no_media(root)
        return trace, discovery, expected_path


def save_evidence(folder, target, case, value):
    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    filename = target + "-" + case + "-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".json"
    path = root / filename
    # No raw event stream, account details, environment, or opaque identifiers.
    with path.open("x", encoding="utf-8") as handle:
        path.chmod(0o600)
        handle.write(adapters.redact(json.dumps(value, indent=2)) + "\n")


def verify(source, requested, root, scope="project", case="canary", live=False,
           overrides=None, timeout=120, trigger=None, negative=None, expected=None,
           evidence=None, blocked=None, follow_only=False):
    skill = static_verify(source, requested, root)
    trigger, negative, expected = contract(skill, case, trigger, negative, expected)
    if follow_only and case != "lunch-reel":
        raise Problem("--follow-only is limited to the Lunch Reel subtest")
    results = []
    for target in requested:
        row = {"target": target, "time_ct": stamp(), "path": TARGET_PATHS[target] + "/" + skill["name"],
               "docs": DOCS[target], "static": "PASS", "version": "unavailable", "discovery": {"status": "BLOCKED"},
               "trigger": {"status": "BLOCKED"}, "negative": {"status": "BLOCKED"}}
        traces = {}
        try:
            if blocked and target in blocked:
                raise Problem(blocked[target], "BLOCKED")
            binary = adapters.resolve_binary(target, (overrides or {}).get(target))
            row["version"] = adapters.preflight(target, binary, root, min(timeout, 15))
            if not live:
                raise Problem("Cold verification requires explicit --live; path-only is not a pass", "BLOCKED")
            installed = root / TARGET_PATHS[target] / skill["name"]
            trace, discovery, expected_path = cold(target, binary, installed, scope, skill["name"], trigger, timeout, case)
            traces["trigger"] = {"prompt": trigger, "response": trace["text"], "tools": trace["tools"]}
            row["discovery"] = discovery
            row["trigger"] = trigger_check(trace, case, skill["name"], expected_path, expected)
            if follow_only:
                raise Problem("Cold follow passed; negative not run (--follow-only)", "BLOCKED")
            trace, discovery, expected_path = cold(target, binary, installed, scope, skill["name"], negative, timeout, case)
            traces["negative"] = {"prompt": negative, "response": trace["text"], "tools": trace["tools"]}
            row["negative"] = negative_check(trace, skill["name"], expected_path, expected)
            row["status"] = "PASS"
        except Problem as exc:
            row["status"], row["reason"] = exc.status, str(exc)
            if hasattr(exc, "version"):
                row["version"] = exc.version
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
            row["status"], row["reason"] = "BLOCKED", "Adapter or filesystem query could not be completed"
        if evidence:
            save_evidence(evidence, target, case, {"result": row, "transcripts": traces})
        results.append(row)
    status = "FAIL" if any(r["status"] == "FAIL" for r in results) else (
        "BLOCKED" if any(r["status"] == "BLOCKED" for r in results) else "PASS")
    return {"status": status, "case": case, "results": results}
