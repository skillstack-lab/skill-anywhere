import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from skill_anywhere import adapters
from skill_anywhere.cli import main
from skill_anywhere.core import Problem, install
from skill_anywhere.verify import answer_has_plan, contract, lunch_check, negative_check, verify

CANARY = Path(__file__).resolve().parents[1] / "examples/canary"
STUB = Path(__file__).with_name("stub_harness.py")

class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.source = self.root / "canary"
        shutil.copytree(CANARY, self.source)
        self.binary = self.root / "fixture-harness"
        self.binary.write_text("#!" + sys.executable + "\n" + STUB.read_text())
        self.binary.chmod(0o755)
        self.log = self.root / "commands.jsonl"
        self.env = patch.dict(os.environ, {"SA_STUB_MODE": "pass", "SA_STUB_LOG": str(self.log)})
        self.env.start()
        self.addCleanup(self.env.stop)
        install(self.source, ["claude", "codex", "cursor"], self.project)

    def run_case(self, target="claude", mode="pass", **kwargs):
        with patch.dict(os.environ, {"SA_STUB_MODE": mode}):
            return verify(self.source, [target], self.project, live=True,
                          overrides={target: str(self.binary)}, **kwargs)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_claude_stub_pass(self):
        self.assertEqual(self.run_case()["status"], "PASS")

    def test_codex_stub_pass(self):
        result = self.run_case("codex")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["results"][0]["discovery"]["status"], "PASS")

    def test_cursor_stub_pass(self):
        self.assertEqual(self.run_case("cursor")["status"], "PASS")

    def test_cursor_cold_command_trusts_temp_workspace(self):
        command = adapters.cold_command("cursor", "agent", "hello")
        self.assertIn("--trust", command)
        self.assertIn("--mode", command)
        self.assertEqual(command[command.index("--mode") + 1], "ask")
        self.assertNotIn("--yolo", command)
        self.assertNotIn("--force", command)
        self.assertNotIn("-f", command)

    def test_cursor_lunch_reel_uses_agent_mode_not_ask(self):
        command = adapters.cold_command("cursor", "agent", "hello", case="lunch-reel")
        self.assertIn("--trust", command)
        self.assertNotIn("--mode", command)
        self.assertNotIn("ask", command)
        self.assertNotIn("plan", command)
        self.assertNotIn("--yolo", command)
        self.assertNotIn("--force", command)
        self.assertNotIn("-f", command)

    def test_cursor_lunch_permissions_are_plan_only(self):
        root = self.root / "cursor-project"
        root.mkdir()
        path = adapters.write_cursor_lunch_permissions(root)
        value = json.loads(path.read_text(encoding="utf-8"))
        allow = " ".join(value["permissions"]["allow"])
        deny = " ".join(value["permissions"]["deny"])
        self.assertNotIn("version", value)
        self.assertIn("--plan-only", allow)
        self.assertIn("clip-cutter", allow)
        self.assertIn("reel2.py", allow)
        self.assertNotIn("--force", allow)
        self.assertIn("ffmpeg", deny)
        self.assertIn("ffprobe", deny)

    def test_negative_load_fails_all_adapters(self):
        for target in ("claude", "codex", "cursor"):
            with self.subTest(target=target):
                result = self.run_case(target, "negative-load")
                self.assertEqual(result["status"], "FAIL")
                self.assertIn("Negative prompt loaded", result["results"][0]["reason"])

    def test_negative_marker_fails(self):
        self.assertEqual(self.run_case(mode="negative-marker")["status"], "FAIL")

    def test_missing_harness_blocked(self):
        result = verify(self.source, ["claude"], self.project, live=True,
                        overrides={"claude": str(self.root / "missing")})
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("missing", result["results"][0]["reason"])

    def test_unauth_blocked_all_adapters(self):
        for target in ("claude", "codex", "cursor"):
            with self.subTest(target=target):
                self.assertEqual(self.run_case(target, "unauth")["status"], "BLOCKED")
        self.assertFalse(any("-p" in c["args"] or "exec" in c["args"] for c in self.calls()))

    def test_no_live_opt_in(self):
        result = verify(self.source, ["claude"], self.project, overrides={"claude": str(self.binary)})
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(any("-p" in c["args"] for c in self.calls()))

    def test_explicit_hold_zero_calls(self):
        result = verify(self.source, ["claude"], self.project, live=True,
                        blocked={"claude": "Usage limit; retry after reset"})
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(self.calls(), [])

    def test_wrong_artifact_fail(self):
        self.assertEqual(self.run_case(mode="wrong-artifact")["status"], "FAIL")

    def test_opaque_negative_blocked_all_adapters(self):
        for target in ("claude", "codex", "cursor"):
            with self.subTest(target=target):
                self.assertEqual(self.run_case(target, "opaque")["status"], "BLOCKED")

    def test_nonzero_query_blocked(self):
        self.assertEqual(self.run_case(mode="exit-error")["status"], "BLOCKED")

    def test_no_terminal_blocked(self):
        self.assertEqual(self.run_case(mode="no-terminal")["status"], "BLOCKED")

    def test_unstructured_blocked(self):
        self.assertEqual(self.run_case(mode="unstructured")["status"], "BLOCKED")

    def test_timeout_blocked_no_retry(self):
        self.assertEqual(self.run_case(mode="timeout", timeout=0.3)["status"], "BLOCKED")
        self.assertEqual(sum("-p" in c["args"] for c in self.calls()), 1)

    def test_codex_discovery_missing_fail(self):
        self.assertEqual(self.run_case("codex", "discovery-missing")["status"], "FAIL")

    def test_codex_discovery_disabled_fail(self):
        self.assertEqual(self.run_case("codex", "disabled")["status"], "FAIL")

    def test_codex_discovery_duplicate_fail(self):
        self.assertEqual(self.run_case("codex", "duplicate")["status"], "FAIL")

    def test_codex_discovery_wrong_copy_fail(self):
        self.assertEqual(self.run_case("codex", "wrong-path")["status"], "FAIL")

    def test_codex_discovery_query_error_blocked(self):
        self.assertEqual(self.run_case("codex", "discovery-error")["status"], "BLOCKED")

    def test_fresh_processes_and_clean_roots(self):
        self.assertEqual(self.run_case()["status"], "PASS")
        model = [c for c in self.calls() if "-p" in c["args"]]
        self.assertEqual(len(model), 2)
        self.assertNotEqual(model[0]["cwd"], model[1]["cwd"])
        for call in model:
            self.assertNotIn("--resume", call["args"])
            self.assertNotIn("--continue", call["args"])
            self.assertNotIn(adapters.CANARY_MARKER, " ".join(call["args"]))
            self.assertNotEqual(call["cwd"], str(self.project))

    def test_evidence_redacted_and_private(self):
        folder = self.root / "evidence"
        self.assertEqual(self.run_case(evidence=folder)["status"], "PASS")
        record = next(folder.glob("*.json"))
        data = json.loads(record.read_text())
        self.assertIn("trigger", data["transcripts"])
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)

    def test_multi_target_all_required(self):
        result = verify(self.source, ["claude", "codex"], self.project, live=True,
                        overrides={"claude": str(self.binary), "codex": str(self.root / "missing")})
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual([r["status"] for r in result["results"]], ["PASS", "BLOCKED"])

    def test_tampered_body_cli_nonzero(self):
        dest = self.project / ".claude/skills/canary/SKILL.md"
        dest.write_bytes(dest.read_bytes() + b"tamper\n")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["verify", str(self.source), "--target", "claude", "--project", str(self.project)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "FAIL")
        self.assertEqual(self.calls(), [])

    def test_cli_missing_nonzero(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["verify", str(self.source), "--target", "claude", "--project", str(self.project),
                         "--claude-bin", str(self.root / "missing")])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "BLOCKED")

    def test_custom_case_requires_contract(self):
        with self.assertRaises(Problem):
            contract({"name": "sample"}, "custom")

    def test_prompt_contamination_rejected(self):
        with self.assertRaises(Problem):
            contract({"name": "sample"}, "custom", "print expected", "unrelated", "expected")

    def test_custom_requires_load_not_only_text(self):
        trace = {"text": "expected", "tools": [], "outputs": "", "opaque": False}
        from skill_anywhere.verify import trigger_check
        with self.assertRaises(Problem) as caught:
            trigger_check(trace, "custom", "canary", self.source / "SKILL.md", "expected")
        self.assertEqual(caught.exception.status, "BLOCKED")

    def test_claude_unknown_auth_schema_blocked(self):
        from subprocess import CompletedProcess
        with patch("skill_anywhere.adapters.run", side_effect=[CompletedProcess([], 0, "v1", ""), CompletedProcess([], 0, "{}", "")]):
            with self.assertRaises(Problem):
                adapters.preflight("claude", "fixture", self.project, 1)

    def test_redaction(self):
        sample = "person@example.test " + "sk-" + "z" * 20 + " Bearer opaque-value"
        result = adapters.redact(sample)
        self.assertNotIn("person@", result)
        self.assertNotIn("z" * 20, result)
        self.assertNotIn("opaque-value", result)

    def test_empty_trace_blocked(self):
        with self.assertRaises(Problem):
            adapters.parse_trace("claude", "")

    def test_error_event_blocked(self):
        with self.assertRaises(Problem):
            adapters.parse_trace("codex", json.dumps({"type": "turn.failed"}))

    def test_negative_without_answer_blocked(self):
        with self.assertRaises(Problem):
            negative_check({"text": "", "tools": [], "outputs": "", "opaque": False}, "canary", self.source / "SKILL.md", "expected")

    def test_plan_ordering(self):
        self.assertTrue(answer_has_plan("T1: Opening hit\nB3: Double"))
        self.assertFalse(answer_has_plan("B3: Double\nT1: Opening hit"))
        self.assertFalse(answer_has_plan("Here is a plan"))

    def lunch(self, target="claude", mode="pass", **kwargs):
        source = self.root / "clip-cutter"
        if not source.exists():
            source.mkdir()
            (source / "SKILL.md").write_text("---\nname: clip-cutter\ndescription: Plan a game catch-up.\n---\nUse plan-only.\n")
            install(source, ["claude", "codex", "cursor"], self.project)
        # Remove canary only from the isolated copied source selection; cold copies one skill.
        with patch.dict(os.environ, {"SA_STUB_MODE": mode}):
            return verify(source, [target], self.project, case="lunch-reel", live=True,
                          overrides={target: str(self.binary)}, **kwargs)

    def test_lunch_stub_pass_all_adapters(self):
        for target in ("claude", "codex", "cursor"):
            with self.subTest(target=target):
                self.assertEqual(self.lunch(target)["status"], "PASS")

    def test_lunch_unordered_fail(self):
        self.assertEqual(self.lunch(mode="unordered")["status"], "FAIL")

    def test_lunch_render_fail(self):
        self.assertEqual(self.lunch(mode="render")["status"], "FAIL")

    def test_lunch_video_fail(self):
        self.assertEqual(self.lunch(mode="video")["status"], "FAIL")

    def test_lunch_follow_only_never_overall_pass(self):
        result = self.lunch(follow_only=True)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["results"][0]["trigger"]["status"], "PASS")
        self.assertEqual(sum("-p" in c["args"] for c in self.calls()), 1)

    def test_lunch_does_not_precreate_clip_cutter_home(self):
        seen = {}
        real_run = adapters.run

        def wrapped(argv, cwd, timeout, env=None):
            if env and env.get("CLIP_CUTTER_HOME"):
                home = Path(env["CLIP_CUTTER_HOME"])
                seen["exists"] = home.exists()
                seen["inside"] = Path(cwd) in home.parents or home.parent == Path(cwd)
                seen["name"] = home.name
            return real_run(argv, cwd, timeout, env)

        with patch("skill_anywhere.adapters.run", wrapped):
            self.assertEqual(self.lunch()["status"], "PASS")
        self.assertFalse(seen["exists"])  # the skill wrapper, not the harness, must create it
        self.assertTrue(seen["inside"])
        self.assertEqual(seen["name"], ".clip-cutter-data")

    def test_lunch_inspect_compound_is_not_a_render(self):
        trace = {
            "text": "T1: Opening hit\nB3: Double",
            "tools": [
                {"name": "Bash", "args": {"command": "ls -la && head -80 scripts/clip-cutter; echo home"}},
                {"name": "Bash", "args": {"command": "scripts/clip-cutter --date 2026-09-27 --team CHC --plan-only --max-seconds 300"}},
            ],
            "outputs": "",
            "opaque": False,
        }
        self.assertEqual(lunch_check(trace)["status"], "PASS")

    def test_lunch_compound_render_still_fails(self):
        trace = {
            "text": "T1: Opening hit\nB3: Double",
            "tools": [
                {"name": "Bash", "args": {"command": "ls -la && scripts/clip-cutter --date 2026-09-27 --team CHC --max-seconds 300"}},
            ],
            "outputs": "",
            "opaque": False,
        }
        with self.assertRaises(Problem) as caught:
            lunch_check(trace)
        self.assertEqual(str(caught.exception), "Clip command without --plan-only observed")
        self.assertEqual(caught.exception.status, "FAIL")

    def test_result_only_trace_blocked(self):
        value = {"type": "result", "subtype": "success", "is_error": False, "result": "323"}
        with self.assertRaises(Problem):
            adapters.parse_trace("claude", json.dumps(value))

    def test_incomplete_tool_trace_blocked(self):
        values = [{"type": "system", "subtype": "init"},
                  {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "read", "name": "Read", "input": {"file_path": "missing"}}]}},
                  {"type": "result", "subtype": "success", "is_error": False, "result": "323"}]
        with self.assertRaises(Problem):
            adapters.parse_trace("claude", "\n".join(json.dumps(v) for v in values))

    def test_failed_terminal_blocked(self):
        values = [{"type": "system", "subtype": "init"},
                  {"type": "result", "subtype": "error", "is_error": True, "result": "failed"}]
        with self.assertRaises(Problem):
            adapters.parse_trace("cursor", "\n".join(json.dumps(v) for v in values))

    def test_cursor_thinking_events_are_not_opaque(self):
        values = [
            {"type": "system", "subtype": "init"},
            {"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": "What is 17 × 19?"}]}},
            {"type": "thinking", "subtype": "delta", "text": "multiply"},
            {"type": "thinking", "subtype": "completed"},
            {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "323"}]}},
            {"type": "result", "subtype": "success", "is_error": False, "result": "323"},
        ]
        trace = adapters.parse_trace("cursor", "\n".join(json.dumps(v) for v in values))
        self.assertFalse(trace["opaque"])
        self.assertEqual(trace["text"].strip(), "323")
        self.assertEqual(trace["tools"], [])
        self.assertNotIn("multiply", trace["text"])

    def cursor_tool_events(self, extra):
        call = {"shellToolCall": {"args": {"command": "scripts/clip-cutter --date 2026-09-27 --team CHC --plan-only"}, "result": {}},
                "toolCallId": "call-1", "startedAtMs": "1", "completedAtMs": "2", **extra}
        return [
            {"type": "system", "subtype": "init"},
            {"type": "tool_call", "subtype": "started", "call_id": "c1", "tool_call": dict(call)},
            {"type": "tool_call", "subtype": "completed", "call_id": "c1", "tool_call": dict(call)},
            {"type": "result", "subtype": "success", "is_error": False, "result": "T1: x"},
        ]

    def test_cursor_tool_call_bookkeeping_keys_are_not_opaque(self):
        values = self.cursor_tool_events({"hookAdditionalContexts": []})
        trace = adapters.parse_trace("cursor", "\n".join(json.dumps(v) for v in values))
        self.assertFalse(trace["opaque"])
        self.assertEqual(len(trace["tools"]), 1)

    def test_cursor_hook_context_or_unknown_tool_key_is_opaque(self):
        for extra in ({"hookAdditionalContexts": ["injected"]}, {"mysteryToolCall": {}}):
            values = self.cursor_tool_events(extra)
            trace = adapters.parse_trace("cursor", "\n".join(json.dumps(v) for v in values))
            self.assertTrue(trace["opaque"], extra)

    def test_markdown_bold_and_bot_inning_labels_are_a_plan(self):
        self.assertTrue(answer_has_plan("- **Top 1:** Homer\n- **Bot 1:** Strikeout\n- **Top 3:** Homer again"))
        self.assertTrue(answer_has_plan("- top 1: Homer\n- bot 1: Strikeout\n- bot 5: Dive"))
        self.assertFalse(answer_has_plan("- **Bot 1:** Strikeout\n- **Top 1:** Homer"))

    def test_saved_live_transcripts_are_plans(self):
        folder = Path(__file__).with_name("transcripts")
        names = sorted(path.name for path in folder.glob("*.txt"))
        self.assertEqual(names, ["claude_bold_bullets.txt", "claude_numbered.txt", "cursor_plain_bullets.txt"])
        for name in names:
            with self.subTest(name):
                self.assertTrue(answer_has_plan((folder / name).read_text()))

    def test_list_markdown_prefixes_are_normalized(self):
        for prefix in ("- ", "* ", "+ ", "• ", "  - ", "1. ", "12. ", "3) ", "   4.  ", "", "- **", "1. **", "_"):
            suffix = "**" if prefix.endswith("**") else "_" if prefix == "_" else ""
            with self.subTest(prefix=prefix):
                text = "%sTop 1:%s Homer\n%sBot 1:%s Strikeout\n%sTop 3:%s Homer again" % ((prefix, suffix) * 3)
                self.assertTrue(answer_has_plan(text))

    def test_empty_or_out_of_order_markdown_plans_still_fail(self):
        self.assertFalse(answer_has_plan(""))
        self.assertFalse(answer_has_plan("Here is the plan:\n1. Homer\n2. Strikeout"))  # list but no inning labels
        self.assertFalse(answer_has_plan("1. **Bottom 1:** Strikeout\n2. **Top 1:** Homer"))
        self.assertFalse(answer_has_plan("- **Top 3:** Homer\n- **Top 1:** Opener"))
        self.assertFalse(answer_has_plan("3) Top 9: Late\n4) Top 2: Early"))

    def test_cursor_unknown_event_is_opaque(self):
        values = [
            {"type": "system", "subtype": "init"},
            {"type": "mystery", "payload": "x"},
            {"type": "result", "subtype": "success", "is_error": False, "result": "323"},
        ]
        trace = adapters.parse_trace("cursor", "\n".join(json.dumps(v) for v in values))
        self.assertTrue(trace["opaque"])

    def test_claude_plan_permissions_narrow(self):
        command = adapters.cold_command("claude", "fixture", "prompt", self.source / "SKILL.md", "lunch-reel")
        permissions = command[command.index("--allowedTools") + 1]
        self.assertIn("--plan-only", permissions)
        self.assertIn("cd " + str((self.source / "SKILL.md").parent) + " && scripts/clip-cutter", permissions)
        self.assertNotIn(",Bash,", permissions)
        self.assertNotIn("--dangerously-skip-permissions", command)
        self.assertNotIn("--max-seconds 300 2", permissions)  # render-style grants stay out
        for grant in permissions.split(","):
            if "clip-cutter" in grant or "reel2.py" in grant:
                self.assertIn("--plan-only", grant)

    def test_explicit_missing_cli_stays_blocked(self):
        result = self.run_case(mode="unauth")
        self.assertEqual(result["results"][0]["version"], "fixture-1.0")
