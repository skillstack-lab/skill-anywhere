import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from skill_anywhere.core import Problem, install, inventory, root_for, static_verify, targets, validate

CANARY = Path(__file__).resolve().parents[1] / "examples" / "canary"

class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "canary"
        self.source.mkdir()
        (self.source / "SKILL.md").write_bytes((CANARY / "SKILL.md").read_bytes())
        self.project = self.root / "project"
        self.project.mkdir()

    def rewrite(self, text):
        (self.source / "SKILL.md").write_text(text)

    def test_official_validator(self):
        self.assertEqual(validate(self.source)["name"], "canary")

    def test_target_dedup(self):
        self.assertEqual(targets("claude,codex,claude"), ["claude", "codex"])

    def test_bad_targets(self):
        for value in ("", "unknown", "claude,", "cursor, codex"):
            with self.subTest(value=value), self.assertRaises(Problem):
                targets(value)

    def test_missing_skill(self):
        (self.source / "SKILL.md").unlink()
        with self.assertRaises(Problem):
            validate(self.source)

    def test_bad_frontmatter(self):
        for text in ("# hello", "---\nname: canary\n", "---\n[]\n---\n", "---\nname: [\n---\n"):
            with self.subTest(text=text), self.assertRaises(Problem):
                self.rewrite(text)
                validate(self.source)

    def test_duplicate_keys(self):
        self.rewrite("---\nname: canary\nname: canary\ndescription: hello\n---\n")
        with self.assertRaisesRegex(Problem, "unique"):
            validate(self.source)

    def test_name_constraints(self):
        for name in ("Canary", "-canary", "canary-", "ca--nary", "wrong", "a" * 65, "../canary"):
            with self.subTest(name=name), self.assertRaises(Problem):
                self.rewrite("---\nname: " + name + "\ndescription: hello\n---\n")
                validate(self.source)

    def test_description_constraints(self):
        for value in ('""', "true", "42", '"' + "a" * 1025 + '"'):
            with self.subTest(value=value), self.assertRaises(Problem):
                self.rewrite("---\nname: canary\ndescription: " + value + "\n---\n")
                validate(self.source)

    def test_optional_constraints(self):
        for extra in ("compatibility: ''", "compatibility: " + "a" * 501, "metadata: {version: 1}", "allowed-tools: [Read]", "license: false"):
            with self.subTest(extra=extra), self.assertRaises(Problem):
                self.rewrite("---\nname: canary\ndescription: hello\n" + extra + "\n---\n")
                validate(self.source)

    def test_optional_valid(self):
        self.rewrite('---\nname: canary\ndescription: hello\nmetadata:\n  version: "1"\ncompatibility: Python\nlicense: MIT\nallowed-tools: Read\n---\nbody\n')
        self.assertEqual(validate(self.source)["body"], b"body\n")

    def test_unknown_frontmatter_reported(self):
        self.rewrite("---\nname: canary\ndescription: hello\nmodel: inherit\n---\nbody\n")
        with self.assertRaisesRegex(Problem, "overlay: model"):
            validate(self.source)

    def test_crlf_body_exact(self):
        self.rewrite("---\nname: canary\ndescription: hello\n---\nBODY\n")
        data = (self.source / "SKILL.md").read_bytes().replace(b"\n", b"\r\n")
        (self.source / "SKILL.md").write_bytes(data)
        install(self.source, ["claude"], self.project)
        self.assertEqual((self.project / ".claude/skills/canary/SKILL.md").read_bytes(), data)

    def test_install_shared_and_claude(self):
        result = install(self.source, ["claude", "codex", "cursor"], self.project)
        self.assertEqual(len(result["locations"]), 2)
        self.assertTrue(result["body_byte_identical"])
        static_verify(self.source, ["claude", "codex", "cursor"], self.project)

    def test_support_files_and_exec(self):
        script = self.source / "scripts" / "hello"
        script.parent.mkdir()
        script.write_text("#!/bin/sh\nprintf hello\n")
        script.chmod(0o755)
        install(self.source, ["codex"], self.project)
        self.assertTrue(inventory(self.project / ".agents/skills/canary")["scripts/hello"]["executable"])

    def test_identical_reinstall_is_unchanged(self):
        first = install(self.source, ["claude"], self.project)
        dest = self.project / ".claude/skills/canary"
        inode = dest.stat().st_ino
        result = install(self.source, ["claude"], self.project)
        self.assertEqual(first["action"], "install")
        self.assertEqual(result["action"], "unchanged")
        self.assertEqual(dest.stat().st_ino, inode)
        static_verify(self.source, ["claude"], self.project)

    def test_refuse_foreign_without_receipt(self):
        dest = self.project / ".claude/skills/canary"
        dest.mkdir(parents=True)
        (dest / "SKILL.md").write_bytes((self.source / "SKILL.md").read_bytes())
        with self.assertRaisesRegex(Problem, "Refusing"):
            install(self.source, ["claude"], self.project)

    def test_installs_are_real_copies_not_symlinks(self):
        result = install(self.source, ["claude", "codex", "cursor"], self.project)
        claude = self.project / ".claude/skills/canary"
        agents = self.project / ".agents/skills/canary"
        self.assertEqual(len(result["locations"]), 2)
        for path in (claude, agents):
            self.assertTrue(path.is_dir())
            self.assertFalse(path.is_symlink())
            for item in path.rglob("*"):
                self.assertFalse(item.is_symlink())
        self.assertNotEqual(claude.stat().st_ino, agents.stat().st_ino)
        self.assertEqual((claude / "SKILL.md").read_bytes(), (agents / "SKILL.md").read_bytes())

    def test_refresh_stale_copy_by_content_not_mtime(self):
        install(self.source, ["claude", "codex"], self.project)
        dest = self.project / ".claude/skills/canary/SKILL.md"
        shared = self.project / ".agents/skills/canary/SKILL.md"
        updated = (self.source / "SKILL.md").read_bytes() + b"updated\n"
        (self.source / "SKILL.md").write_bytes(updated)
        os.utime(dest, (1_900_000_000, 1_900_000_000))
        os.utime(shared, (1_900_000_000, 1_900_000_000))
        os.utime(self.source / "SKILL.md", (1, 1))
        result = install(self.source, ["claude", "codex"], self.project)
        self.assertEqual(result["action"], "refresh")
        self.assertEqual(dest.read_bytes(), updated)
        self.assertEqual(shared.read_bytes(), updated)
        self.assertFalse(dest.parent.is_symlink())
        self.assertFalse(shared.parent.is_symlink())
        static_verify(self.source, ["claude", "codex"], self.project)

    def test_refresh_replaces_symlink_with_real_copy(self):
        install(self.source, ["claude", "codex"], self.project)
        claude = self.project / ".claude/skills/canary"
        agents = self.project / ".agents/skills/canary"
        shutil.rmtree(claude)
        claude.symlink_to(agents)
        self.assertTrue(claude.is_symlink())
        with self.assertRaisesRegex(Problem, "symlink"):
            static_verify(self.source, ["claude"], self.project)
        result = install(self.source, ["claude", "codex"], self.project)
        self.assertEqual(result["action"], "refresh")
        self.assertFalse(claude.is_symlink())
        self.assertTrue(claude.is_dir())
        self.assertEqual(inventory(claude), inventory(self.source))
        self.assertNotEqual((claude / "SKILL.md").stat().st_ino, (agents / "SKILL.md").stat().st_ino)
        static_verify(self.source, ["claude", "codex"], self.project)

    def test_refresh_recreates_missing_dest(self):
        install(self.source, ["claude"], self.project)
        dest = self.project / ".claude/skills/canary"
        shutil.rmtree(dest)
        result = install(self.source, ["claude"], self.project)
        self.assertEqual(result["action"], "refresh")
        self.assertTrue((dest / "SKILL.md").exists())
        static_verify(self.source, ["claude"], self.project)

    def test_symlink_source_rejected(self):
        (self.source / "linked").symlink_to(self.source / "SKILL.md")
        with self.assertRaises(Problem):
            install(self.source, ["claude"], self.project)

    def test_symlink_parent_rejected(self):
        other = self.root / "other"
        other.mkdir()
        (self.project / ".agents").symlink_to(other)
        with self.assertRaises(Problem):
            install(self.source, ["codex"], self.project)
        self.assertEqual(list(other.iterdir()), [])

    def test_inside_source_rejected(self):
        with self.assertRaisesRegex(Problem, "inside source"):
            install(self.source, ["codex"], self.source)

    def test_stage_failure_no_published_files(self):
        with patch("skill_anywhere.core.shutil.copytree", side_effect=OSError("fixture")), self.assertRaises(OSError):
            install(self.source, ["claude", "codex"], self.project)
        self.assertFalse((self.project / ".claude/skills/canary").exists())
        self.assertFalse((self.project / ".skill-anywhere/receipts/canary.json").exists())

    def test_tampered_body_fail(self):
        install(self.source, ["claude"], self.project)
        dest = self.project / ".claude/skills/canary/SKILL.md"
        dest.write_bytes(dest.read_bytes() + b"changed\n")
        with self.assertRaisesRegex(Problem, "differ"):
            static_verify(self.source, ["claude"], self.project)

    def test_added_file_fail(self):
        install(self.source, ["claude"], self.project)
        (self.project / ".claude/skills/canary/extra").write_text("changed")
        with self.assertRaises(Problem):
            static_verify(self.source, ["claude"], self.project)

    def test_changed_source_fail(self):
        install(self.source, ["claude"], self.project)
        (self.source / "SKILL.md").write_bytes((self.source / "SKILL.md").read_bytes() + b"changed")
        with self.assertRaisesRegex(Problem, "Source"):
            static_verify(self.source, ["claude"], self.project)

    def test_missing_receipt_fail(self):
        with self.assertRaisesRegex(Problem, "receipt"):
            static_verify(self.source, ["claude"], self.project)

    def test_receipt_tamper_fail(self):
        install(self.source, ["claude"], self.project)
        p = self.project / ".skill-anywhere/receipts/canary.json"
        p.write_text("[]")
        with self.assertRaises(Problem):
            static_verify(self.source, ["claude"], self.project)

    def test_target_not_installed_fail(self):
        install(self.source, ["codex"], self.project)
        with self.assertRaisesRegex(Problem, "not installed"):
            static_verify(self.source, ["cursor"], self.project)

    def test_user_root(self):
        with patch("pathlib.Path.home", return_value=self.root):
            self.assertEqual(root_for("user"), self.root)
        with self.assertRaises(Problem):
            root_for("user", self.project)

    def test_checker_failure_blocked(self):
        with patch("skill_anywhere.core.reference_validate", side_effect=RuntimeError("fixture")):
            with self.assertRaises(Problem) as caught:
                validate(self.source)
        self.assertEqual(caught.exception.status, "BLOCKED")
