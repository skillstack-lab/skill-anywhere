"""Small JSON-reporting command line interface."""
import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .core import Problem, TARGET_PATHS, install, root_for, targets, validate
from . import trust
from .verify import verify


def parser():
    result = argparse.ArgumentParser(prog="skill-anywhere")
    result.add_argument("--version", action="version", version=__version__)
    commands = result.add_subparsers(dest="command", required=True)
    check = commands.add_parser("validate", help="Validate a standard skill with skills-ref")
    check.add_argument("source", type=Path)
    inspect_cmd = commands.add_parser("check", help="Show what a skill can do (static patterns, not a malware verdict)")
    inspect_cmd.add_argument("source", help="Skill directory or git URL (https://, ssh://, git@host:path, file://)")
    inspect_cmd.add_argument("--ref", help="Git branch, tag, or commit (git URL only)")
    inspect_cmd.add_argument("--subdir", help="Skill directory inside the repository (git URL only)")
    inspect_cmd.add_argument("--json", action="store_true", help="Print the full report as JSON")
    for command in ("install", "verify"):
        sub = commands.add_parser(command)
        if command == "install":
            sub.add_argument("source", help="Skill directory or git URL; the check report is shown first")
            sub.add_argument("--ref", help="Git branch, tag, or commit (git URL only)")
            sub.add_argument("--subdir", help="Skill directory inside the repository (git URL only)")
            sub.add_argument("--yes", action="store_true", help="Approve the shown inventory and pin it in skill-anywhere.lock")
        else:
            sub.add_argument("source", type=Path)
        sub.add_argument("--target", required=True)
        sub.add_argument("--scope", choices=("project", "user"), default="project")
        sub.add_argument("--project", type=Path)
        if command == "verify":
            sub.add_argument("--case", choices=("canary", "lunch-reel", "custom"), default="canary")
            sub.add_argument("--live", action="store_true", help="Permit up to two billable cold calls per target; no retries")
            sub.add_argument("--timeout", type=float, default=120)
            sub.add_argument("--trigger")
            sub.add_argument("--negative")
            sub.add_argument("--expect-text")
            sub.add_argument("--evidence", type=Path)
            sub.add_argument("--follow-only", action="store_true", help="Lunch Reel one-call subtest; overall stays BLOCKED")
            sub.add_argument("--block-target", action="append", default=[], metavar="TARGET=REASON")
            for name in ("claude", "codex", "cursor"):
                sub.add_argument("--" + name + "-bin", help="Explicit harness executable (also useful for tests)")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "validate":
            skill = validate(args.source)
            report = {"status": "PASS", "action": "validate", "name": skill["name"],
                      "validator": "skills-ref 0.1.0 (official source)", "isolated_frontmatter": []}
        else:
            if args.command == "check":
                with trust.resolve_source(args.source, args.ref, args.subdir) as (path, origin):
                    found = trust.inspect(path)
                if args.json:
                    print(json.dumps({"status": "PASS", "action": "check", "origin": origin, **found}, indent=2))
                else:
                    print(trust.render(found, origin))
                return 0
            requested = targets(args.target)
            root = root_for(args.scope, args.project)
            if args.command == "install":
                with trust.resolve_source(args.source, args.ref, args.subdir) as (path, origin):
                    skill = validate(path)
                    print(trust.render(trust.inspect(path), origin), file=sys.stderr)
                    if not trust.approve(args.yes, sys.stdin, sys.stderr):
                        raise Problem("Approval required: review the inventory above, then re-run install with --yes", "BLOCKED")
                    report = install(path, requested, root)
                    try:
                        entry = trust.write_lock(root, skill, origin, report["locations"])
                    except OSError as exc:
                        raise Problem("Installed, but skill-anywhere.lock could not be written", "BLOCKED") from exc
                    report["lock"] = {"file": trust.LOCK_NAME, "source": entry["source"], "ref": entry["ref"],
                                      "sha256": entry["sha256"]}
            else:
                if not 0 < args.timeout <= 1800:
                    raise Problem("--timeout must be between 0 and 1800 seconds")
                blocked = {}
                for value in args.block_target:
                    target, sep, reason = value.partition("=")
                    if not sep or not reason or target not in requested:
                        raise Problem("--block-target needs a requested TARGET=REASON")
                    blocked[target] = reason
                report = verify(args.source, requested, root, args.scope, args.case, args.live,
                                {name: getattr(args, name + "_bin") for name in ("claude", "codex", "cursor")},
                                args.timeout, args.trigger, args.negative, args.expect_text,
                                args.evidence, blocked, args.follow_only)
    except Problem as exc:
        report = {"status": exc.status, "reason": str(exc)}
    except (OSError, ValueError, TypeError, RecursionError):
        report = {"status": "BLOCKED", "reason": "Filesystem or validation query could not be completed"}
    print(json.dumps(report, indent=2))
    return {"PASS": 0, "FAIL": 1, "BLOCKED": 2}[report["status"]]


if __name__ == "__main__":
    sys.exit(main())
