"""Trust check: show what a skill can do before install, pin what was approved, detect drift.

Everything here is static pattern matching over files on disk. It never runs a skill and
never contacts a scanning service. It is NOT a malware verdict.
"""
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from zoneinfo import ZoneInfo

import yaml

from .core import Problem, _write_receipt, inventory, no_links

LOCK_NAME = "skill-anywhere.lock"
DISCLAIMER = ("Static pattern matching only. This is NOT a malware verdict: a clean report does not "
              "mean a skill is safe, and a flag does not mean it is malicious.")
CAPABILITY_FIELDS = ("allowed-tools", "allowed_tools", "tools", "permissions", "hooks", "mcp", "mcp-servers", "mcpServers")
MAX_SCAN_BYTES = 2_000_000

# category -> (why it matters, [(compiled pattern, applies to)]). Patterns are per line.
_SHELL = [
    r"\bos\.(?:system|popen|exec\w*|spawn\w*)\b", r"\bsubprocess\b", r"\bPopen\b", r"\bshell\s*=\s*True\b",
    r"\b(?:eval|exec)\b\s*[(\w$\"']", r"\b(?:ba|z|da)?sh\s+-c\b", r"\|\s*(?:ba|z)?sh\b", r"\bchild_process\b",
    r"\b(?:execSync|spawnSync)\b", r"\bsudo\b", r"\bxargs\b", r"\b__import__\b",
]
_NETWORK = [
    r"\b(?:curl|wget|ncat|scp|sftp|rsync|telnet)\b", r"(?<![\w.-])(?:nc|ssh)\s", r"\bhttps?://[^\s\"'<>)\]]+",
    r"\b(?:urllib|urlopen|httpx|aiohttp|http\.client|XMLHttpRequest|WebFetch)\b", r"\brequests\.(?:get|post|put|request|Session)\b",
    r"\bsocket\.", r"\bfetch\(",
]
_CREDENTIALS = [
    r"\bos\.(?:environ|getenv)\b", r"\bgetenv\(", r"\bprocess\.env\b", r"\$\{?(?!BASH_)[A-Z][A-Z0-9_]{2,}\b",
    r"\b(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?|PRIVATE[_ -]?KEY)\b", r"~/\.(?:ssh|aws|gnupg|netrc|config)\b",
    r"(?<![\w])\.env\b", r"\bid_(?:rsa|ed25519)\b", r"\bkeychain\b",
]
_WRITES = [
    r"\bopen\([^)]*['\"][wax]b?\+?['\"]", r"\.write_(?:text|bytes)\(", r"\bos\.(?:makedirs|mkdir|remove|unlink|rename|replace|rmdir)\b",
    r"\bshutil\.(?:copy\w*|move|rmtree)\b", r"\.mkdir\(", r"\bPath\([^)]*\)\.(?:unlink|rename|touch)\b",
    r"(?:^|[;&|\s])(?:mkdir|touch|cp|mv|rm|tee|ln|chmod|chown)\s[^#\n]*[\s=\"'](?:/|~|\.\./|\$)",
    r"(?<![\w<>=-])>>?\s*[\"']?(?!/dev/null)(?:/|~|\.\./|\$)",
]
CATEGORIES = {
    "shell": ("runs other programs or evaluates code; confirm the commands do what the skill says", _SHELL),
    "network": ("contacts or mentions network hosts; data could be fetched or sent", _NETWORK),
    "credentials/env": ("reads environment variables or credential-like names, which may hold secrets", _CREDENTIALS),
    "writes": ("writes or deletes files; the destination is often a runtime value, so it may be outside the skill directory", _WRITES),
}
_COMPILED = {name: [re.compile(p) for p in patterns] for name, (_, patterns) in CATEGORIES.items()}
_URL = re.compile(r"https?://([^/\s\"'<>):]+)")
_ENV = re.compile(r"\$\{?(?!BASH_)([A-Z][A-Z0-9_]{2,})|os\.environ(?:\.get)?\(?\[?['\"]([A-Za-z0-9_]+)|getenv\(['\"]([A-Za-z0-9_]+)|process\.env\.([A-Za-z0-9_]+)")


def _frontmatter(text):
    match = re.match(r"\A---\r?\n(.*?)\r?\n---(?:\r?\n|\Z)", text, re.S)
    if not match:
        return {}
    try:
        value = yaml.safe_load(match.group(1))
    except (yaml.YAMLError, RecursionError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _clip(text, limit=72):
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


_PROSE = {"network", "credentials/env"}  # in Markdown prose only these are meaningful; shell/write need code context
_CODE_SPAN = re.compile(r"`([^`]+)`")


def _scan(rel, text):
    """Yield (line number, line, (category, matched text)) for each pattern hit, skipping code comments."""
    markdown = rel.lower().endswith((".md", ".markdown", ".txt"))
    fenced = False
    for number, line in enumerate(text.splitlines(), 1):
        if markdown:
            if line.lstrip().startswith(("```", "~~~")):
                fenced = not fenced
                continue
            code = line if fenced else " ".join(_CODE_SPAN.findall(line))
        else:
            if line.lstrip().startswith(("#", "//")) and not line.startswith("#!"):
                continue  # a comment is documentation, not an action
            code = line
        for category, patterns in _COMPILED.items():
            haystack = line if (markdown and category in _PROSE) else code
            for pattern in patterns:
                hit = pattern.search(haystack)
                if hit:
                    yield number, line, (category, hit.group(0))
                    break


def _clip_around(text, needle, limit=72):
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    at = max(text.find(needle.strip()), 0)
    start = max(0, min(at - 12, len(text) - limit))
    piece = text[start:start + limit]
    return ("…" if start else "") + piece[1 if start else 0:] .rstrip() + ("…" if start + limit < len(text) else "")


def inspect(path):
    """Return a plain, JSON-serializable inventory of what a skill directory contains and can touch."""
    path = Path(path).absolute()
    files = inventory(path)
    entries, unscanned, findings = [], [], []
    for rel, info in files.items():
        raw = (path / rel).read_bytes()
        entries.append({"path": rel, "size": len(raw), "executable": info["executable"] or raw.startswith(b"#!")})
        if b"\0" in raw:
            unscanned.append({"path": rel, "reason": "binary file, not scanned"})
            continue
        if len(raw) > MAX_SCAN_BYTES:
            unscanned.append({"path": rel, "reason": "larger than 2 MB, not scanned"})
            continue
        for number, line, matched in _scan(rel, raw.decode("utf-8", "replace")):
            findings.append({"category": matched[0], "file": rel, "line": number, "text": _clip_around(line.strip(), matched[1])})
    meta = {}
    if "SKILL.md" in files:
        meta = _frontmatter((path / "SKILL.md").read_text(encoding="utf-8", errors="replace"))
    capabilities = []
    for field in CAPABILITY_FIELDS:
        if field in meta:
            value = meta[field]
            value = value if isinstance(value, str) else json.dumps(value, default=str)
            broad = field.replace("_", "-") == "allowed-tools" and bool(re.search(r"(?:^|[\s,])(?:Bash|Shell|\*)(?:$|[\s,])", value))
            capabilities.append({"field": field, "value": _clip(value, 120),
                                 "note": "grants shell or all tools without narrowing" if broad else "pre-approves tools for the agent"})
    hosts, env_vars = set(), set()
    for item in findings:
        if item["category"] == "network":
            hosts.update(_URL.findall(item["text"]))
    for rel in files:
        if (path / rel).stat().st_size <= MAX_SCAN_BYTES:
            text = (path / rel).read_bytes().decode("utf-8", "replace")
            for match in _ENV.finditer(text):
                env_vars.add(next(g for g in match.groups() if g))
            hosts.update(_URL.findall(text))
    return {"name": meta.get("name") if isinstance(meta.get("name"), str) else path.name,
            "files": entries, "total_bytes": sum(e["size"] for e in entries),
            "scripts": [e["path"] for e in entries if e["path"].startswith("scripts/")],
            "executables": [e["path"] for e in entries if e["executable"]],
            "capabilities": capabilities, "findings": findings,
            "network_hosts": sorted(hosts), "env_vars": sorted(env_vars), "unscanned": unscanned,
            "disclaimer": DISCLAIMER}


def _size(n):
    return "%d B" % n if n < 1024 else "%.1f KB" % (n / 1024)


def render(report, origin=None, examples=3):
    """Human report meant to fit on one screen; `--json` has everything."""
    lines = ["Skill: %s%s" % (report["name"], " (%s)" % origin["source"] if origin else ""), report["disclaimer"], ""]
    files = report["files"]
    lines.append("Files: %d, %s total" % (len(files), _size(report["total_bytes"])))
    shown = ", ".join("%s %s" % (e["path"], _size(e["size"])) for e in files[:6])
    lines.append("  " + shown + (" (+%d more)" % (len(files) - 6) if len(files) > 6 else ""))
    lines.append("Scripts (scripts/): " + (", ".join(report["scripts"]) or "none"))
    lines.append("Executable files: " + (", ".join(report["executables"]) or "none"))
    if report["capabilities"]:
        for cap in report["capabilities"]:
            lines.append("Capability frontmatter: %s: %s  <- %s" % (cap["field"], cap["value"], cap["note"]))
    else:
        lines.append("Capability frontmatter (allowed-tools etc.): none")
    for item in report["unscanned"]:
        lines.append("Not scanned: %s (%s)" % (item["path"], item["reason"]))
    flagged = False
    for category, (why, _) in CATEGORIES.items():
        items = [f for f in report["findings"] if f["category"] == category]
        if not items:
            continue
        if not flagged:
            lines += ["", "Flags (line patterns, not verdicts):"]
            flagged = True
        extra = ""
        if category == "network" and report["network_hosts"]:
            extra = " Hosts: " + ", ".join(report["network_hosts"][:5])
        if category == "credentials/env" and report["env_vars"]:
            extra = " Env: " + ", ".join(report["env_vars"][:6])
        lines.append("  %s (%d): %s.%s" % (category, len(items), why, extra))
        for item in items[:examples]:
            lines.append("    %s:%d  %s" % (item["file"], item["line"], item["text"]))
        if len(items) > examples:
            lines.append("    (+%d more; use --json for all)" % (len(items) - examples))
    if not flagged:
        lines += ["", "Flags: no shell, network, credential/env, or file-write patterns matched."]
    return "\n".join(lines)


def tree_hash(files):
    digest = hashlib.sha256()
    for rel, info in sorted(files.items()):
        digest.update(("%s\0%s\0%d\n" % (rel, info["sha256"], int(info["executable"]))).encode())
    return digest.hexdigest()


# ---- sources: a local directory or a git URL -------------------------------------------------

_GIT_URL = re.compile(r"(?:https://|ssh://|file://|git@[\w.-]+:)")
_SAFE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@-]*")


def is_git_url(spec):
    return bool(_GIT_URL.match(str(spec))) and not Path(str(spec)).exists()


def _git(args, cwd=None, timeout=180):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ALLOW_PROTOCOL="https:ssh:file", GIT_CONFIG_NOSYSTEM="1")
    try:
        proc = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never", *args],
                              cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Problem("git could not be run for this source", "BLOCKED") from exc
    if proc.returncode != 0:
        raise Problem("git failed: " + _clip(proc.stderr.strip() or "unknown error", 120), "BLOCKED")
    return proc.stdout.strip()


@contextmanager
def resolve_source(spec, ref=None, subdir=None):
    """Yield (skill_directory, origin). Git sources are cloned without running hooks, then copied without .git."""
    spec = str(spec)
    if not is_git_url(spec):
        if ref or subdir:
            raise Problem("--ref and --subdir only apply to a git URL")
        path = Path(spec).absolute()
        no_links(path)
        origin = {"kind": "dir", "source": str(path), "ref": None, "subdir": None}
        try:
            if path.is_dir():
                origin["ref"] = _git(["rev-parse", "HEAD"], cwd=path) or None
        except Problem:
            pass
        yield path, origin
        return
    if ref is not None and not _SAFE_REF.fullmatch(ref):
        raise Problem("Invalid --ref")
    if subdir is not None:
        parts = Path(subdir).parts
        if Path(subdir).is_absolute() or ".." in parts or not parts:
            raise Problem("--subdir must be a relative path inside the repository")
    with tempfile.TemporaryDirectory(prefix="skill-anywhere-src-") as folder:
        repo = Path(folder) / "repo"
        if ref is None:
            _git(["clone", "--quiet", "--depth", "1", "--", spec, str(repo)])
        else:
            _git(["clone", "--quiet", "--", spec, str(repo)])
            _git(["checkout", "--quiet", "--detach", ref + "^{commit}"], cwd=repo)
        commit = _git(["rev-parse", "HEAD"], cwd=repo)
        src = repo / subdir if subdir else repo
        no_links(src)
        skill_md = src / "SKILL.md"
        if not src.is_dir() or not skill_md.is_file():
            raise Problem("No SKILL.md at the requested location in the repository (try --subdir)")
        name = _frontmatter(skill_md.read_text(encoding="utf-8", errors="replace")).get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or len(name) > 64:
            raise Problem("Skill name in the repository is missing or invalid")
        target = Path(folder) / "skill" / name
        shutil.copytree(src, target, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        yield target, {"kind": "git", "source": spec, "ref": commit, "subdir": subdir}


# ---- approval, lock, drift --------------------------------------------------------------------

def approve(yes, stdin, stderr, prompt_input=None):
    """True only on --yes or an interactive y/yes. Never approves silently."""
    if yes:
        return True
    if stdin.isatty():
        stderr.write("Approve installing this skill? [y/N] ")
        stderr.flush()
        return (prompt_input or input)("").strip().lower() in ("y", "yes")
    return False


def lock_path(root):
    return Path(root) / LOCK_NAME


def _read_lock(root):
    path = lock_path(root)
    no_links(path)
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Problem(LOCK_NAME + " is unreadable; fix or remove it, then re-run install") from exc
    if not isinstance(value, dict) or value.get("format") != 1 or not isinstance(value.get("skills"), dict):
        raise Problem(LOCK_NAME + " has an unknown format")
    return value


def write_lock(root, skill, origin, locations):
    """Record the approved source, ref, and content hash of the whole skill directory."""
    lock = _read_lock(root) or {"format": 1, "skills": {}}
    lock["skills"][skill["name"]] = {
        "source": origin["source"], "ref": origin["ref"], "subdir": origin.get("subdir"),
        "sha256": tree_hash(skill["files"]), "files": skill["files"], "locations": list(locations),
        "approved_at": datetime.now(ZoneInfo("America/Chicago")).isoformat(),
    }
    _write_receipt(lock_path(root), lock)
    return lock["skills"][skill["name"]]


def _diff(locked, current):
    changed = sorted(p for p in locked if p in current and locked[p] != current[p])
    return changed, sorted(set(locked) - set(current)), sorted(set(current) - set(locked))


def check_drift(root, name, requested_locations):
    """None when there is no lock entry; "PASS" when every locked location still matches; else raises Problem naming files."""
    lock = _read_lock(root)
    entry = (lock or {}).get("skills", {}).get(name)
    if entry is None:
        return None
    files = entry.get("files")
    if not isinstance(files, dict) or tree_hash(files) != entry.get("sha256"):
        raise Problem(LOCK_NAME + " entry for " + name + " does not match its own hash; re-run install to re-approve")
    checked = False
    for location in requested_locations:
        if location not in entry.get("locations", []):
            continue
        checked = True
        changed, missing, added = _diff(files, inventory(Path(root) / location))
        if changed or missing or added:
            parts = []
            for label, names in (("changed", changed), ("missing", missing), ("added", added)):
                if names:
                    parts.append("%s: %s%s" % (label, ", ".join(names[:10]), " (+%d more)" % (len(names) - 10) if len(names) > 10 else ""))
            raise Problem("Installed copy %s drifted from %s (approved %s); %s. Re-run install to re-approve."
                          % (location, LOCK_NAME, str(entry["sha256"])[:12], "; ".join(parts)))
    return "PASS" if checked else None
