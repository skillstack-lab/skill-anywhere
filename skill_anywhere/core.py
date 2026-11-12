"""Strict source validation and non-destructive, byte-preserving installation."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

import yaml
from skills_ref import validate as reference_validate

FIELDS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
TARGET_PATHS = {"claude": ".claude/skills", "codex": ".agents/skills", "cursor": ".agents/skills"}
# Future adapters are layout sketches, not implemented verification targets.
SKETCHES = {
    "copilot": (".agents/skills", "https://docs.github.com/en/copilot/concepts/agents/about-agent-skills"),
    "gemini": (".agents/skills", "https://geminicli.com/docs/cli/creating-skills/"),
    "antigravity": (".agents/skills", "https://antigravity.google/docs/skills/"),
    "opencode": (".agents/skills", "https://opencode.ai/docs/skills/"),
}
DOCS = {
    "claude": "https://code.claude.com/docs/en/skills/",
    "codex": "https://learn.chatgpt.com/docs/build-skills.md",
    "cursor": "https://cursor.com/docs/skills",
}


class Problem(Exception):
    def __init__(self, message, status="FAIL"):
        super().__init__(message)
        self.status = status


class UniqueLoader(yaml.SafeLoader):
    """Reject duplicate YAML keys instead of silently picking one."""


def _mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise Problem("Frontmatter keys must be unique strings")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def targets(value):
    result = list(dict.fromkeys(value.split(",")))
    if not result or any(t not in TARGET_PATHS for t in result):
        raise Problem("Targets must be claude,codex,cursor (comma-separated)")
    return result


def no_links(path, allow_leaf=False):
    """Reject symlink traversal in an existing path or any of its ancestors."""
    path = Path(path).absolute()
    parts = path.parents if allow_leaf else (path, *path.parents)
    for part in parts:
        if part.is_symlink():
            raise Problem("Symlink paths are not supported by this installer")


def stale(dest, skill):
    """True when dest is missing, a symlink, or its contents differ from skill.

    Comparison uses SHA-256 digests and executable flags, never mtime.
    """
    dest = Path(dest)
    if dest.is_symlink() or not dest.exists():
        return True
    try:
        current = validate(dest)
    except Problem:
        return True
    return current["files"] != skill["files"] or current["body"] != skill["body"]


def _write_receipt(path, value, exclusive=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if exclusive:
        with path.open("x", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2)
            handle.write("\n")
        return
    handle, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            json.dump(value, out, indent=2)
            out.write("\n")
        os.replace(tmp, path)
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise


def inventory(path):
    path = Path(path)
    no_links(path)
    if not path.is_dir():
        raise Problem("Skill must be a readable directory")
    result = {}
    for base, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            item = Path(base) / name
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise Problem("Skill must contain only regular files and directories")
            if stat.S_ISREG(info.st_mode):
                rel = item.relative_to(path).as_posix()
                result[rel] = {
                    "sha256": hashlib.sha256(item.read_bytes()).hexdigest(),
                    "executable": bool(info.st_mode & 0o111),
                }
    return dict(sorted(result.items()))


def validate(source):
    source = Path(source).absolute()
    files = inventory(source)
    if "SKILL.md" not in files:
        raise Problem("Missing SKILL.md")
    raw = (source / "SKILL.md").read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Problem("SKILL.md must be UTF-8") from exc
    # Match complete lines, preserve every body byte, support LF and CRLF.
    match = re.match(rb"\A---\r?\n(.*?)\r?\n---(?:\r?\n|\Z)", raw, re.S)
    if not match:
        raise Problem("SKILL.md needs opening and closing YAML frontmatter lines")
    try:
        meta = yaml.load(match.group(1).decode("utf-8"), Loader=UniqueLoader)
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        raise Problem("Invalid YAML frontmatter") from exc
    if not isinstance(meta, dict):
        raise Problem("Frontmatter must be a mapping")
    extras = sorted(set(meta) - FIELDS)
    if extras:
        raise Problem("Tool-specific or unknown frontmatter rejected; move to an external overlay: " + ", ".join(extras))
    for field in ("name", "description"):
        if not isinstance(meta.get(field), str) or not meta[field].strip():
            raise Problem(field + " must be a non-empty string")
    name = meta["name"]
    if len(name) > 64 or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        raise Problem("Invalid skill name")
    if source.name != name:
        raise Problem("Skill name must match its directory")
    if len(meta["description"]) > 1024:
        raise Problem("Description exceeds 1024 characters")
    for field in ("license", "allowed-tools", "compatibility"):
        if field in meta and (not isinstance(meta[field], str) or not meta[field].strip()):
            raise Problem(field + " must be a non-empty string")
    if "compatibility" in meta and len(meta["compatibility"]) > 500:
        raise Problem("Compatibility exceeds 500 characters")
    if "metadata" in meta and (not isinstance(meta["metadata"], dict) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in meta["metadata"].items()
    )):
        raise Problem("Metadata must map strings to strings")
    try:
        problems = reference_validate(source)
    except Exception as exc:
        raise Problem("Official skills-ref validator could not be queried", "BLOCKED") from exc
    if problems:
        raise Problem("Official skills-ref validation failed: " + "; ".join(str(x) for x in problems))
    return {"name": name, "metadata": meta, "files": files, "body": raw[match.end():], "isolated_frontmatter": []}


def root_for(scope, project=None):
    if scope == "user":
        if project is not None:
            raise Problem("--project is only valid with --scope project")
        return Path.home().absolute()
    return Path(project or Path.cwd()).absolute()


def receipt_path(root, name):
    return root / ".skill-anywhere" / "receipts" / (name + ".json")


def install(source, requested, root):
    source, root = Path(source).absolute(), Path(root).absolute()
    skill = validate(source)
    name = skill["name"]
    locations = list(dict.fromkeys(TARGET_PATHS[t] + "/" + name for t in requested))
    dests = [root / location for location in locations]
    receipt = receipt_path(root, name)
    for dest in dests:
        no_links(dest, allow_leaf=True)
        if dest.is_relative_to(source):
            raise Problem("Install destination cannot be inside source skill")
    no_links(receipt)
    record = None
    if receipt.exists():
        try:
            record = json.loads(receipt.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise Problem("Missing or invalid install receipt") from exc
        if not isinstance(record, dict) or record.get("format") != 1 or record.get("name") != name:
            raise Problem("Invalid install receipt format")
    elif any(item.exists() or item.is_symlink() for item in dests):
        raise Problem("Refusing to replace an existing install or receipt")
    stale_dests = [dest for dest in dests if stale(dest, skill)]
    merged_targets = list(dict.fromkeys([*(record or {}).get("targets", []), *requested]))
    merged_locations = list(dict.fromkeys([*(record or {}).get("locations", []), *locations]))
    value = {"format": 1, "name": name, "targets": merged_targets, "locations": merged_locations, "files": skill["files"]}
    if not stale_dests and record == value:
        return {"status": "PASS", "action": "unchanged", "name": name, "locations": merged_locations,
                "body_byte_identical": True, "validator": "skills-ref 0.1.0 (official source)", "isolated_frontmatter": []}
    action = "install" if record is None else "refresh"
    # Stage copies before replacing any visible tree. Roll back only our changes.
    staged, published, backups = [], [], []
    receipt_written = False
    previous_receipt = receipt.read_text(encoding="utf-8") if receipt.exists() else None
    try:
        for dest in stale_dests:
            dest.parent.mkdir(parents=True, exist_ok=True)
            stage = Path(tempfile.mkdtemp(prefix=".skill-anywhere-", dir=dest.parent))
            staged.append(stage)
            shutil.copytree(source, stage / name)
            if validate(stage / name)["files"] != skill["files"]:
                raise Problem("Source changed during install")
        for dest, stage in zip(stale_dests, staged):
            if dest.exists() or dest.is_symlink():
                backup = Path(tempfile.mkdtemp(prefix=".skill-anywhere-bak-", dir=dest.parent))
                dest.rename(backup / name)
                backups.append((dest, backup))
            if dest.exists() or dest.is_symlink():
                raise Problem("Install destination appeared during install")
            (stage / name).rename(dest)
            published.append(dest)
        _write_receipt(receipt, value, exclusive=record is None)
        receipt_written = True
    except Exception:
        if receipt_written:
            if previous_receipt is None:
                receipt.unlink(missing_ok=True)
            else:
                receipt.write_text(previous_receipt, encoding="utf-8")
        for dest in published:
            if dest.is_symlink() or dest.is_file():
                dest.unlink(missing_ok=True)
            elif dest.exists():
                shutil.rmtree(dest)
        for dest, backup in backups:
            (backup / name).rename(dest)
        raise
    finally:
        for stage in staged:
            shutil.rmtree(stage, ignore_errors=True)
        for _, backup in backups:
            shutil.rmtree(backup, ignore_errors=True)
    return {"status": "PASS", "action": action, "name": name, "locations": merged_locations,
            "body_byte_identical": True, "validator": "skills-ref 0.1.0 (official source)", "isolated_frontmatter": []}


def static_verify(source, requested, root):
    skill = validate(source)
    receipt = receipt_path(root, skill["name"])
    no_links(receipt)
    try:
        record = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Problem("Missing or invalid install receipt") from exc
    if not isinstance(record, dict) or record.get("format") != 1 or record.get("name") != skill["name"]:
        raise Problem("Invalid install receipt format")
    if record.get("files") != skill["files"]:
        raise Problem("Source no longer matches install receipt; re-run install to refresh")
    for target in requested:
        location = TARGET_PATHS[target] + "/" + skill["name"]
        if target not in record.get("targets", []) or location not in record.get("locations", []):
            raise Problem("Requested target was not installed")
        dest = root / location
        if dest.is_symlink():
            raise Problem("Installed copy is a symlink; re-run install to refresh a real copy")
        current = validate(dest)
        if current["files"] != skill["files"] or current["body"] != skill["body"]:
            raise Problem("Installed files or body differ from source; re-run install to refresh")
    return skill
