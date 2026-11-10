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


def no_links(path):
    """Reject symlink traversal in an existing path or any of its ancestors."""
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if part.is_symlink():
            raise Problem("Symlink paths are not supported by this installer")


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
    for dest in dests + [receipt]:
        no_links(dest)
        if dest.exists():
            raise Problem("Refusing to replace an existing install or receipt")
        if dest.is_relative_to(source):
            raise Problem("Install destination cannot be inside source skill")
    # Stage all copies before making any visible. Roll back only our new trees.
    staged, published = [], []
    receipt_created = False
    try:
        for dest in dests:
            dest.parent.mkdir(parents=True, exist_ok=True)
            stage = Path(tempfile.mkdtemp(prefix=".skill-anywhere-", dir=dest.parent))
            staged.append(stage)
            shutil.copytree(source, stage / name)
            copied = stage / name
            if validate(copied)["files"] != skill["files"]:
                raise Problem("Source changed during install")
        for dest, stage in zip(dests, staged):
            if dest.exists() or dest.is_symlink():
                raise Problem("Install destination appeared during install")
            (stage / name).rename(dest)
            published.append(dest)
        value = {"format": 1, "name": name, "targets": requested, "locations": locations, "files": skill["files"]}
        receipt.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive create also protects against a concurrent install.
        with receipt.open("x", encoding="utf-8") as handle:
            receipt_created = True
            json.dump(value, handle, indent=2)
            handle.write("\n")
    except Exception:
        if receipt_created:
            receipt.unlink(missing_ok=True)
        for dest in published:
            shutil.rmtree(dest)
        raise
    finally:
        for stage in staged:
            shutil.rmtree(stage, ignore_errors=True)
    return {"status": "PASS", "action": "install", "name": name, "locations": locations,
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
        raise Problem("Source no longer matches install receipt")
    for target in requested:
        location = TARGET_PATHS[target] + "/" + skill["name"]
        if target not in record.get("targets", []) or location not in record.get("locations", []):
            raise Problem("Requested target was not installed")
        dest = root / location
        current = validate(dest)
        if current["files"] != skill["files"] or current["body"] != skill["body"]:
            raise Problem("Installed files or body differ from source")
    return skill
