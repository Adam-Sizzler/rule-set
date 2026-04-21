#!/usr/bin/env python3
import os
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
SECTIONS = (
    ("JSON", "json", "*.json"),
    ("SRS", "srs", "*.srs"),
    ("MRS", "mrs", "*.mrs"),
    ("YAML", "yaml", "*.yaml"),
)


def remote_slug():
    configured = os.environ.get("CDN_REPO")
    if configured:
        return configured.strip()

    try:
        remote = subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError:
        return "Adam-Sizzler/sb-rule-set"

    match = re.search(r"github\.com[:/]([^/\s]+/[^/\s]+?)(?:\.git)?$", remote)
    if not match:
        return "Adam-Sizzler/sb-rule-set"
    return match.group(1)


def cdn_url(path):
    branch = os.environ.get("CDN_BRANCH", "main")
    return f"https://cdn.jsdelivr.net/gh/{remote_slug()}@{branch}/{path.as_posix()}"


def section_lines(title, directory, pattern):
    files = sorted((ROOT / directory).glob(pattern))
    if not files:
        return []

    lines = [f"## {title}", ""]
    for path in files:
        relative = path.relative_to(ROOT)
        lines.append(f"- `{cdn_url(relative)}`")
    lines.append("")
    return lines


def main():
    lines = ["# Rule-sets CDN links", ""]
    for section in SECTIONS:
        lines.extend(section_lines(*section))
    README.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
