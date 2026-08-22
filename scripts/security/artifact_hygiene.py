"""Refuse to publish an artifact carrying a secret or a local path.

    python scripts/security/artifact_hygiene.py          # what this run produced
    python scripts/security/artifact_hygiene.py --all     # everything, for an audit

AGENTS.md 5 forbids absolute local paths in *newly published* artifacts, and
AGENTS.md 4/6.3 forbid an unredacted secret anywhere. The distinction matters
here: the Week 1 scanner output was produced on a Windows host and carries
`C:\\...` paths inside evidence that is already committed and immutable. Failing
on that forever would mean the check gets switched off, so by default this looks
only at files this run would add or change — which is exactly the set the rule is
about. ``--all`` audits the history when someone actually wants to look.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

PATTERNS = {
    "absolute local path": re.compile(r"(/mnt/[a-z]/|/home/[A-Za-z0-9_.-]+/|[A-Za-z]:\\\\)"),
    "api key": re.compile(r"\b(sk-[A-Za-z0-9_-]{8,}|(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,})"),
    "bearer token": re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._-]{16,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}

SUFFIXES = {".json", ".jsonl", ".md", ".log"}


def changed_files() -> list[Path]:
    """Artifacts this working tree would publish: untracked or modified.

    Ignored paths never appear, so the pytest scratch area under
    ``artifacts/ci/`` is out of scope without needing its own exception.
    """
    out = subprocess.run(
        ["git", "status", "--porcelain", "--", "artifacts", "reports", "datasets"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    paths = []
    for line in out.splitlines():
        if not line.strip():
            continue
        name = line[3:].strip().strip('"')
        if " -> " in name:  # a rename reports both sides
            name = name.split(" -> ", 1)[1]
        path = ROOT / name
        if path.is_dir():
            paths.extend(path.rglob("*"))
        else:
            paths.append(path)
    return paths


def all_files() -> list[Path]:
    return [path for folder in ("artifacts", "reports", "datasets") for path in (ROOT / folder).rglob("*")]


def scan(paths: list[Path]) -> list[str]:
    findings = []
    for path in paths:
        if not path.is_file() or path.suffix not in SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for name, pattern in PATTERNS.items():
            match = pattern.search(text)
            if match:
                findings.append(f"{path.relative_to(ROOT).as_posix()}: {name} -> {match.group(0)[:48]}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--all", action="store_true", help="audit every committed artifact, including immutable history")
    args = parser.parse_args()
    paths = all_files() if args.all else changed_files()
    findings = scan(paths)
    print(f"[hygiene] checked {sum(1 for path in paths if path.is_file() and path.suffix in SUFFIXES)} file(s)")
    for line in findings:
        print(f"  FAIL {line}")
    print("[hygiene] clean" if not findings else f"[hygiene] {len(findings)} problem(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
