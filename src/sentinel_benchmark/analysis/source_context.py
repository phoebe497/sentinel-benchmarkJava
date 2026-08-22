"""Give the agent the code the scanner was talking about.

Until now the payload carried only the scanner's *description* of a finding —
prose that already asserts a weakness. With nothing to argue against, the agent
agreed with it, which is how a run produced 20 true positives, 4 false
positives and zero true negatives: it never once concluded "not vulnerable".
Its own rationale named the cause: *"the supplied excerpt is descriptive rather
than source code"*.

The BenchmarkJava false-positive cases turn on details that live only in the
code — a value that is a constant, a query that is parameterised, a list whose
tainted element is removed before use. This module supplies those lines.

Three constraints shape it:

* **Scope.** Only ``BenchmarkTest00001``–``BenchmarkTest00100`` inside a known
  root resolve. A path from a scanner is untrusted input, so it selects a file
  by test id rather than by following the path it supplied.
* **Trust.** Source read from the corpus is untrusted DATA like any other
  application content (AGENTS.md 6.1). It is scanned for injection here, and
  redacted at the prompt sink like the rest of the payload.
* **Integrity.** The corpus keeps its answers in a separate CSV, never in the
  test files, so nothing here can leak ground truth. The assertion is checked
  in ``tests/test_week6_source_context.py`` rather than assumed.
"""

from __future__ import annotations

import re
from pathlib import Path

# BenchmarkJava files are 80-130 lines. A window around the sink would cut the
# taint's origin out of the picture, which is the very link the agent reported
# missing, so the whole file goes in and the cap only guards against surprises.
MAX_SOURCE_CHARS = 14000

TEST_FILE = re.compile(r"BenchmarkTest(\d{5})\.java$")

# The identical GPL/Javadoc block that opens all 100 files: ~17 lines of licence
# text carrying nothing about the finding.
_LICENCE_HEADER = re.compile(r"\A\s*/\*\*.*?\*/\s*", re.DOTALL)


def default_roots(project_root: Path) -> tuple[Path, ...]:
    """Where corpus source may be read from, in order of preference."""
    return (
        project_root / "vendor/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode",
        project_root / "app/web/data/benchmark-sources",
    )


def resolve(location: str, roots: tuple[Path, ...]) -> Path | None:
    """The file a scanner location refers to, or None if it is out of scope.

    The supplied path is never joined onto a root: only the test id is taken
    from it, so a location like ``../../etc/passwd`` cannot address anything.
    """
    match = TEST_FILE.search(location or "")
    if match is None or not 1 <= int(match.group(1)) <= 100:
        return None
    name = f"BenchmarkTest{match.group(1)}.java"
    for root in roots:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def read(location: str, roots: tuple[Path, ...]) -> dict[str, object] | None:
    """The numbered source lines for one location, ready to put in a payload.

    Lines are numbered so the model can tie a claim to a line the scanner also
    cited, instead of describing code by paraphrase.
    """
    path = resolve(location, roots)
    if path is None:
        return None
    text = path.read_text(encoding="utf-8")
    body = _LICENCE_HEADER.sub("", text, count=1)
    offset = text.count("\n", 0, len(text) - len(body))
    truncated = len(body) > MAX_SOURCE_CHARS
    if truncated:
        body = body[:MAX_SOURCE_CHARS]
    numbered = "\n".join(
        f"{number:>4}| {line}"
        for number, line in enumerate(body.splitlines(), start=offset + 1)
    )
    return {
        "file": location,
        "first_line": offset + 1,
        "licence_header_omitted": offset > 0,
        "truncated": truncated,
        "lines": numbered,
    }
