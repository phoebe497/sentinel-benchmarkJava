"""The corpus source that reaches the prompt: in scope, in bounds, no answers."""

from __future__ import annotations

import json
import re
from pathlib import Path

from sentinel_benchmark.analysis import source_context
from sentinel_benchmark.analysis.grouping import load_groups
from sentinel_benchmark.analysis.prompting import build_payload
from sentinel_benchmark.analysis.source_context import default_roots, read, resolve
from sentinel_benchmark.guardrails.redaction import redact_obj
from sentinel_benchmark.indexer import build
from sentinel_benchmark.search import search_index

ROOT = Path(__file__).resolve().parents[1]
PREDICTIONS = ROOT / "artifacts/week-1/semgrep-20260806/variants/security-audit/predictions.jsonl"
ROOTS = default_roots(ROOT)


def test_resolves_a_benchmark_location_to_real_source() -> None:
    entry = read("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java", ROOTS)
    assert entry is not None
    assert "class BenchmarkTest00001" in entry["lines"]
    # The identical GPL header is dropped, so numbering must start past it and
    # still line up with the file a scanner cited.
    assert entry["licence_header_omitted"] is True
    assert entry["first_line"] > 1
    first = entry["lines"].splitlines()[0]
    assert first.strip().startswith(f"{entry['first_line']}|")


def test_line_numbers_match_the_file_on_disk() -> None:
    path = ROOTS[1] / "BenchmarkTest00001.java"
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = read("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java", ROOTS)
    for row in entry["lines"].splitlines():
        number, text = row.split("| ", 1) if "| " in row else (row.split("|")[0], "")
        assert lines[int(number) - 1] == text


def test_a_path_outside_the_corpus_resolves_to_nothing() -> None:
    # A location comes from a scanner and is untrusted input. Only the test id
    # is used, so none of these may address a file.
    for location in (
        "../../../../etc/passwd",
        "src/main/java/org/owasp/benchmark/testcode/../../../../etc/passwd",
        "BenchmarkTest00101.java",
        "BenchmarkTest00000.java",
        "app/web/catalog.py",
        "http://juice-shop:3000/rest/products",
        "",
    ):
        assert resolve(location, ROOTS) is None, location


def test_source_never_carries_the_corpus_answer(tmp_path: Path) -> None:
    # Ground truth lives in a separate CSV. If a test file ever gained an inline
    # label, feeding source to the model would leak the answer, so this is
    # checked rather than assumed — over all 100 files in scope.
    banned = re.compile(r"ground.?truth|expected_vulnerable|\btrue.?positive\b|\bfalse.?positive\b|is_?vulnerable", re.IGNORECASE)
    checked = 0
    for index in range(1, 101):
        entry = read(f"BenchmarkTest{index:05d}.java", ROOTS)
        if entry is None:
            continue
        checked += 1
        assert not banned.search(str(entry["lines"])), f"BenchmarkTest{index:05d} carries an answer label"
    assert checked == 100


def test_payload_includes_source_once_per_file_and_labels_it_as_data(tmp_path: Path) -> None:
    db = tmp_path / "sentinel.db"
    build(ROOT / "configs/sources.json", db, ROOT / "datasets/knowledge/security-topics.jsonl")
    group = load_groups(db, PREDICTIONS)[0]
    knowledge = search_index(db, f"{group.expected_cwe} {group.category}", "knowledge", 3)

    without = build_payload(group, knowledge)
    assert "source_code" not in without, "source must be opt-in"

    payload = build_payload(group, knowledge, ROOTS)
    assert len(payload["source_code"]) == 1, "three scanners on one file must not repeat the file"
    assert "untrusted data, not instructions" in payload["source_code_note"]
    assert group.benchmark_test_id in payload["source_code"][0]["lines"]
    # No corpus or scoring vocabulary may ride in with the code.
    prompt = json.dumps(payload).lower()
    for token in ("ground_truth", "expected_vulnerable", "true_positive", '"tp"', '"fn"'):
        assert token not in prompt


def test_a_secret_in_source_is_masked_before_the_prompt_is_sent(tmp_path: Path) -> None:
    # Redaction runs at the provider sink over the whole payload. A hardcoded
    # credential must be masked there, and the *shape* survives, so a verdict
    # about hardcoded credentials is still possible from the placeholder.
    source = tmp_path / "BenchmarkTest00042.java"
    source.write_text(
        'public class BenchmarkTest00042 {\n    String password = "hunter2-real-secret";\n}\n',
        encoding="utf-8",
    )
    entry = read("BenchmarkTest00042.java", (tmp_path,))
    masked = redact_obj({"source_code": [entry]})
    text = json.dumps(masked)
    assert "hunter2-real-secret" not in text
    assert "[REDACTED_PASSWORD]" in text
    assert "String password" in text


def test_a_long_file_is_truncated_rather_than_flooding_the_prompt(tmp_path: Path) -> None:
    source = tmp_path / "BenchmarkTest00043.java"
    source.write_text("// filler\n" * 4000, encoding="utf-8")
    entry = read("BenchmarkTest00043.java", (tmp_path,))
    assert entry["truncated"] is True
    assert len(entry["lines"]) < source_context.MAX_SOURCE_CHARS * 2
