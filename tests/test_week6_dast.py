"""DAST branch: ZAP output must land in the shared schema and group by endpoint.

Behaviour is asserted against a small inline fixture, never against the live
artifact: the ZAP spider explores a running SPA, so its alert set legitimately
changes between runs. The committed artifact is only checked for provenance.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sentinel_benchmark.analysis.grouping import endpoint_path, group_dast_observations, load_dast_groups
from sentinel_benchmark.indexer import build
from sentinel_benchmark.normalizer import is_zap_report, normalize_file, normalize_zap_report

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "artifacts/week-6/dast/zap-baseline.json"
MANIFEST = ROOT / "artifacts/week-6/dast/manifest.json"

ZAP_FIXTURE = {
    "@programName": "ZAP",
    "@version": "2.17.0",
    "created": "2026-01-01T00:00:00.000Z",
    "site": [
        {
            "@name": "http://juice-shop:3000",
            "alerts": [
                {
                    "pluginid": "2",
                    "alertRef": "2",
                    "name": "Private IP Disclosure",
                    "riskcode": "1",
                    "confidence": "1",
                    "desc": "<p>A private IP has been found in the HTTP response body.</p>",
                    "solution": "<p>Remove the private IP address.</p>",
                    "cweid": "497",
                    "count": "1",
                    "instances": [
                        {
                            "uri": "http://juice-shop:3000/rest/admin/application-configuration",
                            "method": "GET",
                            "param": "",
                            "evidence": "192.168.99.100:3000",
                            "otherinfo": "",
                        }
                    ],
                },
                {
                    "pluginid": "10038",
                    "alertRef": "10038-1",
                    "name": "Content Security Policy (CSP) Header Not Set",
                    "riskcode": "2",
                    "confidence": "3",
                    "desc": "<p>CSP is an added layer of security.</p>",
                    "solution": "<p>Set the header.</p>",
                    "cweid": "693",
                    "count": "2",
                    "instances": [
                        {"uri": "http://juice-shop:3000/rest/admin/application-configuration", "method": "GET"},
                        {"uri": "http://juice-shop:3000/api/Products/42?q=x", "method": "GET"},
                    ],
                },
                {
                    "pluginid": "10109",
                    "name": "Modern Web Application",
                    "riskcode": "0",
                    "confidence": "2",
                    "desc": "<p>The application appears to be a modern web application.</p>",
                    "solution": "<p>Nothing to change.</p>",
                    "cweid": "-1",
                    "count": "1",
                    "instances": [{"uri": "http://juice-shop:3000/", "method": "GET"}],
                },
            ],
        }
    ],
}


def _rows(dataset: str = "juice-shop-dast") -> list[dict]:
    records = normalize_zap_report(ZAP_FIXTURE, Path("artifacts/week-6/dast/zap-baseline.json"))
    return [
        {**record, "dataset": dataset, "observation_id": f"zap-fixture:{index:04d}"}
        for index, record in enumerate(records, 1)
    ]


# --------------------------------------------------------------------------- #
# Normalization: one shared schema for both evidence sources.
# --------------------------------------------------------------------------- #
def test_zap_report_is_recognised() -> None:
    assert is_zap_report(ZAP_FIXTURE)
    assert not is_zap_report({"results": []})
    assert not is_zap_report([{"check_id": "x"}])


def test_zap_alerts_flatten_to_one_record_per_instance() -> None:
    records = normalize_zap_report(ZAP_FIXTURE, Path("zap.json"))
    assert len(records) == 4  # 1 + 2 + 1 instances
    assert {record["tool"] for record in records} == {"OWASP ZAP"}
    assert all(record["line_start"] is None and record["line_end"] is None for record in records)


def test_zap_severity_cwe_and_confidence_are_mapped() -> None:
    private_ip, csp, *_ = normalize_zap_report(ZAP_FIXTURE, Path("zap.json"))
    assert private_ip["severity"] == "low" and private_ip["cwe"] == "CWE-497"
    assert private_ip["confidence"] == 0.25
    assert csp["severity"] == "medium" and csp["cwe"] == "CWE-693"
    assert csp["confidence"] == 0.75


def test_zap_html_is_stripped_and_evidence_is_kept() -> None:
    private_ip = normalize_zap_report(ZAP_FIXTURE, Path("zap.json"))[0]
    assert "<p>" not in private_ip["description"] and "<p>" not in private_ip["recommendation"]
    assert private_ip["description"].startswith("A private IP has been found")
    # The evidence string is application content: it must survive intact so the
    # injection filter and redaction downstream have something real to act on.
    assert "GET http://juice-shop:3000/rest/admin/application-configuration" in private_ip["evidence"]
    assert "evidence=192.168.99.100:3000" in private_ip["evidence"]


def test_zap_missing_cwe_is_not_invented() -> None:
    modern = normalize_zap_report(ZAP_FIXTURE, Path("zap.json"))[-1]
    assert modern["cwe"] is None  # cweid "-1" means the scanner did not claim one


# --------------------------------------------------------------------------- #
# Grouping: the subject is an endpoint, and one group is one issue.
# --------------------------------------------------------------------------- #
def test_endpoint_path_drops_host_and_query_and_collapses_ids() -> None:
    assert endpoint_path("http://juice-shop:3000/api/Products/42?q=x") == "/api/Products/{id}"
    assert endpoint_path("http://juice-shop:3000") == "/"
    assert endpoint_path("http://juice-shop:3000/rest/products/1/reviews") == "/rest/products/{id}/reviews"


def test_same_endpoint_with_two_issues_stays_two_groups() -> None:
    groups = group_dast_observations(_rows())
    config = [group for group in groups if group.endpoint == "/rest/admin/application-configuration"]
    assert len(config) == 2
    assert {group.reported_cwes[0] for group in config} == {"CWE-497", "CWE-693"}
    assert all(group.grouping_reason == ["same_endpoint_path", "same_reported_cwe"] for group in config)


def test_group_without_a_reported_cwe_is_still_grouped() -> None:
    groups = group_dast_observations(_rows())
    modern = [group for group in groups if group.category == "modern_web_application"]
    assert len(modern) == 1
    assert modern[0].reported_cwes == []
    assert modern[0].grouping_reason == ["same_endpoint_path"]


def test_group_ids_are_stable_and_observations_are_never_dropped() -> None:
    rows = _rows()
    first = group_dast_observations(rows)
    again = group_dast_observations(rows)
    assert [group.analysis_group_id for group in first] == [group.analysis_group_id for group in again]
    assigned = [obs for group in first for obs in group.observation_ids]
    assert sorted(assigned) == sorted(row["observation_id"] for row in rows)


def test_endpoint_group_carries_no_ground_truth() -> None:
    # A running app has no ground truth. Nothing downstream may mistake a
    # scanner claim for a verified fact.
    payload = json.dumps([group.model_dump(mode="json") for group in group_dast_observations(_rows())])
    assert "expected_cwe" not in payload
    assert "ground_truth" not in payload.lower()


def test_rows_from_another_dataset_are_ignored() -> None:
    assert group_dast_observations(_rows(dataset="owasp-benchmark-java")) == []


# --------------------------------------------------------------------------- #
# The committed artifact: provenance, not counts.
# --------------------------------------------------------------------------- #
def test_dast_manifest_matches_the_artifact_it_describes() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["dataset"] == "juice-shop-dast"
    assert manifest["scanner"]["mode"].startswith("baseline")
    assert manifest["output"]["raw_sha256"] == hashlib.sha256(RAW.read_bytes()).hexdigest()
    assert manifest["output"]["normalized_observations"] == len(normalize_file(RAW))
    assert manifest["run_id"] == json.loads((ROOT / "configs/sources.json").read_text(encoding="utf-8"))[-1]["run_id"]


def test_indexed_dast_observations_all_reach_an_endpoint_group(tmp_path: Path) -> None:
    db = tmp_path / "sentinel.db"
    build(ROOT / "configs/sources.json", db, ROOT / "datasets/knowledge/security-topics.jsonl")
    groups = load_dast_groups(db)
    assert groups
    assigned = {obs for group in groups for obs in group.observation_ids}
    assert len(assigned) == len(normalize_file(RAW))
    assert all(group.analysis_group_id.startswith("EG-") for group in groups)
    assert all(group.grouping_mode == "endpoint_assisted" for group in groups)
