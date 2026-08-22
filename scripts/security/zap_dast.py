"""Record provenance for a ZAP baseline run and keep the source manifest in sync.

The DAST scan is not reproducible byte-for-byte: the spider explores a live SPA,
so alert counts move between runs. What must stay exact is the *provenance* —
which scanner version, which target image, which command, which output file and
its digest. This script derives all of that from the artifact ZAP just wrote, so
the manifest can never drift from the evidence.

Run it after the scanner container exits (scripts/stack.sh does this for you):

    python3 scripts/security/zap_dast.py
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from sentinel_benchmark.normalizer import normalize_file  # noqa: E402

DAST_DIR = ROOT / "artifacts" / "week-6" / "dast"
RAW = DAST_DIR / "zap-baseline.json"
MANIFEST = DAST_DIR / "manifest.json"
SOURCES = ROOT / "configs" / "sources.json"
SOURCE_ID = "juiceshop-zap-baseline"
DATASET = "juice-shop-dast"

ZAP_IMAGE = "zaproxy/zap-stable:2.17.0"
TARGET_IMAGE = "bkimminich/juice-shop:latest"
SCAN_COMMAND = "zap-baseline.py -t http://juice-shop:3000 -J zap-baseline.json -r zap-baseline.html -m 3 -j -I"


def _digest(image: str) -> str | None:
    """Resolve the pulled image digest, or None when Docker is unavailable."""
    try:
        out = subprocess.run(
            ["docker", "image", "inspect", image, "--format", "{{index .RepoDigests 0}}"],
            capture_output=True,
            text=True,
            timeout=20,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return out.split("@", 1)[1] if "@" in out else None


def _generated_at(report: dict[str, Any]) -> datetime:
    # `created` is ISO-8601 UTC; `@generated` is RFC-1123-ish local time and only
    # a fallback ("Sat, 22 Aug 2026 04:32:55").
    created = str(report.get("created") or "").strip()
    if created:
        try:
            return datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            pass
    raw = str(report.get("@generated") or "").strip()
    for fmt in ("%a, %d %b %Y %H:%M:%S", "%a, %d %b %Y %H:%M:%S %z"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    raise SystemExit(f"cannot determine when the report was created: {created!r} / {raw!r}")


def _urls_with_alerts(report: dict[str, Any]) -> int:
    """Distinct URLs an alert was raised on. The crawl total is not in the report."""
    uris = {
        str(instance.get("uri") or "")
        for site in report.get("site") or []
        for alert in site.get("alerts") or []
        for instance in alert.get("instances") or []
    }
    return len(uris - {""})


def build_manifest() -> dict[str, Any]:
    if not RAW.exists():
        raise SystemExit(f"no DAST output at {RAW.relative_to(ROOT)}; run: bash scripts/stack.sh scan")
    report = json.loads(RAW.read_text(encoding="utf-8"))
    generated = _generated_at(report)
    stamp = generated.strftime("%Y%m%dT%H%M%SZ")
    sites = report.get("site") or []
    alerts = sum(len(site.get("alerts") or []) for site in sites)
    previous = json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.exists() else {}
    previous_scanner = previous.get("scanner", {}) if isinstance(previous.get("scanner"), dict) else {}
    previous_target = previous.get("target", {}) if isinstance(previous.get("target"), dict) else {}
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "run_id": f"{stamp}-zap-juiceshop-baseline",
        "dataset": DATASET,
        "target": {
            "app": "OWASP Juice Shop",
            "image": TARGET_IMAGE,
            # Keep the previously recorded digest when Docker cannot be queried,
            # so provenance survives a manifest refresh on another machine.
            "image_digest": _digest(TARGET_IMAGE) or previous_target.get("image_digest"),
            "internal_url": "http://juice-shop:3000",
            "published_ports": "none (internal network only; reachable through the gateway or by ZAP on the same network)",
        },
        "scanner": {
            "tool": str(report.get("@programName") or "ZAP"),
            "mode": "baseline (passive only, no active attack)",
            "version": str(report.get("@version") or ""),
            "image": ZAP_IMAGE,
            "image_digest": _digest(ZAP_IMAGE) or previous_scanner.get("image_digest"),
            "command": SCAN_COMMAND,
            "spider": "traditional (3 min) + AJAX spider",
            "urls_with_alerts": _urls_with_alerts(report),
        },
        "output": {
            "raw": str(RAW.relative_to(ROOT).as_posix()),
            "raw_sha256": hashlib.sha256(RAW.read_bytes()).hexdigest(),
            "html_report": str((DAST_DIR / "zap-baseline.html").relative_to(ROOT).as_posix()),
            "generated_at": generated.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "alerts": alerts,
            "normalized_observations": len(normalize_file(RAW)),
        },
        "reproduce": ["bash scripts/stack.sh up", "bash scripts/stack.sh scan"],
        "notes": [
            "Baseline mode is passive: ZAP spiders and reports what normal traffic reveals; it never sends attack payloads.",
            "Alert counts are not deterministic between runs because the spider explores a live SPA, so tests must not pin them.",
            "ZAP scans juice-shop directly on the internal network because it is a scanner. The agent's request tool has no route except the gateway.",
        ],
    }
    return manifest


def sync_sources(run_id: str) -> bool:
    """Point the DAST entry of the source manifest at the run just recorded."""
    sources = json.loads(SOURCES.read_text(encoding="utf-8"))
    changed = False
    for source in sources:
        if source.get("id") == SOURCE_ID and source.get("run_id") != run_id:
            source["run_id"] = run_id
            changed = True
    if changed:
        SOURCES.write_text(json.dumps(sources, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return changed


def main() -> int:
    manifest = build_manifest()
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    synced = sync_sources(manifest["run_id"])
    print(
        json.dumps(
            {
                "run_id": manifest["run_id"],
                "alerts": manifest["output"]["alerts"],
                "observations": manifest["output"]["normalized_observations"],
                "sources_updated": synced,
                "next": "python -m sentinel_benchmark.indexer",
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
