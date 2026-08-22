"""Verify DAST findings against the running app, one approved request at a time.

    python scripts/probe.py routes            # what the gateway will carry
    python scripts/probe.py plan              # proposals per finding, sends nothing
    python scripts/probe.py run [--limit N]   # ask, send, record

``run`` is interactive by design: each request is printed in full and waits for
a typed y/n. There is no flag that answers for the human (AGENTS.md 6.2), so a
scripted demo must feed the answers on stdin rather than skip the question.

Every attempt is appended to artifacts/week-6/probes/<run_id>.jsonl, redacted,
including the ones that were rejected or could not be routed.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dotenv import load_dotenv
from sentinel_benchmark.analysis.grouping import load_dast_groups
from sentinel_benchmark.guardrails.approval import ApprovalGate, ProposedRequest
from sentinel_benchmark.guardrails.injection import DATA_OPEN
from sentinel_benchmark.indexer import build
from sentinel_benchmark.probe import GatewayClient, ProbeRequest, propose_for_group, run_probe
from sentinel_benchmark.probe.proposal import merge_by_route
from sentinel_benchmark.probe.payloads import FIXTURE_PATH, INJECTION_PROBE_ID

MANIFEST = ROOT / "configs" / "sources.json"
KB = ROOT / "datasets" / "knowledge" / "security-topics.jsonl"
OUT = ROOT / "artifacts" / "week-6" / "probes"


def dast_groups() -> list:
    db = Path(tempfile.mkdtemp(prefix="sentinel-week6-")) / "sentinel.db"
    build(MANIFEST, db, KB)
    return load_dast_groups(db)


def cli_prompter(request: ProposedRequest) -> tuple[bool, str]:
    """Show endpoint, payload and purpose; require a typed approval."""
    summary = request.summary()
    print("\n" + "-" * 72)
    print(f"  endpoint : {summary['method']} {summary['endpoint']}")
    print(f"  payload  : {json.dumps(summary['payload'], ensure_ascii=False)}")
    print(f"  purpose  : {summary['purpose']}")
    print("-" * 72)
    try:
        answer = input("  send this request? [y/N] ").strip().lower()
    except EOFError:
        # No human on the other end means no approval, not a default yes.
        return False, "no_input_available"
    return (answer in {"y", "yes"}), "approved_at_cli" if answer in {"y", "yes"} else "rejected_at_cli"


def cmd_routes(client: GatewayClient) -> int:
    for route in sorted(client.routes().values(), key=lambda item: item.id):
        print(f"{route.id:24} {route.method:5} {route.path}")
    return 0


def cmd_plan(client: GatewayClient) -> int:
    routes = client.routes()
    routable = unroutable = 0
    for group in dast_groups():
        request = propose_for_group(group, routes)
        if request is None:
            unroutable += 1
            print(f"[cannot verify] {group.endpoint:52} {','.join(group.reported_cwes) or '-'}")
            continue
        routable += 1
        print(f"[{request.route_id:22}] {group.endpoint:52} {','.join(group.reported_cwes) or '-'}")
    print(f"\n{routable} finding(s) can be verified through the gateway, {unroutable} cannot.")
    return 0


def cmd_run(client: GatewayClient, limit: int | None) -> int:
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-probe"
    OUT.mkdir(parents=True, exist_ok=True)
    records = OUT / f"{run_id}.jsonl"
    gate = ApprovalGate(log_path=OUT / "approvals.jsonl")
    routes = client.routes()
    proposals = [request for group in dast_groups() if (request := propose_for_group(group, routes)) is not None]
    unique = merge_by_route(proposals)
    if limit:
        unique = unique[:limit]
    covered = sum(len(request.analysis_group_ids) for request in unique)
    print(f"[probe] run_id={run_id}: {len(unique)} request(s) covering {covered} finding(s), each needs your approval")
    tally: dict[str, int] = {}
    with records.open("w", encoding="utf-8", newline="\n") as stream:
        for request in unique:
            result = run_probe(request, client=client, gate=gate, prompter=cli_prompter)
            stream.write(json.dumps(result.to_record(), ensure_ascii=False, sort_keys=True) + "\n")
            tally[result.decision] = tally.get(result.decision, 0) + 1
            if result.sent:
                state = result.transport_error or f"HTTP {result.status}"
                flag = " injection-flagged" if result.injection_flagged else ""
                print(f"  -> sent {request.route_id}: {state}{flag}")
            else:
                print(f"  -> not sent {request.route_id}: {result.decision} ({result.reason})")
    print(f"\n[probe] {json.dumps(tally)} -> {records.relative_to(ROOT)}")
    return 0


def cmd_injection_check(client: GatewayClient) -> int:
    """Send the crafted fixture through the gateway and check what came back.

    Week 5 proved the filter against a stored file. This proves it against a
    real HTTP response: the fixture is POSTed to the echo route, which reflects
    it, so the text arrives as an untrusted response over the wire.
    """
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    expected = fixture["expected"]
    result = run_probe(
        ProbeRequest(
            route_id="echo",
            purpose="send the crafted injection fixture to the echo endpoint and confirm the reflected response is quarantined and redacted",
            payload_id=INJECTION_PROBE_ID,
        ),
        client=client,
        gate=ApprovalGate(log_path=OUT / "approvals.jsonl"),
        prompter=cli_prompter,
    )
    if not result.sent:
        print(f"\n[injection-check] not sent: {result.decision} ({result.reason})")
        return 1
    record = json.dumps(result.to_record(), ensure_ascii=False)
    missed = [name for name in expected["injection_patterns"] if name not in result.injection_patterns]
    survived = [secret for secret in expected["must_not_survive"] if secret in record]
    checks = {
        "reached_target": result.reached_target,
        "injection_flagged": result.injection_flagged,
        "expected_patterns_detected": not missed,
        "response_quarantined_as_data": result.body.startswith(DATA_OPEN),
        "no_secret_survived": not survived,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    evidence = OUT / f"injection-check-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    evidence.write_text(
        json.dumps(
            {
                "fixture": str(FIXTURE_PATH.relative_to(ROOT).as_posix()),
                "checks": checks,
                "patterns_detected": result.injection_patterns,
                "patterns_missed": missed,
                "secrets_that_survived": survived,
                "redaction_hits": result.redaction_hits,
                "probe": result.to_record(),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print()
    for name, ok in checks.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n[injection-check] evidence -> {evidence.relative_to(ROOT)}")
    return 0 if all(checks.values()) else 1


def main() -> int:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["routes", "plan", "run", "injection-check"])
    parser.add_argument("--limit", type=int, default=None, help="stop after N endpoints (run only)")
    args = parser.parse_args()
    client = GatewayClient.from_env()
    if args.command == "routes":
        return cmd_routes(client)
    if args.command == "plan":
        return cmd_plan(client)
    if args.command == "injection-check":
        return cmd_injection_check(client)
    return cmd_run(client, args.limit)


if __name__ == "__main__":
    raise SystemExit(main())
