"""The whole Week 6 chain in one command, logged and measured end to end.

    python scripts/flow.py --provider nine_router --limit 3

Each stage is runnable on its own (scripts/analyze.py, scripts/probe.py); this
script exists because "the stages work" and "the flow works" are different
claims. It runs them in order, in one process, and writes a single log plus a
single metrics file so the second claim has evidence:

    normalize -> analyse -> propose -> approve -> send -> filter -> verify
              -> score -> metrics

The human is still in the loop. There is no flag that answers the approval
prompt (AGENTS.md 6.2); a scripted demo pipes the answers in on stdin:

    printf 'y\\nn\\ny\\n' | python scripts/flow.py --provider nine_router --limit 3

Only the DAST branch has a probe step, so that is the branch this runs. SAST
has no live endpoint to probe; its ground-truth scoring is a separate command.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import analyze
import probe as probe_cli
from dotenv import load_dotenv
from sentinel_benchmark.analysis.artifacts import load_run, write_checksums, write_jsonl
from sentinel_benchmark.analysis.runner import run_batch
from sentinel_benchmark.analysis.scoring import score_reports
from sentinel_benchmark.analysis.verification import apply_verification, verify_report
from sentinel_benchmark.guardrails.approval import ApprovalGate
from sentinel_benchmark.probe import GatewayClient, propose_for_group, run_probe
from sentinel_benchmark.probe.proposal import merge_by_route
from sentinel_benchmark.runlog import RunLog, probe_counters, report_counters

WEEK6 = ROOT / "artifacts" / "week-6"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--provider", choices=["fake", "nine_router"], default="nine_router")
    parser.add_argument("--limit", type=int, default=None, help="stop after N approval prompts")
    parser.add_argument("--tag", default="flow")
    args = parser.parse_args()
    load_dotenv(ROOT / ".env")

    run = RunLog.create(WEEK6, tag=args.tag)
    print(f"[flow] run_id={run.run_id}")
    status = "completed"
    summary: dict[str, object] = {}
    try:
        with run.stage("normalize") as detail:
            db, groups = analyze.indexed_dast_groups()
            detail["alerts"] = sum(len(group.observation_ids) for group in groups)
            detail["endpoint_groups"] = len(groups)
            run.count("alerts.normalized", detail["alerts"])

        with run.stage("analyse", provider=args.provider) as detail:
            provider = analyze.provider(args.provider)
            provider.preflight()
            run_dir = run_batch(groups=groups, db_path=db, provider=provider, run_root=WEEK6, tag=args.tag)
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            reports = load_run(run_dir)["reports"]
            errors = [row for row in load_run(run_dir).get("errors", [])]
            detail["run_dir"] = str(run_dir.relative_to(ROOT).as_posix())
            detail["model"] = manifest["model"]
            detail["reports"] = len(reports)
            detail["failed_groups"] = len(errors)
            for error in errors:
                run.failure("analyse", "llm_or_guard_failure", json.dumps(error, ensure_ascii=False))
            for name, value in report_counters(reports).items():
                # Labelled as pre-probe: the score stage records the distribution
                # again after verification, and the difference between the two is
                # the whole point of probing.
                run.count(name.replace("verdicts.", "verdicts.before_probe."), value)

        with run.stage("propose") as detail:
            client = GatewayClient.from_env()
            routes = client.routes()
            proposals, unroutable = [], 0
            for group in groups:
                request = propose_for_group(group, routes)
                if request is None:
                    unroutable += 1
                    continue
                proposals.append(request)
            requests = merge_by_route(proposals)
            if args.limit:
                requests = requests[: args.limit]
            detail["routes_available"] = len(routes)
            detail["requests"] = len(requests)
            detail["findings_unroutable"] = unroutable
            run.count("probes.unroutable_findings", unroutable)

        # One stage covers approve, send and filter: they are inseparable by
        # design. The gate is the only way a request is emitted, and the
        # response passes injection scanning and redaction inside run_probe
        # before it is ever recorded.
        with run.stage("approve_send_filter") as detail:
            probe_dir = WEEK6 / "probes"
            probe_dir.mkdir(parents=True, exist_ok=True)
            records_path = probe_dir / f"{run.run_id}-probe.jsonl"
            gate = ApprovalGate(log_path=probe_dir / "approvals.jsonl")
            records = []
            with records_path.open("w", encoding="utf-8", newline="\n") as stream:
                for request in requests:
                    result = run_probe(request, client=client, gate=gate, prompter=probe_cli.cli_prompter)
                    record = result.to_record()
                    records.append(record)
                    stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                    run.event(
                        "probe",
                        route_id=result.route_id,
                        decision=result.decision,
                        sent=result.sent,
                        status=result.status,
                        reached_target=result.reached_target,
                        injection_flagged=result.injection_flagged,
                        findings_covered=len(request.analysis_group_ids),
                    )
                    if result.transport_error:
                        run.failure("approve_send_filter", "gateway_transport_error", result.transport_error)
            for name, value in probe_counters(records).items():
                run.count(name, value)
            detail["records"] = str(records_path.relative_to(ROOT).as_posix())
            detail["sent"] = sum(1 for row in records if row.get("sent"))

        with run.stage("verify") as detail:
            by_group: dict[str, dict] = {}
            for row in records:
                for group_id in row.get("analysis_group_ids") or []:
                    by_group[str(group_id)] = row
            updated, exchanges, changed, answered = [], [], 0, 0
            for report in reports:
                probe_record = by_group.get(str(report.get("analysis_group_id")))
                if probe_record is None:
                    updated.append(report)
                    continue
                verification, exchange = verify_report(report, probe_record, provider=provider)
                if exchange:
                    exchanges.append(exchange)
                changed += int(verification.changed)
                answered += int(verification.reached_target)
                updated.append(apply_verification(report, verification))
            write_jsonl(run_dir / "reports.jsonl", updated)
            write_jsonl(run_dir / "verification-responses.jsonl", exchanges)
            write_checksums(run_dir)
            detail["verdicts_answered_by_a_response"] = answered
            detail["verdicts_changed_by_a_response"] = changed
            run.count("verifications.answered", answered)
            run.count("verifications.verdict_changed", changed)

        with run.stage("score") as detail:
            # DAST has no ground-truth corpus, so the confusion matrix stays
            # empty on purpose and the honest measure is how many verdicts a
            # real response answered.
            scored = score_reports(updated, {})
            analyze.atomic_json(WEEK6 / "evaluation" / f"verdict-metrics-{run.run_id}.json", {**scored, "run_id": run.run_id, "tag": args.tag, "ground_truth_source": None})
            for verdict, count in scored["verdict_distribution"].items():
                run.count(f"verdicts.after_probe.{verdict}", count)
            detail["verdict_distribution"] = scored["verdict_distribution"]
            summary["verdicts"] = scored["verdict_distribution"]
            summary["reports"] = scored["reports"]
    except Exception as exc:  # noqa: BLE001 - the metrics file must still be written
        status = "failed"
        summary["failure"] = f"{type(exc).__name__}: {exc}"[:400]
        print(f"[flow] failed: {summary['failure']}", file=sys.stderr)

    metrics = run.finish(status=status, **summary)
    print(f"\n[flow] {status} in {metrics['duration_ms'] / 1000:.1f}s")
    for stage in metrics["stages"]:
        print(f"  {stage['status']:6} {stage['stage']:20} {stage['duration_ms'] / 1000:6.1f}s")
    print(json.dumps(metrics["counters"], ensure_ascii=False, indent=2))
    print(f"[flow] log     -> {run.log_path.relative_to(ROOT)}")
    print(f"[flow] metrics -> {run.metrics_path.relative_to(ROOT)}")
    return 0 if status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
