"""FastAPI entrypoint for the Sentinel design-system UI."""

from __future__ import annotations

from pathlib import Path

import csv
import io
import json

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from app.web import catalog
from app.web import gateway_lab

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")

STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Sentinel", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinel-ui"}


@app.get("/api/overview")
def api_overview() -> dict:
    return catalog.overview()


@app.get("/api/sast")
def api_sast() -> dict:
    return catalog.sast_payload()


@app.get("/api/dast")
def api_dast() -> dict:
    return catalog.dast_payload()


@app.get("/api/agent")
def api_agent(finding_id: str | None = Query(default=None)) -> dict:
    return catalog.agent_payload(finding_id)


@app.post("/api/agent/chat")
def api_agent_chat(payload: dict) -> dict:
    question = str(payload.get("question") or "")
    finding_id = str(payload.get("finding_id") or "")
    try:
        return catalog.answer_finding(finding_id, question)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown finding") from exc


@app.get("/api/approval")
def api_approval() -> dict:
    return catalog.approval_payload()


@app.get("/api/gateway")
def api_gateway() -> dict:
    return gateway_lab.gateway_payload()


@app.post("/api/gateway/probe")
def api_gateway_probe(payload: dict) -> dict:
    return gateway_lab.run_sandbox(payload or {})


@app.post("/api/gateway/analyze")
def api_gateway_analyze(payload: dict) -> dict:
    return gateway_lab.analyze_sandbox(payload.get("result") or payload or {})


@app.post("/api/approval/{request_id}")
def api_decide(request_id: str, payload: dict) -> dict:
    approved = bool(payload.get("approved"))
    try:
        return catalog.decide_request(request_id, approved)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown request") from exc


@app.get("/api/reports")
def api_reports() -> dict:
    return catalog.reports_payload()


@app.get("/api/knowledge")
def api_knowledge() -> dict:
    return catalog.knowledge_payload()


@app.get("/api/search")
def api_search(q: str = "") -> dict:
    return {"results": catalog.workspace_search(q)}


@app.get("/api/export/{kind}")
def api_export(kind: str, format: str = "json") -> Response:
    try:
        bundle = catalog.export_bundle(kind)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown export") from exc
    filename = f"sentinel-{kind}"
    if format == "csv":
        rows = bundle.get("findings") or bundle.get("summary") or [bundle.get("kpis") or {}]
        output = io.StringIO()
        fieldnames = list(rows[0].keys()) if rows else ["value"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: "" if value is None else value for key, value in row.items() if key in fieldnames})
        return Response(
            output.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'},
        )
    return Response(
        json.dumps(bundle, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}.json"'},
    )


@app.get("/api/source/{finding_id}")
def api_source(finding_id: str) -> dict:
    try:
        return catalog.source_for_finding(finding_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown finding") from exc


@app.get("/")
@app.get("/{page}")
def index(page: str = "overview") -> FileResponse:
    del page
    return FileResponse(STATIC / "index.html")
