"""FastAPI entrypoint for the Sentinel design-system UI."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.web import catalog

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
    rows = catalog.approval_queue()
    return {
        "items": rows,
        "counts": {
            "Pending": sum(1 for row in rows if row["status"] == "Pending"),
            "Approved": sum(1 for row in rows if row["status"] == "Approved"),
            "Rejected": sum(1 for row in rows if row["status"] == "Rejected"),
        },
    }


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
