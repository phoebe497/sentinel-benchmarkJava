from app.web.catalog import approval_payload
from app.web.catalog import approval_payload
from app.web.gateway_lab import gateway_payload, run_sandbox
from app.web.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def _isolate_live_log(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("SENTINEL_UI_LIVE_LOG", str(tmp_path / "ui-live-probe.jsonl"))


def test_gateway_payload_reads_the_committed_policy() -> None:
    payload = gateway_payload()
    assert payload["limits"]["allowed_routes"] >= 20
    assert payload["limits"]["rate_limit"] == "30 req/min"
    assert payload["limits"]["timeout"] == "5 s"
    assert payload["limits"]["max_body"] == "256 KB"
    ids = {row["id"] for row in payload["routes"]}
    assert {"health", "slow", "js-login", "js-product-search"} <= ids
    assert any(row["path"] == "/api/Users" for row in payload["deny_list"])
    assert {row["id"] for row in payload["scenarios"]} >= {"health", "sqli", "overload", "bad-key"}


def test_sqli_scenario_is_refused_and_not_sent(monkeypatch, tmp_path) -> None:
    _isolate_live_log(monkeypatch, tmp_path)
    result = run_sandbox(
        {
            "route_id": "js-product-search",
            "purpose": "SQLi attempt",
            "query": {"q": "' OR 1=1--"},
        }
    )
    assert result["sent"] is False
    assert result["status"] == 403
    assert result["mode"] == "policy"
    assert any(row["name"] == "Payload Safety" and row["result"] == "Fail" for row in result["checks"])


def test_unknown_route_is_denied(monkeypatch, tmp_path) -> None:
    _isolate_live_log(monkeypatch, tmp_path)
    result = run_sandbox({"route_id": "not-published", "purpose": "deny"})
    assert result["sent"] is False
    assert result["status"] == 403
    assert any(row["result"] == "Deny" for row in result["checks"])


def test_mutating_probe_requires_approve(monkeypatch, tmp_path) -> None:
    _isolate_live_log(monkeypatch, tmp_path)
    result = run_sandbox(
        {
            "route_id": "js-login",
            "purpose": "login",
            "body": {"email": "demo", "password": "demo"},
            "approved": False,
        }
    )
    assert result["sent"] is False
    assert result["mode"] == "needs_approval"


def test_readonly_ui_does_not_send_an_allowlisted_get(monkeypatch, tmp_path) -> None:
    _isolate_live_log(monkeypatch, tmp_path)
    monkeypatch.setenv("SENTINEL_UI_READONLY", "1")
    monkeypatch.setenv("SENTINEL_GATEWAY_URL", "https://example.invalid")
    monkeypatch.delenv("SENTINEL_GATEWAY_SANDBOX", raising=False)
    result = run_sandbox({"route_id": "health", "purpose": "health", "scenario": "health"})
    assert result["sent"] is False
    assert result["mode"] == "readonly"
    assert result["status_label"] == "Not sent"
    assert result["expected"] == "200 OK"


def test_gateway_api_is_mounted(monkeypatch, tmp_path) -> None:
    _isolate_live_log(monkeypatch, tmp_path)
    response = client.get("/api/gateway")
    assert response.status_code == 200
    body = response.json()
    assert body["routes"]
    probe = client.post("/api/gateway/probe", json={"route_id": "not-published", "purpose": "deny"})
    assert probe.status_code == 200
    assert probe.json()["sent"] is False


def test_playground_probe_appears_on_approval_tabs(monkeypatch, tmp_path) -> None:
    _isolate_live_log(monkeypatch, tmp_path)
    before = approval_payload()["counts"]["Approved"]
    result = run_sandbox({"route_id": "health", "purpose": "health", "scenario": "health", "method": "GET"})
    assert result["request_id"].startswith("REQ-LIVE-")
    after = approval_payload()
    assert after["counts"]["Approved"] == before + 1
    live = next(row for row in after["items"] if row["id"] == result["request_id"])
    assert live["source"] == "ui-gateway"
    assert live["route_id"] == "health"
    assert any(row["request_id"] == result["request_id"] for row in after["history"])
