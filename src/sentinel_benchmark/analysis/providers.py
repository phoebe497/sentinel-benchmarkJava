from __future__ import annotations

import json
import re
import time
from typing import Any, Protocol

import httpx


class Provider(Protocol):
    name: str
    model: str
    def preflight(self) -> dict[str, Any]: ...
    def analyze(self, *, system_prompt: str, user_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]: ...


def parse_json_message(message: dict[str, Any]) -> dict[str, Any]:
    """Parse common OpenAI-compatible content shapes without accepting non-JSON output."""
    content = message.get("content")
    if isinstance(content, list):
        content = "".join(
            str(part.get("text") or part.get("content") or "") if isinstance(part, dict) else str(part)
            for part in content
        )
    if not isinstance(content, str) or not content.strip():
        for key in ("reasoning_content", "reasoning", "analysis"):
            candidate = message.get(key)
            if isinstance(candidate, str) and candidate.strip():
                content = candidate
                break
    text = str(content or "").strip()
    if not text:
        raise ValueError("Provider returned an empty assistant message")
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.IGNORECASE | re.DOTALL)
    if fenced:
        text = fenced.group(1)
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        if start < 0:
            raise ValueError("Provider response did not contain a JSON object")
        try:
            value, _ = json.JSONDecoder().raw_decode(text[start:])
        except json.JSONDecodeError as exc:
            raise ValueError(f"Provider response contained malformed JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ValueError("Provider response JSON must be an object")
    return value


def parse_chat_response(response: httpx.Response) -> dict[str, Any]:
    """Normalize JSON and servers that stream SSE despite stream=false."""
    content_type = response.headers.get("content-type", "").lower()
    if "text/event-stream" not in content_type:
        try:
            body = response.json()
        except json.JSONDecodeError as exc:
            raise ValueError(f"Router returned non-JSON content-type {content_type or 'unknown'}") from exc
        if not isinstance(body, dict):
            raise ValueError("Router response JSON must be an object")
        return body
    content_parts: list[str] = []
    reasoning_parts: list[str] = []
    result: dict[str, Any] = {"id": None, "model": None, "usage": None}
    finish_reason = None
    for line in response.text.splitlines():
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if not data or data == "[DONE]":
            continue
        try:
            event = json.loads(data)
        except json.JSONDecodeError as exc:
            raise ValueError("Router returned malformed SSE JSON") from exc
        result["id"] = event.get("id") or result["id"]
        result["model"] = event.get("model") or result["model"]
        result["usage"] = event.get("usage") or result["usage"]
        choices = event.get("choices") or []
        if not choices:
            continue
        choice = choices[0]
        delta = choice.get("delta") or choice.get("message") or {}
        if isinstance(delta.get("content"), str):
            content_parts.append(delta["content"])
        if isinstance(delta.get("reasoning_content"), str):
            reasoning_parts.append(delta["reasoning_content"])
        finish_reason = choice.get("finish_reason") or finish_reason
    if not content_parts and not reasoning_parts:
        raise ValueError("Router SSE response contained no assistant content")
    result["choices"] = [{"index": 0, "message": {"role": "assistant", "content": "".join(content_parts), "reasoning_content": "".join(reasoning_parts)}, "finish_reason": finish_reason}]
    return result


class FakeProvider:
    name = "fake"
    model = "deterministic-evidence-v1"

    def preflight(self) -> dict[str, Any]:
        return {"provider": self.name, "model": self.model, "available": True}

    def analyze(self, *, system_prompt: str, user_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        evidence = user_payload["scanner_evidence"]
        knowledge = user_payload["knowledge"]
        order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        severity = max((item.get("severity", "info") for item in evidence), key=lambda value: order.get(value, 0), default="info")
        tools = sorted({item["tool"] for item in evidence})
        kb_title = knowledge[0]["title"] if knowledge else "no matching knowledge document"
        explanation = f"Scanner evidence from {', '.join(tools)} contains {len(evidence)} observation(s). The closest repository knowledge is {kb_title}; manual source-to-sink validation is still required."
        remediation_text = knowledge[0]["content"] if knowledge else "Review the source-to-sink flow and apply remediation appropriate to the reported weakness."
        confidence = round(min(0.45 + 0.1 * len(tools) + (0.1 if knowledge else 0) + (0.05 if all(item.get("file_or_url") for item in evidence) else 0), 0.9), 2)
        limitations = []
        if not knowledge:
            limitations.append("No matching knowledge document was retrieved.")
        if any(not item.get("excerpt") for item in evidence):
            limitations.append("At least one scanner observation has no evidence excerpt.")
        return {
            "severity_assessment": severity,
            "explanation": explanation,
            "verification_steps": ["Inspect the reported location and trace untrusted input to the security-sensitive sink.", "Reproduce with a harmless payload in an isolated test environment."],
            "remediation": [remediation_text[:1200]], "limitations": limitations,
            "analysis_confidence": confidence,
        }, {"request_id": None, "model": self.model, "latency_ms": 0, "token_usage": None, "retry_count": 0}


class NineRouterProvider:
    name = "nine_router"

    def __init__(self, *, base_url: str, model: str, api_key: str, timeout: float = 60, max_retries: int = 1):
        if not api_key:
            raise ValueError("NINE_ROUTER_API_KEY is required")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries

    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def preflight(self) -> dict[str, Any]:
        response = httpx.get(f"{self.base_url}/models", headers=self._headers, timeout=self.timeout)
        response.raise_for_status()
        ids = [item.get("id") for item in response.json().get("data", [])]
        if self.model not in ids:
            near = [value for value in ids if value and any(part in value.lower() for part in self.model.lower().split("/")[-1].split("-"))][:10]
            raise ValueError(f"Configured model {self.model!r} is unavailable. Nearby models: {near}")
        return {"provider": self.name, "model": self.model, "available": True, "models_seen": len(ids)}

    def analyze(self, *, system_prompt: str, user_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        started = time.perf_counter()
        payload = {"model": self.model, "temperature": 0, "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)}]}
        response = httpx.post(f"{self.base_url}/chat/completions", headers=self._headers, json=payload, timeout=self.timeout)
        response.raise_for_status()
        body = parse_chat_response(response)
        candidate = parse_json_message(body["choices"][0]["message"])
        return candidate, {"request_id": body.get("id"), "model": body.get("model", self.model), "latency_ms": round((time.perf_counter() - started) * 1000), "token_usage": body.get("usage"), "retry_count": 0}
