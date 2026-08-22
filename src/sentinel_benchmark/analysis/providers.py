from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Protocol

import httpx

from sentinel_benchmark.guardrails.redaction import redact_obj


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
    # SSE terminates a line with CRLF, CR or LF — and nothing else. Using
    # splitlines() here would also break on U+2028, which models do emit, and
    # the half after the break would be dropped for not starting with "data:".
    for line in re.split(r"\r\n|\r|\n", response.text):
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
    """A deterministic stand-in so the pipeline runs with no API key.

    It is not an analyst and must not pretend to be one: it never returns
    ``confirmed_vulnerable``, because a fixed rule has read nothing. Metrics
    from a fake run measure the plumbing — schema validity, guard pass rate,
    evidence linkage — and say nothing about analysis quality.
    """

    name = "fake"
    model = "deterministic-evidence-v2"

    def preflight(self) -> dict[str, Any]:
        return {"provider": self.name, "model": self.model, "available": True}

    def analyze(self, *, system_prompt: str, user_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        if "probe_observation" in user_payload:
            return self._verify(user_payload)
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
        observation_id = evidence[0]["observation_id"] if evidence else ""
        kb_id = knowledge[0]["document_id"] if knowledge else ""
        has_excerpt = any(str(item.get("excerpt") or "").strip() for item in evidence)
        if not has_excerpt:
            verdict = "insufficient_evidence"
            rationale = f"Observation {observation_id} carries no readable excerpt, so this deterministic pass cannot judge the flow."
            if not limitations:
                limitations.append("No evidence excerpt was available to analyse.")
        else:
            verdict = "likely_vulnerable"
            rationale = f"Observation {observation_id} reports the weakness at a concrete location, and {kb_id or 'no knowledge document'} describes the same class, but a fixed rule cannot trace the flow, so this stops short of confirmation."
        return {
            "severity_assessment": severity,
            "verdict": verdict,
            "verdict_rationale": rationale,
            "false_positive_indicators": [],
            "explanation": explanation,
            "verification_steps": ["Inspect the reported location and trace untrusted input to the security-sensitive sink.", "Reproduce with a harmless payload in an isolated test environment."],
            "remediation": [remediation_text[:1200]], "limitations": limitations,
            "analysis_confidence": confidence,
        }, {"request_id": None, "model": self.model, "latency_ms": 0, "token_usage": None, "retry_count": 0}

    def _verify(self, user_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        """Deterministic post-probe pass: report what the response shows, keep the verdict.

        A fixed rule may state observable facts, but revising a verdict is a
        judgement call, so this stub declines to make one.
        """
        probe = user_payload["probe_observation"]
        headers = probe.get("response_headers") or {}
        route_id = probe.get("route_id") or ""
        observed = [f"HTTP {probe.get('status')} through route {route_id}."]
        for header in ("content-security-policy", "x-frame-options"):
            observed.append(f"Response header {header} is {'present' if header in headers else 'absent'}.")
        return {
            "verdict": user_payload.get("previous_verdict") or "insufficient_evidence",
            "verdict_rationale": f"Route {route_id} answered and its headers were recorded, but this deterministic pass does not revise a verdict.",
            "observed": observed[:8],
        }, {"request_id": None, "model": self.model, "latency_ms": 0, "token_usage": None, "retry_count": 0}


class NineRouterProvider:
    name = "nine_router"

    def __init__(self, *, base_url: str, model: str, api_key: str, timeout: float = 60, max_retries: int = 1):
        if not api_key:
            raise ValueError("OPENCODE_API_KEY is required")
        if not model:
            raise ValueError("CUSTOM_SCAN_MODEL is required")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries

    @classmethod
    def from_env(cls, *, model_env: str = "CUSTOM_SCAN_MODEL") -> "NineRouterProvider":
        """Build the OpenAI-compatible provider from the OpenCode zen gateway.

        Every outbound LLM call from this class goes to OPENCODE_BASE_URL with
        OPENCODE_API_KEY. Local 9Router variables are not read.

        There is one agent and, by default, one model: ``CUSTOM_SCAN_MODEL``
        serves both the analysis pass and the post-probe verification pass, so a
        change in accuracy is attributable to the pass rather than to the model.
        ``model_env`` exists only to run a deliberate, recorded A/B on one pass;
        it falls back to ``CUSTOM_SCAN_MODEL`` when the named variable is unset.
        """
        api_key = os.getenv("OPENCODE_API_KEY", "")
        model = os.getenv(model_env, "") or os.getenv("CUSTOM_SCAN_MODEL", "")
        base_url = os.getenv("OPENCODE_BASE_URL", "https://opencode.ai/zen/go/v1")
        return cls(
            base_url=base_url,
            model=model,
            api_key=api_key,
            timeout=float(os.getenv("OPENCODE_TIMEOUT_SECONDS") or os.getenv("NINE_ROUTER_TIMEOUT_SECONDS", "60")),
            max_retries=int(os.getenv("OPENCODE_MAX_RETRIES") or os.getenv("NINE_ROUTER_MAX_RETRIES", "1")),
        )

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
        # Redaction sink: mask any sensitive value before it leaves for the LLM.
        safe_payload = redact_obj(user_payload)
        payload = {"model": self.model, "temperature": 0, "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": json.dumps(safe_payload, ensure_ascii=False)}]}
        response = httpx.post(f"{self.base_url}/chat/completions", headers=self._headers, json=payload, timeout=self.timeout)
        response.raise_for_status()
        body = parse_chat_response(response)
        candidate = parse_json_message(body["choices"][0]["message"])
        return candidate, {"request_id": body.get("id"), "model": body.get("model", self.model), "latency_ms": round((time.perf_counter() - started) * 1000), "token_usage": body.get("usage"), "retry_count": 0}


# Compatibility alias: all live LLM calls go through the OpenCode zen gateway.
OpenCodeProvider = NineRouterProvider
