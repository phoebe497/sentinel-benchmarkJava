"""The only way out of this process: an HTTP client that speaks route ids.

The client knows the gateway address and nothing else. It cannot be handed a
URL, so there is no code path that reaches a host the gateway has not published
in its allowlist, and the upstream addresses stay unknown to this side. A
proposal naming a route the gateway does not publish fails here, before the
approval gate is even shown a request (AGENTS.md 7).

Transport failures are values, not exceptions: an unreachable gateway or a
timeout is an observation about the target and must reach the report, not
abort the run.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from sentinel_benchmark.probe.payloads import is_forbidden

# How much of a response body is kept. Enough to inspect a JSON document or an
# HTML head, bounded so one large page cannot dominate a prompt or a log.
MAX_BODY_CHARS = 8000

# Path parameter values are restricted to this shape. A value containing "/",
# "?" or ".." would change which endpoint is addressed, which is exactly the
# decision the allowlist exists to make.
_SAFE_PARAM = re.compile(r"^[A-Za-z0-9._~-]{1,64}$")


class RouteNotAllowed(ValueError):
    """The proposed route id is not in the allowlist the gateway publishes."""


@dataclass(frozen=True)
class Route:
    id: str
    method: str
    path: str

    @property
    def parameters(self) -> tuple[str, ...]:
        return tuple(re.findall(r"\{([^}]+)\}", self.path))

    def fill(self, params: dict[str, str] | None = None) -> str:
        """Substitute the ``{name}`` placeholders, refusing anything unsafe."""
        supplied = dict(params or {})
        expected = set(self.parameters)
        missing = expected - set(supplied)
        if missing:
            raise ValueError(f"route {self.id!r} needs path parameters {sorted(missing)}")
        unknown = set(supplied) - expected
        if unknown:
            raise ValueError(f"route {self.id!r} has no path parameters {sorted(unknown)}")
        path = self.path
        for name, value in supplied.items():
            text = str(value)
            if not _SAFE_PARAM.match(text):
                raise ValueError(f"path parameter {name}={text!r} is not a single safe path segment")
            path = path.replace("{" + name + "}", text)
        return path


@dataclass
class RawResponse:
    """What came back. ``error`` is set instead of ``status`` on transport failure."""

    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_truncated_by_tool: bool = False
    truncated_by_gateway: bool = False
    gateway_route: str | None = None
    elapsed_ms: int = 0
    error: str | None = None

    @property
    def reached_target(self) -> bool:
        """True when the gateway proxied upstream, rather than refusing or failing.

        The gateway answers 401/403/405/413/429 itself, so those statuses say
        something about this tool's request and nothing about the target.
        """
        return self.error is None and self.gateway_route is not None


class GatewayClient:
    def __init__(self, *, base_url: str, api_key: str, timeout: float = 15.0) -> None:
        if not base_url:
            raise ValueError("SENTINEL_GATEWAY_URL is required")
        if not api_key:
            raise ValueError("SENTINEL_GATEWAY_API_KEY is required")
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self.timeout = timeout
        self._routes: dict[str, Route] | None = None

    @classmethod
    def from_env(cls) -> "GatewayClient":
        return cls(
            base_url=os.getenv("SENTINEL_GATEWAY_URL", "http://localhost:8080"),
            api_key=os.getenv("SENTINEL_GATEWAY_API_KEY", ""),
            timeout=float(os.getenv("SENTINEL_GATEWAY_TIMEOUT_SECONDS", "15")),
        )

    @property
    def _headers(self) -> dict[str, str]:
        return {"X-API-Key": self._api_key}

    def routes(self, *, refresh: bool = False) -> dict[str, Route]:
        """The published allowlist, keyed by route id. Fetched once per client."""
        if self._routes is None or refresh:
            response = httpx.get(f"{self.base_url}/_gateway/routes", headers=self._headers, timeout=self.timeout)
            response.raise_for_status()
            self._routes = {
                str(item["id"]): Route(id=str(item["id"]), method=str(item["method"]).upper(), path=str(item["path"]))
                for item in response.json().get("routes", [])
            }
        return self._routes

    def route(self, route_id: str) -> Route:
        routes = self.routes()
        if route_id not in routes:
            raise RouteNotAllowed(f"route {route_id!r} is not in the published allowlist; available: {sorted(routes)}")
        return routes[route_id]

    def send(
        self,
        route_id: str,
        *,
        path_params: dict[str, str] | None = None,
        query: dict[str, Any] | None = None,
        body: Any = None,
    ) -> RawResponse:
        """Send one request through the gateway. Callers must gate this first.

        This method does not ask for approval: the gate is a separate object so
        that it cannot be satisfied by the same code that wants to send.
        :func:`sentinel_benchmark.probe.runner.run_probe` is the guarded path.
        """
        route = self.route(route_id)
        for value in (query or {}).values():
            offending = is_forbidden(value)
            if offending is not None:
                raise ValueError(f"query value matches forbidden pattern {offending!r}")
        if body is not None:
            offending = is_forbidden(body)
            if offending is not None:
                raise ValueError(f"request body matches forbidden pattern {offending!r}")
        url = f"{self.base_url}{route.fill(path_params)}"
        started = time.perf_counter()
        try:
            response = httpx.request(
                route.method,
                url,
                headers=self._headers,
                params={key: str(value) for key, value in (query or {}).items()},
                json=body if route.method in {"POST", "PUT", "PATCH"} else None,
                timeout=self.timeout,
            )
        except httpx.TimeoutException:
            return RawResponse(error="gateway_timeout", elapsed_ms=round((time.perf_counter() - started) * 1000))
        except httpx.RequestError as exc:
            return RawResponse(error=f"gateway_unreachable: {type(exc).__name__}", elapsed_ms=round((time.perf_counter() - started) * 1000))
        text = response.text
        return RawResponse(
            status=response.status_code,
            headers={key.lower(): value for key, value in response.headers.items()},
            body=text[:MAX_BODY_CHARS],
            body_truncated_by_tool=len(text) > MAX_BODY_CHARS,
            truncated_by_gateway=response.headers.get("x-truncated") == "true",
            gateway_route=response.headers.get("x-gateway-route"),
            elapsed_ms=round((time.perf_counter() - started) * 1000),
        )
