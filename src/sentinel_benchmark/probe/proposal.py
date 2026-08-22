"""Turn a finding into a request the gateway is willing to carry.

A proposal is derived from the finding's endpoint and matched against the
published allowlist, so the agent chooses among ids that already exist instead
of composing a URL. When nothing matches, that is a result too: the finding is
un-probeable and must be reported as "cannot verify" rather than guessed at.
The allowlist is deliberately narrower than the scan surface, so this refusal
happens on real findings in every run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any

from sentinel_benchmark.analysis.models import EndpointGroup
from sentinel_benchmark.guardrails.approval import ProposedRequest
from sentinel_benchmark.probe.client import Route
from sentinel_benchmark.probe.payloads import get as get_payload

# A concrete, harmless value for each path placeholder the allowlist uses.
SAMPLE_PATH_PARAMS = {"id": "1", "code": "200"}

# What a probe of this category is actually checking, in plain language, so the
# human at the approval gate reads intent instead of inferring it from a URL.
_PURPOSE = {
    "missing_security_control": "read the response headers to check whether the security header the scanner reported as missing is really absent",
    "information_disclosure": "read the response body to check whether it really exposes the internal detail the scanner reported",
    "clickjacking": "read the framing headers to check whether the page can really be embedded",
    "access_control_misconfiguration": "read the response to check whether this endpoint really answers without authentication",
}


@dataclass(frozen=True)
class ProbeRequest:
    """A concrete, allowlisted request awaiting human approval."""

    route_id: str
    purpose: str
    path_params: dict[str, str] = field(default_factory=dict)
    query: dict[str, Any] = field(default_factory=dict)
    payload_id: str | None = None
    # Where the catalogue payload goes: a query parameter name, or None for the
    # request body.
    payload_param: str | None = None
    # Every finding this one response can speak to. Three alerts on the same
    # endpoint are answered by one GET, so asking a human three times for the
    # same request would be noise, not diligence.
    analysis_group_ids: tuple[str, ...] = ()

    @property
    def is_special(self) -> bool:
        """A catalogue payload is an edge case by construction (AGENTS.md 6.2)."""
        return self.payload_id is not None

    def materialize(self) -> tuple[dict[str, Any], Any]:
        """Resolve the payload id into the concrete query and body to send."""
        query: dict[str, Any] = dict(self.query)
        body: Any = None
        if self.payload_id is None:
            return query, body
        value = get_payload(self.payload_id)
        if self.payload_param is None:
            return query, value
        if isinstance(value, (dict, list)):
            raise ValueError(f"payload {self.payload_id!r} is structured and cannot go in query parameter {self.payload_param!r}")
        query[self.payload_param] = value
        return query, body

    def for_approval(self, route: Route) -> ProposedRequest:
        """The exact endpoint, payload and purpose the gate must show a human."""
        query, body = self.materialize()
        endpoint = route.fill(self.path_params)
        if query:
            endpoint = f"{endpoint}?" + "&".join(f"{key}={value}" for key, value in query.items())
        return ProposedRequest(
            endpoint=f"{self.route_id} {endpoint}",
            method=route.method,
            payload=body if body is not None else (query or None),
            purpose=self.purpose,
        )


def bind(route: Route, endpoint: str) -> dict[str, str] | None:
    """Bind a concrete endpoint to a route template, or None if it does not fit.

    A scanner reports the URL it actually requested — ``/api/Products/1`` — while
    the allowlist publishes a template — ``/api/Products/{id}``. Without this
    step every parameterised route is dead weight: no finding endpoint is ever
    literally the template, so none would match.

    The captured segment uses the same character class the client enforces, so a
    value that would change *which* endpoint is addressed (containing ``/``,
    ``?`` or ``..``) cannot bind here.
    """
    pattern = "".join(
        f"(?P<{part[1:-1]}>[A-Za-z0-9._~-]{{1,64}})" if part.startswith("{") and part.endswith("}") else re.escape(part)
        for part in re.split(r"(\{[^}]+\})", route.path)
    )
    # The gateway strips a trailing slash when it loads the policy, while a
    # scanner reports the URL as it requested it (`/socket.io/`). Treating those
    # as different endpoints would lose the match without making anything safer,
    # since the endpoint addressed is the same one either way.
    match = re.fullmatch(pattern, endpoint) or re.fullmatch(pattern, endpoint.rstrip("/") or "/")
    return match.groupdict() if match else None


def propose_for_group(group: EndpointGroup, routes: dict[str, Route]) -> ProbeRequest | None:
    """The read-only probe that would verify this finding, or None if unroutable.

    Exact routes are tried before templates, so a finding on ``/ftp`` uses the
    listing route rather than binding ``ftp`` into a wildcard.
    """
    ordered = sorted(routes.values(), key=lambda route: (len(route.parameters), route.id))
    for route in ordered:
        if route.method != "GET":
            continue
        params = bind(route, group.endpoint)
        if params is None:
            # The finding may name the template itself rather than a concrete
            # URL; then a harmless sample value stands in.
            if route.path != group.endpoint:
                continue
            params = {name: SAMPLE_PATH_PARAMS[name] for name in route.parameters if name in SAMPLE_PATH_PARAMS}
            if len(params) != len(route.parameters):
                continue
        reported = ", ".join(group.reported_cwes) or "an uncategorized issue"
        purpose = _PURPOSE.get(group.category, "read the response to check whether the reported issue is really present")
        return ProbeRequest(
            route_id=route.id,
            purpose=f"The scanner reported {reported} on {group.endpoint}; {purpose}.",
            path_params=params,
            analysis_group_ids=(group.analysis_group_id,),
        )
    return None


def merge_by_route(requests: list[ProbeRequest]) -> list[ProbeRequest]:
    """Collapse proposals that would send the identical request.

    The merged request covers every finding the response can inform, so one
    approval decision buys one response and answers all of them.
    """
    merged: dict[tuple[Any, ...], ProbeRequest] = {}
    for request in requests:
        key = (
            request.route_id,
            tuple(sorted(request.path_params.items())),
            tuple(sorted(request.query.items())),
            request.payload_id,
            request.payload_param,
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = request
            continue
        merged[key] = replace(existing, analysis_group_ids=tuple(dict.fromkeys(existing.analysis_group_ids + request.analysis_group_ids)))
    return list(merged.values())
