"""The agent's request tool: propose, get approval, send through the gateway.

Nothing in this package can reach a target directly. Egress is the gateway and
the gateway only, addressed by route id, and every send passes the approval
gate first.
"""

from sentinel_benchmark.probe.client import GatewayClient, RawResponse, Route, RouteNotAllowed
from sentinel_benchmark.probe.proposal import ProbeRequest, propose_for_group
from sentinel_benchmark.probe.runner import ProbeResult, run_probe

__all__ = [
    "GatewayClient",
    "ProbeRequest",
    "ProbeResult",
    "RawResponse",
    "Route",
    "RouteNotAllowed",
    "propose_for_group",
    "run_probe",
]
