# The request tool: from a finding to a verified fact

A scanner claim is an observation, not a fact. This is the path that turns one
into the other, and the only path out of the agent's process.

    finding (endpoint group)
      -> proposal            src/sentinel_benchmark/probe/proposal.py
      -> human approval      src/sentinel_benchmark/guardrails/approval.py
      -> gateway             vendor/api-gateway (external service, Week 4)
      -> injection scan + redaction + quarantine   probe/runner.py
      -> probe record        artifacts/week-6/probes/

Run it with `scripts/probe.py` once `bash scripts/stack.sh up` is healthy:

    python scripts/probe.py routes            # what the gateway will carry
    python scripts/probe.py plan              # proposals per finding, sends nothing
    python scripts/probe.py run               # ask, send, record
    python scripts/probe.py injection-check   # live guardrail proof

## The tool speaks route ids, not URLs

`GatewayClient` cannot be handed a URL. It fetches the allowlist from
`GET /_gateway/routes` and accepts a `route_id` from that menu; the upstream
addresses never cross into this process. Two consequences worth stating:

- There is no code path to a host the gateway has not published, so "the agent
  probed something it should not have" is not a mistake this design can make.
- A proposal naming an unpublished route fails *before* the approval gate is
  shown anything. Nobody is asked to approve a request that cannot be sent.

Path parameters are restricted to a single safe segment (`[A-Za-z0-9._~-]{1,64}`).
A value containing `/`, `?` or `..` would change which endpoint is addressed,
which is precisely the decision the allowlist exists to make.

## "Cannot verify" is a result

The allowlist is deliberately narrower than the scan surface. In the current
run, 9 of 18 endpoint groups are routable and 9 are not: ZAP alerts on
`/styles.css`, `/socket.io/` and `/ftp/*.bak`, and none of those are in the
allowlist. Those findings must be reported as unverified rather than guessed at.
`propose_for_group` returns `None` for them, and the probe record carries
`decision: not_routable`.

This is why the split is worth keeping: a report that can only say "confirmed"
is not measuring anything.

## Payloads probe input handling; they never attack

`probe/payloads.py` holds the catalogue, and the request tool can send nothing
else - a literal body is not part of the interface. Every value is re-checked
against `FORBIDDEN_PATTERNS` at send time, so a careless edit fails closed.
The ids match the Week 4 request tool's ids, so `payload_id=long-string` means
the same thing in both projects' reports.

The forbidden patterns match the *call shape*, not English words: `system(` is
code execution, "system prompt" is prose. The earlier `\b(exec|eval|system)\b`
rejected the project's own injection fixture, which was a false positive that
would have blocked the guardrail proof below.

Every catalogue payload is an edge case by definition, so a probe carrying one
is marked `special_payload` and, like every other request, requires approval.

## The response is data, and the order of the guardrails matters

`probe/runner.py` applies, in this order:

1. **scan** the original body for injection patterns - before redaction, so
   detection sees the text as it arrived;
2. **redact** to typed placeholders - before anything is stored, logged or put
   in a prompt;
3. **quarantine** the redacted text in `<<UNTRUSTED_DATA ...>>` delimiters,
   carrying a `hazard="injection"` note when step 1 matched.

Reversing 1 and 2 would let redaction erase the evidence that an injection was
attempted. Reversing 2 and 3 would put a real secret inside the delimiters.

Response headers are kept for a short allowlist (`KEPT_HEADERS`) because a
whole class of findings is a statement *about* the headers. This is why the
gateway was changed to forward upstream response headers
(`vendor/api-gateway` commit `af6c49b`): before that, "CSP header missing" was
unverifiable - the tool could not see whether the header was absent at the
target or merely stripped in transit. Header values are redacted too, since a
`Set-Cookie` routinely carries a token.

Transport failures are values, not exceptions. An unreachable gateway or a
timeout sets `transport_error` and leaves `reached_target = False`, so the
report can distinguish "checked and found present" from "could not check".
A gateway-generated 401/403/405/413/429 also leaves `reached_target = False`:
those statuses describe this tool's request, not the target.

## The live guardrail proof

Week 5 proved the filter against a stored file, which proved the filter and
nothing about the wiring. `python scripts/probe.py injection-check` POSTs
`datasets/guardrails/crafted-injection-response.json` to the `echo` route on
the guardrail lab target, so the crafted text arrives as a real HTTP response
over the wire, and then asserts five things:

| check | meaning |
| --- | --- |
| `reached_target` | the gateway proxied it, so the response is really from the target |
| `injection_flagged` | the filter fired on the reflected text |
| `expected_patterns_detected` | every pattern the fixture declares was found |
| `response_quarantined_as_data` | the body is delimited as data, not instructions |
| `no_secret_survived` | no value from `must_not_survive` appears in the record |

Evidence lands in `artifacts/week-6/probes/injection-check-<ts>.json`.

## Known limitations

- **Redaction over-masks.** The PII rule matches any 9- or 12-digit run, so
  build hashes and long numeric ids in an HTML page are masked as
  `[REDACTED_PII]`. Over-masking is the safe direction, but it does reduce the
  technical detail the agent sees in a page body.
- **Repeated response headers arrive comma-joined.** Enough to observe presence
  and flags on a `Set-Cookie`, not enough to reason about several cookies
  separately.
- **The approval prompt shows redacted values.** The human approves the shape
  and intent of a request, not its literal secrets; redaction happens at the
  sink and the sink is upstream of the prompt.
- **Verification is not yet a verdict.** The probe record states what the
  response contained; deciding TP/FP from it is the agent's verdict step and is
  not wired in yet.
