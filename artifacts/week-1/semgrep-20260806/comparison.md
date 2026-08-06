# Semgrep baseline and A/B results — 20260806T074509Z-semgrep-first100

Semgrep is a non-LLM scanner; token usage is not applicable and is recorded as zero.
Ground truth was joined after scanning from OWASP BenchmarkJava.

| Variant | Findings | TP | FP | FN | TN | Precision | Recall | F1 | Time (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| S1-semgrep-security-audit | 89 | 57 | 4 | 18 | 21 | 93.44% | 76.00% | 83.82% | 16.974 |

## Interpretation

- S0 is the primary Semgrep Java baseline.
- S1 broadens the ruleset to `p/security-audit`.
- S2 unions both rulesets to measure coverage versus noise.
- S3 keeps `p/java` but reports only ERROR severity as a precision-oriented ablation.
