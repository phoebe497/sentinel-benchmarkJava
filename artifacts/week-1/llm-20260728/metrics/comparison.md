# Alibaba OpenCodeReview vs Vercel DeepSec/Pi

- Run: `20260728T043417Z-ocr-deepsec-first100`
- Scope: `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java` through `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00100.java`
- Model/router: `gc/gemini-2.5-flash` via 9Router
- Ground truth: OWASP Benchmark expectedresults-1.2.csv, joined after scanning

| Scanner | Files | Findings | Tokens | Seconds | TP | FP | FN | TN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Alibaba OpenCodeReview | 100 | 131 | 1216883 | 2408.000 | 60 | 6 | 15 | 19 | 90.91% | 80.00% |
| Vercel DeepSec | 100 | 152 | 1000842 | 1909.339 | 64 | 10 | 11 | 15 | 86.49% | 85.33% |

A test is positive only when a finding matches that test's expected
OWASP Benchmark vulnerability category. No LLM judge is used.
