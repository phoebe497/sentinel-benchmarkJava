# Repository instructions

- Active security dataset is OWASP BenchmarkJava only; do not re-introduce WebGoat.
- Keep product code in `src/`, test code in `tests/`, machine-readable output in `artifacts/`, and human reports in `reports/`.
- Treat a submitted `reports/week-N/week-N.md` as immutable. Add corrections as a dated appendix instead of rewriting history.
- Never deploy the intentionally vulnerable BenchmarkJava application publicly.
- Never commit tokens, `.env`, local SQLite databases, scanner caches, or absolute local paths in newly generated artifacts.
- Scanner failure or incomplete coverage is not equivalent to zero findings.
- Run `python -m pytest -q` before committing code changes.
