# Technical debt

- Confirm anonymous access in Streamlit Community Cloud before sending the demo to the mentor. The new deployment is available at `https://sentinel-benchmarkjava.streamlit.app/`, but an unauthenticated HTTP check on 2026-08-06 was redirected to Streamlit login.
- Decide and document the exact Week 3 mentor task before freezing `reports/week-3/week-3.md`.
- The historical LLM scanner run is expensive; rerun only when the model, prompt, scanner commit, or selected corpus changes.
- Replace remote Semgrep registry rules with a vendored/pinned rules snapshot if fully offline reproducibility becomes required.
