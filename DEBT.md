# Technical debt

- Repoint the existing Streamlit Community Cloud app from the legacy repository to this repository after GitHub authentication is restored.
- Decide and document the exact Week 3 mentor task before freezing `reports/week-3/week-3.md`.
- The historical LLM scanner run is expensive; rerun only when the model, prompt, scanner commit, or selected corpus changes.
- Replace remote Semgrep registry rules with a vendored/pinned rules snapshot if fully offline reproducibility becomes required.
