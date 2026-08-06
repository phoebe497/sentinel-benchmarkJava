# Project instructions

## 1. Project mission

This repository tracks one security research project from Week 1 through
Week 6.

The active evaluation corpus is the first 100 OWASP BenchmarkJava test
cases. WebGoat is not part of the active dataset.

The project must preserve a reproducible path from:

Benchmark source
→ scanner output
→ normalized findings
→ metrics
→ knowledge base
→ Streamlit demo
→ weekly report

## 2. Repository structure

- `src/`: reusable application and data-processing code.
- `app/`: Streamlit entrypoint.
- `vendor/BenchmarkJava/`: pinned upstream Git submodule.
- `datasets/`: input manifests and knowledge documents.
- `tests/`: automated tests.
- `scripts/security/`: scanner and evaluation harnesses.
- `artifacts/week-N/`: machine-readable raw output, logs and metrics.
- `reports/week-N/`: short mentor-facing weekly reports.
- `docs/`: methodology, architecture and review guidance.

Do not create separate copies of shared source code for each week.

## 3. Benchmark integrity

- Keep BenchmarkJava pinned to the commit declared in the dataset manifest.
- Week 1 compatibility scope is:
  `BenchmarkTest00001.java` through `BenchmarkTest00100.java`.
- Do not send the ground-truth CSV or Benchmark metadata to a scanner.
- Join ground truth only after scanning has finished.
- Do not change the sample, ruleset, model or scanner version without
  recording the change in the run manifest.
- Never interpret scanner failure or incomplete coverage as zero findings.

## 4. Data rules

- Raw scanner output belongs in `artifacts/`, not `reports/`.
- Generated SQLite databases and caches must not be committed.
- Every normalized finding must retain:
  `dataset`, `tool`, `run_id`, `source_artifact` and `observation_id`.
- Do not manually edit generated metrics to make reports look better.
- Report numbers must be traceable to committed JSON or JSONL evidence.
- Never reintroduce WebGoat into the active manifest or Streamlit index.

## 5. Security rules

- BenchmarkJava intentionally contains vulnerable code.
- Never deploy the BenchmarkJava web application to a public environment.
- The public Streamlit app may expose findings and aggregate metrics only.
- Never commit tokens, `.env` files, credentials or private endpoints.
- Do not include absolute local paths in newly published artifacts.
- Treat scanner output as unverified observations until validated.

## 6. Reports

- Keep each weekly report close to one A4 page.
- Clearly separate `Quá trình` from `Kết quả`.
- Use natural Vietnamese suitable for presenting to a mentor.
- Preserve exact technical terms only where they improve accuracy.
- After a weekly report is submitted, treat it as immutable.
- Add a dated appendix for corrections instead of rewriting submitted history.
- Do not claim that a demo, CI run or scan succeeded without verifying it.

## 7. Required verification

For Python or data-pipeline changes:

    python -m pytest -q

For index or source-manifest changes:

    python -m sentinel_benchmark.indexer
    python -m pytest -q

For Streamlit changes:

    streamlit run app/streamlit_app.py

Then verify:

- the health endpoint responds;
- the UI loads;
- `CWE-89` returns BenchmarkJava findings;
- displayed counts match the generated SQLite index.

For CI or Semgrep changes:

- verify the GitHub Actions workflow completes;
- verify SARIF is uploaded;
- verify alerts appear under GitHub Security → Code scanning.

## 8. Definition of done

A task is complete only when:

- implementation is in the correct folder;
- tests pass;
- generated evidence is stored in the correct artifact folder;
- reported numbers match machine-readable evidence;
- relevant documentation is updated;
- the working tree contains no accidental cache, database or secret files.

If the task or weekly deliverable is unclear, inspect the existing reports and
ask for the mentor requirement instead of inventing project scope.