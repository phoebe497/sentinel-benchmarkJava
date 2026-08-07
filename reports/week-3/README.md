# Week 3 — Security Analysis Agent

Machine evidence is stored under `artifacts/week-3/`. Reproduce the deterministic
pipeline with:

```powershell
python scripts/analyze.py baseline
python scripts/analyze.py run --provider fake --limit 99 --tag ci-full
python scripts/analyze.py evaluate --fake-tag ci-full
```

The mentor-facing `week-3.md` is generated only after the real 9Router smoke run
succeeds. Missing provider configuration is reported as incomplete, never
converted into zero findings or a successful run.
