"""Railway entrypoint so Railpack can detect and start the Sentinel UI."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from app.web.main import app
from fastapi import FastAPI

assert isinstance(app, FastAPI)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
