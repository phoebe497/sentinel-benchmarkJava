from __future__ import annotations

import uuid
from pathlib import Path

import pytest


@pytest.fixture
def tmp_path() -> Path:
    """Workspace-local temp path for restricted Windows test environments."""
    root = Path(__file__).resolve().parents[1] / "artifacts" / "ci" / "pytest"
    path = root / uuid.uuid4().hex
    path.mkdir(parents=True)
    return path
