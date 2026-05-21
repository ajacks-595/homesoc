"""pytest fixtures: isolate each test in a temp SQLite DB."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add project root to path so tests can import the modules
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def tmp_db(monkeypatch):
    """Each test gets its own fresh SQLite DB."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    monkeypatch.setenv("SOC_DB_PATH", tmp.name)

    # Reset config module state so it picks up the env override
    import importlib
    import config
    importlib.reload(config)
    import database
    importlib.reload(database)
    database.init_db()
    yield tmp.name
    os.unlink(tmp.name)
