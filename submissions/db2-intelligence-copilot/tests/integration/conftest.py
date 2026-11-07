"""Integration tests against a real Db2 database: opt-in only.

Every test collected here must carry the `db2` marker. They are skipped unless DB2INTEL_IT=1 is
set. No integration test is approved yet: the first ones belong to gate G2 and need their own
approval, so the placeholder below skips even when DB2INTEL_IT=1.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

IT_ENV = "DB2INTEL_IT"
_HERE = Path(__file__).resolve().parent


def integration_enabled(environ=None) -> bool:
    return (os.environ if environ is None else environ).get(IT_ENV) == "1"


def pytest_collection_modifyitems(config, items):
    enabled = integration_enabled()
    skip = pytest.mark.skip(reason=f"integration tests need a real Db2; set {IT_ENV}=1 to run them")
    for item in items:
        if _HERE not in Path(str(item.fspath)).resolve().parents:
            continue
        if item.get_closest_marker("db2") is None:
            raise pytest.UsageError(f"{item.nodeid}: tests under tests/integration must be marked @pytest.mark.db2")
        if not enabled:
            item.add_marker(skip)
