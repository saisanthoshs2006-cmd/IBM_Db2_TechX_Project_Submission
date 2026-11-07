"""Placeholder so the integration layout is collected. It never connects to Db2."""
import pytest

pytestmark = pytest.mark.db2


def test_no_integration_tests_are_approved_yet():
    pytest.skip("no Db2 integration test is approved yet (gate G2)")
