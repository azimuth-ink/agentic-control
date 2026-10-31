"""Shared fixtures and the `spec` marker that ties each test to specification clauses and to the
verification findings (F1 to F9) it reproduces. `tools/conformance_report.py` reads the markers."""
from __future__ import annotations

import pytest


def spec(*clauses: str, finding: str | None = None):
    """Usage: @spec("A.3", "5.4", finding="F1")."""
    def deco(fn):
        fn.spec_clauses = clauses
        fn.spec_finding = finding
        return pytest.mark.spec(clauses=clauses, finding=finding)(fn)
    return deco


def pytest_configure(config):
    config.addinivalue_line("markers", "spec(clauses, finding): specification clauses and verification finding a test covers")


@pytest.fixture
def scenario():
    from warranty import build_scenario
    return build_scenario()


def types(sc, run):
    return [e["type"] for e in sc.events(run)]


def events(sc, run, kind, node=None):
    return [e for e in sc.events(run) if e["type"] == kind and (node is None or e.get("node_id") == node)]


def decisions(sc, run, node, purpose="normal"):
    """Decision events of one node for one purpose (a hold's preview writes its own decision event)."""
    return [e for e in events(sc, run, "decision", node) if e["purpose"] == purpose]


def last_decision(sc, run, node, purpose="normal"):
    return decisions(sc, run, node, purpose)[-1]
