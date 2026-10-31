#!/usr/bin/env python3
"""Conformance matrix: which specification clauses and verification findings (F1 to F9) the test suite
covers. Reads the `@spec(...)` markers from tests/conformance without running the tests.

    python tools/conformance_report.py            # print the matrix (markdown)
    python tools/conformance_report.py --check    # exit 1 if any finding F1..F9 has no test
    python tools/conformance_report.py --json     # machine-readable
"""
from __future__ import annotations

import ast
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests" / "conformance"
FINDINGS = {
    "F1": "Injection laundering across hops (taint, provenance, sanitizers, deliveries)",
    "F2": "Hold and resumption (single action hash, discharged causes, timers, re-hold maximum)",
    "F3": "Velocity counters (reserve, release, confirm, reconcile, exposed halving, hard cap)",
    "F4": "Identity and credentials (attested PEP, binding, delegation, substitution, recovery)",
    "F5": "Effects in doubt (replay with the recorded key, resolver outcomes, stops)",
    "F6": "Degradation matrix (EVS, PDP, RUN, IDS, PIP outages; recovery; escalation; OPS close)",
    "F7": "Compensation (mapping over the recorded call, verification, reverse order, failure)",
    "F8": "Registry and release linter (derived fields, caps, anchoring, resumption path, suspension)",
    "F9": "Bounds and node-type matrix at run time (declaration, denials, caps, deliveries, spawns)",
}


def collect() -> list[dict]:
    out: list[dict] = []
    for path in sorted(TESTS.glob("test_*.py")):
        tree = ast.parse(path.read_text())
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
                continue
            for deco in node.decorator_list:
                if isinstance(deco, ast.Call) and getattr(deco.func, "id", None) == "spec":
                    clauses = [ast.literal_eval(a) for a in deco.args]
                    finding = None
                    for kw in deco.keywords:
                        if kw.arg == "finding":
                            finding = ast.literal_eval(kw.value)
                    out.append({"file": path.name, "test": node.name, "clauses": clauses, "finding": finding})
    return out


def main(argv: list[str]) -> int:
    rows = collect()
    by_finding: dict[str, list[dict]] = defaultdict(list)
    by_clause: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        if r["finding"]:
            by_finding[r["finding"]].append(r)
        for c in r["clauses"]:
            by_clause[c].append(r["test"])
    missing = [f for f in FINDINGS if not by_finding.get(f)]
    if "--json" in argv:
        print(json.dumps({"tests": rows, "by_finding": {k: len(v) for k, v in by_finding.items()},
                          "by_clause": {k: len(v) for k, v in sorted(by_clause.items())}, "missing": missing}, indent=2))
    else:
        print("# Conformance matrix\n")
        print(f"{len(rows)} marked tests in {len({r['file'] for r in rows})} files.\n")
        print("| Finding | Covered by | Tests |\n|---|---|---|")
        for f, desc in FINDINGS.items():
            n = len(by_finding.get(f, []))
            print(f"| {f} | {desc} | {n if n else '**none**'} |")
        print("\n| Spec clause | Tests |\n|---|---|")
        for c, tests in sorted(by_clause.items(), key=lambda kv: (len(kv[0].split('.')[0]) > 1 and kv[0][0].isalpha(), kv[0])):
            print(f"| {c} | {len(tests)} |")
        if missing:
            print(f"\nUncovered findings: {', '.join(missing)}")
    if "--check" in argv and missing:
        print(f"conformance check failed: no test covers {', '.join(missing)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
