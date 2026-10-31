#!/usr/bin/env python3
"""Regenerates docs/spec-map.md: specification clause → module → conformance tests (from the @spec markers)."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MODULES = {
    "1": "all components; I1 `enforcement._credential` (only the PEP presents), I2 `policy._intersection`, I3 `enforcement._decision_event` before `_execute`, I5 `identity._identity_current`, I8 by construction (OPS/REG/IDS are separate objects; people act through OPS with identity-provider assertions)",
    "3.9": "`registry.unregister_tool`, `enforcement._check_live_schema`",
    "3.10": "`policy._decide_compensation`, `enforcement._compensate`, `policy.apply_mapping`, `coordinator.instruct_compensation`",
    "4.1": "`enforcement._apply_read_result`, `enforcement.call` step caps, `runtime._loop`, `gateway.ModelGateway` budgets",
    "4.2": "`enforcement._deliver`, `policy` delivery rule, `coordinator.start_run` (console sessions), `coordinator.checkpoint` branch validation",
    "4.3": "`release.anchored_params`, `registry.lint_release` anchoring rule, `registry.relation_capable`, `policy._bounds`",
    "4.4": "`coordinator.hold/approve/deny/rehold`, `identity.mint_resumption_grant/redeem_resumption_grant/credential_for_approved_action`, `enforcement._resume/_resume_credential/_revoked_at_redemption`, `policy._approver_set`",
    "4.5": "`coordinator.node_entered/checkpoint/heartbeat`, `enforcement.enter_node/exit_node/_resolve`, `coordinator.spawn`",
    "4.6": "`coordinator.reserve/release/confirm/reconcile_counters`, `coordinator.in_doubt/resolve_in_doubt/record_outcome`, `enforcement._replay`",
    "4.7": "`enforcement._spawn`, `coordinator.spawn`, `identity.exchange_child`, `warranty._wire_child`",
    "4.8": "`coordinator._park/recover/tick/owner_*/ops_close`, `coordinator.runtime_error`",
    "4.9": "`gateway.Operations.issue_stop/lift_stop`, `coordinator.apply_stop/stop_refusal/stop_in_scope`, `enforcement._stopped/_stop_refusal`, `policy` stop-scope rule",
    "5.1": "`coordinator.start_run` payload trust, `enforcement._apply_read_result` (reads and effect results), `coordinator.provide_input`, `enforcement._spawn` child taint, `dbs.System._item_tainted`",
    "5.2": "`coordinator.update_run_state`, `policy` exposed velocity factor, `dbs.System.write_record` tags",
    "5.3": "`enforcement._sanitize/_provenance/_accepted`, `registry.Sanitizer.value_fits/qualifies_for_sanitized_provenance`, `dbs.identifier_numeric_extractor/rendering_sanitizer`",
    "5.4": "`policy._bounds` (Tainted), `warranty.WarrantyPIP.relation`",
    "6.1": "`enforcement._effect` degradation gate, `enforcement._local_decide`, `enforcement._write` journal path, `enforcement._manifest` cache, `coordinator.recover`, `platform.outage`",
    "6.2": "`enforcement._no_factor`",
    "6.3": "`identity.vault_recovery_identity/release_recovery_identity`, `gateway.Operations.recovery`",
    "7": "`registry.TIER_CAPS`, `registry.lint_release` tier cap rule, S1 hook writers in `coordinator.node_entered/checkpoint`, `evidence.import_external`",
    "8": "`examples/warranty/scenario.py`",
    "A.1": "`registry.py`", "A.2": "`evidence.py`, `identity.py` grants", "A.3": "`policy.py`", "A.4": "`enforcement.py`",
    "A.5": "`coordinator.py`", "A.6": "`identity.py`", "A.7": "`dbs.py`", "A.8": "`gateway.ModelGateway`", "A.9": "`gateway.Operations`",
    "B.1": "`coordinator.py` transitions", "B.2": "`coordinator.resolver_*`, `gateway.Operations`", "D": "`events.py`",
    "I1": "`enforcement._credential`, `dbs.System._accept`", "I2": "`policy._intersection`", "I5": "`identity.issue_agent_identity/_identity_current`",
    "I8": "`coordinator._person`, `gateway.Operations`",
    "ADR-25": "`registry.register_tool` (`none` refused for an external target or an outward-resolving destination role)",
    "ADR-26": "`registry.register_system` (DBS kinds and `provenance_tag` only inside the boundary)",
}


def key(c: str):
    m = re.match(r"^(\d+)(?:\.(\d+))?$", c)
    if m:
        return (0, int(m.group(1)), int(m.group(2) or 0), c)
    if c[0] in "ABCD" and (len(c) == 1 or c[1] == "."):
        return (1, 0, 0, c)
    return (2, 0, 0, c)


def main() -> int:
    data = json.loads(subprocess.check_output([sys.executable, str(ROOT / "tools" / "conformance_report.py"), "--json"], text=True))
    by_clause: dict[str, list[str]] = {}
    for t in data["tests"]:
        for c in t["clauses"]:
            by_clause.setdefault(c, []).append(f'`{t["file"]}::{t["test"]}`')
    lines = ["# Specification → code → tests", "",
             "One row per specification clause the suite marks. The *module* column names where the clause is implemented; the *tests* column lists the conformance tests that exercise it (from the `@spec` markers). Regenerate with `python tools/spec_map.py`; `docs/conformance-matrix.md` with `python tools/conformance_report.py`.", "",
             "Clause numbers are those of the v1.0 publication text (sections 0–11, appendices A–D). `ADR-n` refers to the design rationale.", "",
             "| Clause | Module | Tests |", "|---|---|---|"]
    for c in sorted(set(by_clause) | set(MODULES), key=key):
        lines.append(f"| {c} | {MODULES.get(c, '—')} | {'<br>'.join(by_clause.get(c, ['—']))} |")
    lines += ["", "## Clauses without a dedicated test", "",
              "- **2 Components**: wiring only (`platform.build_platform`).",
              "- **6.2 availability objectives, latency budgets**: deployment content; nothing to test in-process.",
              "- **9 Residual register**, **10 Verification record**, **11 Cite**: text.",
              "- **Appendix C hosting**: `platform.Platform.pep` attests a build hash (`identity.allow_build/bind_workload`); the attestation itself is simulated."]
    (ROOT / "docs" / "spec-map.md").write_text("\n".join(lines) + "\n")
    print("docs/spec-map.md regenerated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
