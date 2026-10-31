"""The evidence schema (Appendix D). One event per occurrence; fields marked required are checked on
append. Run events carry the run header; events outside a run carry `scope` instead."""
from __future__ import annotations

from typing import Any

RUN_HEADER = {"trace_id", "run_id", "agent_id", "release_version", "surface"}
RUN_STATE_EVENTS = {"run.started", "run.held", "run.resumed", "run.stopping", "run.parked", "run.escalated",
                    "run.escalation_resolved", "run.compensating"}
RUN_FINAL_EVENTS = {"run.completed", "run.compensated", "run.cancelled", "run.failed", "run.closed_with_exception"}
RESUME_CAUSES = {"approved", "denial_branch", "resolver", "owner", "recovered"}
HOLD_OUTCOMES = {"approved", "denied", "timeout", "stopped", "revoked", "expired", "superseded"}
EFFECT_ERRORS = {"stopped", "revoked", "dlp", "not_executed", "system_error"}
DISPOSITIONS = {"loss_accepted", "manual_remediation", "incident", "owner_deadline_passed"}

REQUIRED: dict[str, set[str]] = {
    "run.created": {"trigger", "trigger_kind", "signature_verified", "principal_chain", "exposed_at_start"},
    "node.entered": {"node_id", "node_type", "inputs_ref"},
    "decision": {"node_id", "purpose", "tool", "version", "schema_hash", "parameters_ref", "parameter_roles",
                 "action_hash", "factors", "decision", "rule_id", "obligations", "stop_list_seq"},
    "effect.executed": {"node_id", "purpose", "credential_presentation", "result_ref", "recorded_by"},
    "effect.failed": {"node_id", "purpose", "credential_presentation", "error", "recorded_by"},
    "effect.indeterminate": {"node_id", "purpose", "credential_presentation", "last_known", "recorded_by"},
    "delivery.executed": {"node_id", "sink", "sanitizer_applied", "result_ref"},
    "delivery.failed": {"node_id", "sink", "sanitizer_applied", "error"},
    "node.hook": {"node_id", "node_type"},
    "usage.recorded": {"node_id", "tokens", "model"},
    "hold.created": {"node_id", "kind", "hold_causes", "approver_set", "substitution_only", "view_ref"},
    "hold.resolved": {"node_id", "outcome", "approvers", "substitution"},
    "taint.applied": {"source", "items"},
    "sanitize.result": {"node_id", "sanitizer", "version", "accepted_ref", "rejected_ref"},
    "node.exited": {"node_id", "outputs_ref", "data_classes_touched", "exposed"},
    "grant.minted": {"grant_id", "action_hash"},
    "grant.redeemed": {"grant_id", "action_hash", "presenter_workload"},
    "grant.invalidated": {"grant_id", "action_hash"},
    "approved_action.used": {"approval_ref", "action_hash", "presenter_workload"},
    "stop": {"scope", "sequence", "issued_by", "validity"},
    "recovery.used": {"scope", "identity", "releasers", "incident_id", "actions_ref"},
    "journal.reconciled": {"scope", "gap_start", "gap_end", "events_count", "counters_merged"},
    "external.imported": {"scope", "source", "fields_present", "fields_missing", "raw_ref"},
    "erasure.applied": {"run_id", "payload_refs", "authority"},
}
for _e in RUN_STATE_EVENTS:
    REQUIRED[_e] = {"cause"}
for _e in RUN_FINAL_EVENTS:
    REQUIRED[_e] = {"final_state", "exposed", "data_classes_touched"}
REQUIRED["run.parked"] |= {"resolver", "deadline"}
REQUIRED["run.escalated"] |= {"resolver", "deadline"}
REQUIRED["run.closed_with_exception"] |= {"disposition"}

OUT_OF_RUN = {"stop", "recovery.used", "journal.reconciled", "external.imported", "erasure.applied"}


class SchemaError(ValueError):
    pass


def validate(event: dict[str, Any]) -> None:
    t = event.get("type")
    if t not in REQUIRED:
        raise SchemaError(f"unknown event type {t}")
    missing = REQUIRED[t] - set(event)
    if missing:
        raise SchemaError(f"{t}: missing {sorted(missing)}")
    if t in OUT_OF_RUN:
        if "scope" not in event:
            raise SchemaError(f"{t}: events outside a run carry scope")
    else:
        hdr = RUN_HEADER - set(event)
        if hdr:
            raise SchemaError(f"{t}: missing run header {sorted(hdr)}")
    if t == "decision" and event.get("purpose") == "normal" and event.get("tier") is not None:
        if "reservation_id" not in event and event.get("reservation") != "local":
            raise SchemaError("decision: a normal effect decision carries its reservation (or 'local' under a RUN outage)")
    if t == "run.resumed" and event["cause"] not in RESUME_CAUSES:
        raise SchemaError("run.resumed: unknown cause")
    if t == "hold.resolved" and event["outcome"] not in HOLD_OUTCOMES:
        raise SchemaError("hold.resolved: unknown outcome")
    if t == "effect.failed" and event["error"] not in EFFECT_ERRORS:
        raise SchemaError("effect.failed: unknown error")
    if t == "run.closed_with_exception" and event["disposition"] not in DISPOSITIONS:
        raise SchemaError("run.closed_with_exception: unknown disposition")
