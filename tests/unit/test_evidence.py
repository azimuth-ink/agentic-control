"""Unit: the evidence schema (Appendix D), the hash chain, payload erasure, the journal and reconciliation."""
import pytest

from agentic_control import events as schema
from agentic_control.common import Clock, Unavailable
from agentic_control.crypto import Signer, TrustStore
from agentic_control.evidence import EvidenceStore, Journal

HDR = {"trace_id": "t", "run_id": "r", "agent_id": "a", "release_version": "1", "surface": "S2"}


def test_schema_requires_fields_header_and_enumerations():
    with pytest.raises(schema.SchemaError, match="unknown event type"):
        schema.validate({"type": "nope"})
    with pytest.raises(schema.SchemaError, match="missing"):
        schema.validate({"type": "decision", **HDR})
    with pytest.raises(schema.SchemaError, match="run header"):
        schema.validate({"type": "run.started", "cause": "trigger"})
    with pytest.raises(schema.SchemaError, match="scope"):
        schema.validate({"type": "stop", "sequence": 1, "issued_by": "x", "validity": 1})
    with pytest.raises(schema.SchemaError, match="unknown outcome"):
        schema.validate({"type": "hold.resolved", **HDR, "node_id": "n", "outcome": "shrugged", "approvers": [], "substitution": False})
    with pytest.raises(schema.SchemaError, match="unknown error"):
        schema.validate({"type": "effect.failed", **HDR, "node_id": "n", "purpose": "normal", "credential_presentation": "p", "error": "oops", "recorded_by": "pep"})
    with pytest.raises(schema.SchemaError, match="unknown cause"):
        schema.validate({"type": "run.resumed", **HDR, "cause": "magic"})
    with pytest.raises(schema.SchemaError, match="unknown disposition"):
        schema.validate({"type": "run.closed_with_exception", **HDR, "final_state": "x", "exposed": False, "data_classes_touched": [], "disposition": "whatever"})
    schema.validate({"type": "run.parked", **HDR, "cause": "c", "resolver": "r", "deadline": 1})
    with pytest.raises(schema.SchemaError):
        schema.validate({"type": "run.parked", **HDR, "cause": "c"})


def test_every_declared_event_type_has_a_required_set():
    assert set(schema.RUN_STATE_EVENTS) <= set(schema.REQUIRED) and set(schema.RUN_FINAL_EVENTS) <= set(schema.REQUIRED)
    assert schema.OUT_OF_RUN <= set(schema.REQUIRED)


def test_hash_chain_detects_tampering_and_reordering():
    evs = EvidenceStore(Clock())
    ids = [evs.append({"type": "run.started", **HDR, "cause": "trigger"}) for _ in range(3)]
    assert evs.verify() and all(evs.event_verifies(i) for i in ids)
    assert evs.events[1]["prev_hash"] == evs.events[0]["hash"]
    evs.events[1]["cause"] = "spawn"
    assert not evs.verify() and not evs.event_verifies(ids[1]) and evs.event_verifies(ids[0])
    evs2 = EvidenceStore(Clock())
    for _ in range(2):
        evs2.append({"type": "run.started", **HDR, "cause": "trigger"})
    evs2.events.reverse()
    assert not evs2.verify()


def test_witness_records_the_head_and_payload_erasure_keeps_the_chain():
    evs = EvidenceStore(Clock())
    ref = evs.payloads.put({"ticket": "secret body"})
    evs.append({"type": "node.entered", **HDR, "node_id": "n1", "node_type": "read", "inputs_ref": ref})
    w = evs.witness()
    assert w["head"] == evs.head and evs.witness_log[-1] is w
    evs.erase("r", [ref], "data-protection-officer")
    with pytest.raises(KeyError, match="erased"):
        evs.payloads.get(ref)
    assert evs.events[-1]["type"] == "erasure.applied" and evs.verify()


def test_unavailable_store_refuses_appends_and_reads():
    evs = EvidenceStore(Clock())
    evs.available = False
    with pytest.raises(Unavailable):
        evs.append({"type": "run.started", **HDR, "cause": "trigger"})
    with pytest.raises(Unavailable):
        evs.read("r")
    assert evs.read_unchecked("r") == []


def test_journal_is_signed_validated_and_reconciles_in_order():
    clock, trust = Clock(), TrustStore()
    signer = Signer("workload:wl-1"); trust.trust(signer, "workload")
    j = Journal("wl-1", signer, clock)
    with pytest.raises(schema.SchemaError):
        j.append({"type": "decision", **HDR})
    j.append({"type": "run.started", **HDR, "cause": "trigger"})
    j.append({"type": "node.entered", **HDR, "node_id": "n1", "node_type": "read", "inputs_ref": "p"})
    j.local_counters["effects"] = 2
    assert j.entry_verifies(j.events()[0]["event_id"], trust) and not j.entry_verifies("missing", trust)
    evs = EvidenceStore(clock)
    n = evs.reconcile(j, trust)
    assert n == 2 and not j.entries
    assert [e["type"] for e in evs.events] == ["run.started", "node.entered", "journal.reconciled"]
    assert evs.events[-1]["counters_merged"] == 2 and evs.verify()
    j.append({"type": "run.started", **HDR, "cause": "trigger"})
    j.entries[0]["payload"]["cause"] = "spawn"
    with pytest.raises(ValueError):
        evs.reconcile(j, trust)
