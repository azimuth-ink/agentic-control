"""F7. Compensation: deterministic, from the manifest mapping over the recorded original call, verified
against the evidence it is attached to, never held, outside stop scope; a failed or irreversible
compensation parks; cancellation compensates in reverse order."""
import pytest

from conftest import decisions, events, last_decision, spec
from warranty import build_scenario, policy_values


def completed(**kw):
    sc = build_scenario(trigger="clean-ticket", **kw)
    run = sc.start()
    sc.execute(run)
    assert run.state == "COMPLETED"
    return sc, run


@spec("3.10", "A.1", "A.3", "A.4", finding="F7")
def test_compensation_parameters_come_only_from_the_recorded_call():
    sc, run = completed()
    res = sc.pep.instruct(run, "c1", "compensation", original_node="n4")
    assert res["status"] == "executed"
    dec = last_decision(sc, run, "c1", "compensation")
    assert dec["decision"] == "ALLOW" and dec["parameters"] == {"shipment_id": "ship-1"}
    assert dec["action_hash"] != last_decision(sc, run, "n4")["action_hash"]   # its own hash, over the reversing tool
    ex = events(sc, run, "effect.executed", "c1")[-1]
    assert ex["purpose"] == "compensation" and ex["action_hash"] == last_decision(sc, run, "n4")["action_hash"]
    cred = next(c for c in reversed(sc.platform.ids.issued) if c["payload"]["purpose"] == "compensation")
    assert cred["payload"]["per_call"] is True and cred["payload"]["action_hash"] == ex["action_hash"]


@spec("A.3", finding="F7")
def test_a_compensation_whose_parameters_differ_from_the_mapping_is_denied():
    sc, run = completed()
    from agentic_control.policy import apply_mapping
    pdp = sc.platform.pdp
    orig_decide = pdp._decide_compensation
    seen = {}

    def spy(rq):
        seen["params"] = dict(rq.parameters)
        rq.parameters["shipment_id"] = "ship-999"          # a tampered request
        return orig_decide(rq)
    pdp._decide_compensation = spy
    res = sc.pep.instruct(run, "c1", "compensation", original_node="n4")
    assert res["status"] == "denied" and "differ" in res["reason"]
    assert sc.systems["fulfilment"].shipments["ship-1"]["status"] == "created"


@spec("A.3", "A.2", finding="F7")
def test_a_compensation_against_an_original_that_does_not_verify_is_denied():
    sc, run = completed()
    evs = sc.platform.evs
    dec = last_decision(sc, run, "n4")
    for e in evs.events:
        if e["event_id"] == dec["event_id"]:
            e["parameters"] = {**e["parameters"], "amount": 1.0}        # tamper with the chained event
    assert not evs.event_verifies(dec["event_id"])
    res = sc.pep.instruct(run, "c1", "compensation", original_node="n4")
    assert res["status"] == "denied" and "verify" in res["reason"]


@spec("A.3", "A.1", finding="F7")
def test_only_the_mapped_reversing_tool_may_compensate():
    sc, run = completed()
    from agentic_control.release import Node
    rogue = Node("cx", "compensate", tool="delete_note", reverses="n4")
    sc.release.nodes.append(rogue)
    res = sc.pep.instruct(run, "cx", "compensation", original_node="n4")
    assert res["status"] == "denied" and "reversing tool" in res["reason"]


@spec("4.9", "6.1", "A.5", finding="F7")
def test_cancellation_compensates_executed_effects_in_reverse_order():
    sc, run = completed(internal_effect=True)
    assert len(sc.systems["notes"].records) == 1 and len(sc.systems["fulfilment"].shipments) == 1
    rc = sc.platform.run
    run.state = "PARKED"; run.park = {"reason": "test", "resolver": "r", "deadline": 0, "recoverable": False, "from": "RUNNING"}
    assert rc.resolver_cancel(run, "oncall-resolver") == "PARKED"
    # the reply (n5) is irreversible: cancellation parks at it before touching anything earlier
    assert "irreversible" in run.park["reason"] and sc.systems["fulfilment"].shipments["ship-1"]["status"] == "created"


@spec("4.9", "A.5", finding="F7")
def test_cancellation_reverses_in_order_when_every_effect_is_reversible():
    sc = build_scenario(trigger="clean-ticket", internal_effect=True)
    sc.release.nodes[:] = [n for n in sc.release.nodes if n.id != "n5"]
    sc.release.node("n4").denial_branch = "n6"
    run = sc.start()
    sc.execute(run)
    assert run.state == "COMPLETED"
    rc = sc.platform.run
    run.state = "PARKED"; run.park = {"reason": "test", "resolver": "r", "deadline": 0, "recoverable": False, "from": "RUNNING"}
    assert rc.resolver_cancel(run, "oncall-resolver") == "COMPENSATED"
    comps = [e for e in events(sc, run, "effect.executed") if e["purpose"] == "compensation"]
    assert [e["node_id"] for e in comps] == ["c1", "c0"]                  # shipment first, then the note
    assert sc.systems["fulfilment"].shipments["ship-1"]["status"] == "cancelled"
    assert "note-1" not in sc.systems["notes"].records
    fin = events(sc, run, "run.compensated")[-1]
    assert fin["final_state"] == "COMPENSATED"


@spec("4.9", "A.5", finding="F7")
def test_a_failed_compensation_parks_the_run():
    sc = build_scenario(trigger="clean-ticket", internal_effect=True)
    sc.release.nodes[:] = [n for n in sc.release.nodes if n.id != "n5"]
    sc.release.node("n4").denial_branch = "n6"
    run = sc.start()
    sc.execute(run)
    sc.systems["fulfilment"].dispatched.add("ship-1")                    # too late to cancel
    rc = sc.platform.run
    run.state = "PARKED"; run.park = {"reason": "test", "resolver": "r", "deadline": 0, "recoverable": False, "from": "RUNNING"}
    assert rc.resolver_cancel(run, "oncall-resolver") == "PARKED"
    assert "compensation of n4 failed" in run.park["reason"]
    assert events(sc, run, "effect.failed", "c1")[-1]["purpose"] == "compensation"
    assert "note-1" in sc.systems["notes"].records                           # the earlier note was not reached


@spec("A.3", "A.4", finding="F7")
def test_compensation_is_never_held_and_ignores_the_stop_list():
    sc, run = completed()
    sc.model.amount = 500.0
    sc.platform.ops.issue_stop("tool", "cancel_shipment")
    res = sc.pep.instruct(run, "c1", "compensation", original_node="n4")
    assert res["status"] == "executed"
    assert last_decision(sc, run, "c1", "compensation")["rule_id"] == "compensation"


@spec("A.3", "A.5", finding="F7")
def test_an_indeterminate_compensation_is_replayed_by_the_same_rule():
    sc, run = completed()
    sc.systems["fulfilment"].fail_next = "indeterminate_but_executed"
    res = sc.pep.instruct(run, "c1", "compensation", original_node="n4")
    assert res["status"] == "indeterminate"
    assert events(sc, run, "effect.indeterminate", "c1")
    res = sc.pep.instruct(run, "c1", "compensation", original_node="n4")
    assert res["status"] == "executed"
    assert len([c for c in sc.systems["fulfilment"].calls if c["tool"] == "cancel_shipment"]) == 1 or \
        sc.systems["fulfilment"].shipments["ship-1"]["status"] == "cancelled"
