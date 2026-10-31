"""F2. Hold and resumption: the approved action is the single action hash; resumption is re-evaluated in
full with only the discharged causes skipped; approvals are single-use; timers run on RUN's clock and
suspend while parked; the re-hold maximum ends the cycle by denial."""
import pytest

from agentic_control.common import Refused
from conftest import decisions, events, last_decision, spec
from warranty import AGENT, BUILD, build_scenario, policy_values


def outage_at(node_id, sc, component="IDS"):
    """Takes a component down the moment the PEP enters `node_id`."""
    inner = sc.pep.enter_node

    def enter(run, node, inputs):
        inner(run, node, inputs)
        if node.id == node_id:
            sc.platform.outage(component)
    sc.pep.enter_node = enter


def held_scenario(**kw):
    sc = build_scenario(trigger="clean-ticket", **kw)
    sc.model.amount = 500.0            # above the auto limit (200), below the hard limit (1000)
    run = sc.start()
    sc.execute(run)
    assert run.state == "HELD"
    return sc, run


@spec("4.4", "A.5", "B.1", finding="F2")
def test_hold_then_approve_executes_the_same_action_hash():
    sc, run = held_scenario()
    hold = events(sc, run, "hold.created", "n4")[-1]
    assert hold["hold_causes"] == ["limit_band"] and hold["grant_id"]
    res = sc.platform.ops.approve(run, "n4", "approver-1")
    assert res["status"] == "executed"
    sc.execute(run)
    assert run.state == "COMPLETED"
    dec = decisions(sc, run, "n4")
    assert dec[-1]["action_hash"] == dec[0]["action_hash"] and dec[-1]["decision"] == "ALLOW"
    assert dec[-1]["approval_ref"] == hold["event_id"] or dec[-1]["approval_ref"]
    assert [e["type"] for e in events(sc, run, "grant.redeemed")] == ["grant.redeemed"]
    assert len(sc.systems["fulfilment"].shipments) == 1


@spec("4.4", "A.5", finding="F2")
def test_an_approver_outside_the_set_or_a_second_approval_is_refused():
    sc, run = held_scenario()
    with pytest.raises(Refused):
        sc.platform.ops.approve(run, "n4", "stranger")
    sc.platform.ops.approve(run, "n4", "approver-1")
    with pytest.raises(Refused):
        sc.platform.ops.approve(run, "n4", "approver-1")   # no open hold: the record was used once


@spec("4.4", "A.5", finding="F2")
def test_denial_follows_the_denial_branch_and_invalidates_the_grant():
    sc, run = held_scenario()
    sc.platform.ops.deny(run, "n4", "approver-1")
    assert events(sc, run, "hold.resolved", "n4")[-1]["outcome"] == "denied"
    assert events(sc, run, "grant.invalidated")
    sc.execute(run)
    assert run.state == "COMPLETED" and sc.systems["fulfilment"].shipments == {}
    assert len(sc.systems["mail_relay"].sent) == 1


@spec("4.4", "A.5", finding="F2")
def test_resumption_is_re_evaluated_in_full_with_only_discharged_causes_skipped():
    """Approval discharges limit_band. Before the resume the subject's velocity window fills, so the
    resubmission is held again with the new cause only; the discharged set is kept."""
    sc, run = held_scenario()
    # fill the subject counter above its limit while the hold is open
    for _ in range(7):
        sc.platform.run.confirm(sc.platform.run.reserve({"subject": "cust-1"}, 3600)[0])
    res = sc.platform.ops.approve(run, "n4", "approver-1")
    assert res["status"] == "held_again"
    holds = events(sc, run, "hold.created", "n4")
    assert holds[-1]["hold_causes"] == ["velocity:subject"]
    sup = [e for e in events(sc, run, "hold.resolved", "n4") if e["outcome"] == "superseded"]
    assert sup and sup[-1]["causes_discharged"] == ["limit_band"]
    assert run.rehold_counts[holds[-1]["action_hash"]] == 1


@spec("4.4", "A.5", finding="F2")
def test_rehold_maximum_resolves_by_denial():
    sc, run = held_scenario(policy=policy_values(rehold_maximum=1))
    for _ in range(7):
        sc.platform.run.confirm(sc.platform.run.reserve({"subject": "cust-1"}, 3600)[0])
    assert sc.platform.ops.approve(run, "n4", "approver-1")["status"] == "held_again"   # re-hold 1 of 1
    for _ in range(5):
        sc.platform.run.confirm(sc.platform.run.reserve({"destination": "12 Main St"}, 3600)[0])
    assert sc.platform.ops.approve(run, "n4", "approver-1")["status"] == "denied"       # a third cause: no further re-hold
    assert last_decision(sc, run, "n4")["rule_id"] == "rehold_maximum"
    assert sc.systems["fulfilment"].shipments == {}


@spec("4.4", "A.5", finding="F2")
def test_approval_timeout_denies_on_RUNs_clock():
    sc, run = held_scenario()
    sc.platform.clock.advance(3601)
    sc.platform.run.tick()
    assert events(sc, run, "hold.resolved", "n4")[-1]["outcome"] == "timeout"
    assert run.state == "RUNNING" and run.next_node == "n5"


@spec("4.4", "4.5", "A.5", finding="F2")
def test_timers_suspend_while_parked_and_resume_after_recovery():
    sc, run = held_scenario()
    sc.platform.run.park(run, "host lost")
    sc.platform.clock.advance(5000)           # longer than the approval timeout, all of it suspended
    sc.platform.ops.republish_stop_list()     # the stop channel's own heartbeat; otherwise the list is stale
    assert sc.platform.run.recover(run) == "HELD"
    assert run.holds["n4"].status == "open"
    assert sc.platform.ops.approve(run, "n4", "approver-1")["status"] == "executed"


@spec("4.4", "A.5", "A.6", finding="F2")
def test_window_expiry_after_approval_while_parked_reopens_the_hold():
    sc, run = held_scenario()
    sc.platform.outage("IDS")
    sc.platform.ops.approve(run, "n4", "approver-1")
    # IDS unreachable at redemption: the PEP cannot get a credential and the run parks
    assert run.state == "PARKED"
    sc.platform.outage("IDS", down=False)
    sc.platform.clock.advance(1801 + 7201)      # park suspension is capped at max_park; the excess counts
    sc.platform.ops.republish_stop_list()
    assert sc.platform.run.recover(run) == "HELD"
    assert events(sc, run, "hold.resolved", "n4")[-1]["outcome"] == "expired"
    new = run.holds["n4"]
    assert new.status == "open" and new.discharged == set() and new.causes == ["limit_band"]


@spec("4.4", "A.5", "A.6", finding="F2")
def test_ids_unreachable_at_hold_parks_then_recovers_to_held():
    sc = build_scenario(trigger="clean-ticket")
    sc.model.amount = 500.0
    run = sc.start()
    outage_at("n4", sc)                        # IDS goes down as the effect node is entered
    sc.execute(run)
    assert run.state == "PARKED" and run.park["reason"] == "IDS unreachable at hold"
    sc.platform.outage("IDS", down=False)
    assert sc.platform.run.recover(run) == "HELD"
    assert run.holds["n4"].grant_id is not None
    assert sc.platform.ops.approve(run, "n4", "approver-1")["status"] == "executed"


@spec("4.4", "4.5", "A.4", finding="F2")
def test_a_replacement_pep_resumes_from_the_hold_record_alone():
    sc, run = held_scenario()
    p = sc.platform
    pep2 = p.pep("wl-2", "sidecar", "S2", BUILD, AGENT)
    run.workload = "wl-2"
    sc.pep.pending.clear()                      # nothing survives from the first PEP
    res = p.ops.approve(run, "n4", "approver-1")
    assert res["status"] == "executed"
    assert pep2.instructions[-1]["purpose"] == "resume"


@spec("4.4", "6.1", finding="F2")
def test_approval_arriving_while_parked_is_recorded_and_applied_on_recovery():
    sc, run = held_scenario()
    sc.platform.outage("IDS")
    sc.platform.ops.approve(run, "n4", "approver-1")
    assert run.state == "PARKED" and run.holds["n4"].status == "approved"
    sc.platform.outage("IDS", down=False)
    sc.platform.run.recover(run)
    assert events(sc, run, "effect.executed", "n4")
    sc.execute(run)
    assert run.state == "COMPLETED"


@spec("4.3", "A.3", finding="F2")
def test_two_approver_threshold_for_regulated_irreversible_effects():
    sc = build_scenario(regulated_irreversible=True, trigger="clean-ticket")
    sc.model.amount = 160.0                    # above the two-approver threshold (150) set by the variant
    run = sc.start()
    sc.execute(run)
    hold = events(sc, run, "hold.created", "n4")[-1]
    assert set(hold["approver_set"]) == {"approver-1", "approver-2"}
    assert sc.platform.ops.approve(run, "n4", "approver-1") == {"status": "awaiting_second_approver"}
    assert sc.platform.ops.approve(run, "n4", "approver-2")["status"] == "executed"
    assert events(sc, run, "hold.resolved", "n4")[-1]["approvers"] == ["approver-1", "approver-2"]


@spec("4.3", "A.3", finding="F2")
def test_hold_view_carries_the_preview_and_bounds_not_the_prompt():
    sc, run = held_scenario()
    h = run.holds["n4"]
    view = sc.platform.evs.payloads.get(h.view_ref)
    assert view["preview"] == h.preview_ref and h.preview_ref is not None
    assert view["parameters"]["amount"] == 500.0 and view["causes"] == ["limit_band"]
    assert "prompt" not in view and view["provenance_claim"] is None
