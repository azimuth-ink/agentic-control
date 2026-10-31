"""Regressions pinned after the first independent code review (see CHANGELOG, 0.1.0). Each test names
the finding family it belongs to; the review's numbering is in the docstrings."""
import pytest

from agentic_control.common import Denied, Refused
from agentic_control.release import Bound, Node
from conftest import decisions, events, last_decision, spec
from warranty import build_scenario, policy_values


def held(**kw):
    sc = build_scenario(trigger="clean-ticket", **kw)
    sc.model.amount = 500.0
    run = sc.start()
    sc.execute(run)
    assert run.state == "HELD"
    return sc, run


@spec("A.3", "A.2", "4.4", finding="F4")
def test_substitution_resubmits_with_the_approver_as_acting_user():
    """Review 3: the resubmitted request's chain carries the approver, not the revoked user."""
    sc = build_scenario(trigger="console")
    sc.model.amount = 500.0
    for n in sc.release.nodes:
        for b in n.bounds:
            if b.anchor == "acting_user":
                b.anchor = "subject"
    run = sc.start(user="advisor-1")
    run.subject = "advisor-1"
    sc.execute(run)
    sc.platform.ids.revoke_delegation("advisor-1")
    assert sc.platform.ops.approve(run, "n4", "approver-1")["status"] == "executed"
    rq, d = sc.platform.pdp.decisions[-1]
    assert rq.purpose == "normal" and rq.node.id == "n4" and d.result == "ALLOW"
    assert rq.principal_chain["acting_user"] == "approver-1" and rq.principal_chain["requested_principal"] == "advisor-1"


@spec("4.4", "A.5", "B.1", finding="F2")
def test_deny_has_the_same_guards_as_approve_and_is_deferred_while_parked():
    """Review 6 and 7."""
    sc, run = held()
    with pytest.raises(Refused):
        sc.platform.ops.deny(run, "n4", "stranger")
    sc.platform.run.park(run, "host lost")
    assert sc.platform.ops.deny(run, "n4", "approver-1")["status"] == "denied_while_parked"
    assert run.state == "PARKED" and run.holds["n4"].status == "resolved"
    with pytest.raises(Refused):
        sc.platform.ops.deny(run, "n4", "approver-1")              # no open hold any more
    assert sc.platform.run.recover(run) == "RUNNING" and run.next_node == "n5"
    sc.execute(run)
    assert run.state == "COMPLETED" and not sc.systems["fulfilment"].shipments


@spec("4.4", "A.2", "B.1", finding="F2")
def test_an_approval_during_a_park_is_honoured_on_recovery():
    """Review 7: A.2 'An approval recorded during the park is honoured if the run leaves PARKED before
    the window expires'."""
    sc, run = held()
    sc.platform.run.park(run, "host lost")
    res = sc.platform.ops.approve(run, "n4", "approver-1")
    assert res["status"] == "approved_while_parked" and run.holds["n4"].status == "approved"
    sc.platform.clock.advance(100)
    assert sc.platform.run.recover(run) == "RUNNING"
    assert events(sc, run, "effect.executed", "n4")
    sc.execute(run)
    assert run.state == "COMPLETED"


@spec("4.4", "A.2", finding="F2")
def test_a_suspension_before_the_approval_does_not_extend_the_resume_window():
    """Review 11: only suspended time after the approval is credited against the resume window."""
    from agentic_control.coordinator import Hold
    sc, run = held()
    ids, rc, clock = sc.platform.ids, sc.platform.run, sc.platform.clock
    t0 = clock.now()
    # held at t0, parked t0+100 .. t0+3100 (3000 s suspended), approved at t0+3200, now t0+3200+1801
    clock.advance(3200 + 1801)
    assertion = {"hold_time": t0, "approval_time": t0 + 3200, "suspensions": [[t0 + 100, t0 + 3100]]}
    assert ids._check_timers(assertion) == "expired"                  # the pre-approval park is not credited
    h = Hold(hold_id="h", node_id="n4", action_hash="a", kind="effect", causes=[], approver_set=[], approvers_required=1,
             hold_time=t0, substitution_only=False)
    h.suspensions = [[t0 + 100, t0 + 3100]]; h.approval_time = t0 + 3200
    assert rc._approval_expired(h)
    assertion["suspensions"] = [[t0 + 3300, t0 + 3300 + 1000]]        # a park after the approval is credited
    assert ids._check_timers(assertion) is None
    assert not rc._approval_timed_out(h)


@spec("A.4", "A.5", "4.2", finding="F9")
def test_model_calls_need_a_running_run_a_confirmed_node_and_a_model_capable_node_type():
    """Review 10."""
    sc, run = held()
    with pytest.raises(Denied, match="held or parked"):
        sc.pep.model_call(run, sc.release.node("n2"), "model-a", "x")
    sc2 = build_scenario(trigger="clean-ticket")
    run2 = sc2.start()
    with pytest.raises(Denied, match="node_entered"):
        sc2.pep.model_call(run2, sc2.release.node("n1"), "model-a", "x")
    sc2.platform.run.node_entered(run2, "n1", "read", "p:x")
    assert sc2.pep.model_call(run2, sc2.release.node("n1"), "model-a", "x")
    with pytest.raises(Denied, match="no model call"):
        sc2.pep.model_call(run2, Node("c1", "compensate", tool="cancel_shipment", reverses="n4"), "model-a", "x")


@spec("A.5", finding="F9")
def test_checkpoint_requires_the_hook_and_a_human_node_is_held_by_run_at_entry():
    """Review 9."""
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    with pytest.raises(Denied, match="node_entered"):
        sc.platform.run.checkpoint(run, "n3", {}, {})
    sc.release.nodes.insert(1, Node("h0", "human", input_role="advisor", approver_set=["advisor-1"]))
    sc.release.node("n1")  # still first
    run2 = sc.start()
    sc.execute(run2)
    assert run2.state == "HELD" and run2.holds["h0"].kind == "input"
    assert events(sc, run2, "hold.created", "h0")[-1]["kind"] == "input"
    with pytest.raises(Denied):
        sc.platform.run.checkpoint(run2, "n2", {}, {})               # cannot skip past the human node


@spec("6.1", "A.3", "A.4", finding="F6")
def test_local_evaluation_applies_constant_predicates_and_the_bundles_entitlements():
    """Review 2."""
    sc = build_scenario(trigger="clean-ticket", internal_effect=True)
    sc.release.node("n0").bounds.append(Bound("op", param="priority", op="<=", const=0))   # priority 1 fails
    run = sc.start()
    sc.platform.outage("PDP")
    sc.execute(run)
    assert last_decision(sc, run, "n0")["rule_id"] == "bounds" and not sc.systems["notes"].records
    sc2 = build_scenario(trigger="clean-ticket", internal_effect=True)
    sc2.bundle.entitlements["warranty-agent"]["tools"].remove("add_note")
    sc2.platform.publish_bundle(sc2.bundle)
    run2 = sc2.start()
    sc2.platform.outage("PDP")
    sc2.execute(run2)
    assert last_decision(sc2, run2, "n0")["rule_id"] == "intersection" and not sc2.systems["notes"].records


@spec("6.1", "4.2", "A.4", finding="F6")
def test_restricted_reads_stop_under_any_outage():
    """Review 8."""
    sc = build_scenario(trigger="clean-ticket")
    sc.platform.registry.tools["lookup_devices"].reads_data_class = "restricted"
    run = sc.start()
    sc.platform.outage("EVS")
    sc.execute(run)
    assert run.state == "PARKED" and not decisions(sc, run, "n1")


@spec("A.2", "A.7", "I1", finding="F4")
def test_reads_and_previews_present_a_credential():
    """Review 8: only the PEP presents a credential, and every call presents one."""
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    sc.execute(run)
    audiences = {c["payload"]["audience"] for c in sc.platform.ids.issued}
    assert {"device_registry", "support_portal", "fulfilment", "mail_relay", "case_log"} <= audiences
    from agentic_control.dbs import SystemRefused
    with pytest.raises(SystemRefused):
        sc.systems["device_registry"].read("lookup_devices", {"device_id": "dev-1"})


@spec("4.6", "A.5", finding="F5")
def test_a_replay_refused_by_the_system_keeps_the_node_in_doubt_for_a_resolver():
    """Review 4."""
    sc = build_scenario(trigger="clean-ticket")
    f = sc.systems["fulfilment"]
    f.fail_next = "indeterminate"
    orig = f.execute

    def refuse_replays(tool, params, credential, presenter, purpose="normal", action_hash=None, idempotency_key=None, tag=None):
        if purpose == "replay":
            from agentic_control.dbs import SystemRefused
            raise SystemRefused("replay refused")
        return orig(tool, params, credential, presenter, purpose, action_hash, idempotency_key, tag)
    f.execute = refuse_replays
    run = sc.start()
    sc.execute(run)
    assert run.state == "PARKED" and "resolver" in run.park["reason"]
    assert sc.platform.run.in_doubt(run, "n4")
    failed = events(sc, run, "effect.failed", "n4")
    assert failed and failed[-1]["purpose"] == "replay"
    with pytest.raises(Refused):
        sc.platform.ops.resolver_resume(run)


@spec("4.6", "A.5", finding="F5")
def test_a_resolver_not_executed_re_entry_happens_once():
    """Review 5."""
    sc = build_scenario(trigger="clean-ticket", policy=policy_values(consecutive_replays=0))
    sc.systems["fulfilment"].fail_next = "indeterminate"
    run = sc.start()
    sc.execute(run)
    sc.platform.ops.record_outcome(run, "n4", "not_executed", "evidence:q")
    sc.platform.ops.resolver_resume(run)
    sc.execute(run)
    assert run.state == "COMPLETED" and len(sc.systems["fulfilment"].shipments) == 1
    assert not run.not_executed
    # a later recoverable park must not point the run back at the executed node
    run.state = "RUNNING"
    sc.platform.run.park(run, "host lost")
    sc.platform.run.recover(run)
    assert run.next_node != "n4"


@spec("A.4", "A.1", finding="F9")
def test_a_call_whose_parameters_do_not_fit_the_schema_is_refused_before_reservation():
    """Review 11: an untyped comparison must not escape the PDP."""
    sc = build_scenario(trigger="clean-ticket")
    orig = sc.model.propose
    sc.model.propose = lambda r, n, c: {**orig(r, n, c), "amount": "500"} if n.id == "n4" else orig(r, n, c)
    run = sc.start()
    sc.execute(run)
    dec = last_decision(sc, run, "n4")
    assert dec["rule_id"] == "schema" and "reservation_id" not in dec
    assert not sc.systems["fulfilment"].shipments and not sc.platform.run.reservations or \
        all(r["status"] != "reserved" for r in sc.platform.run.reservations.values())


@spec("A.3", "4.4", finding="F2")
def test_the_pdp_verifies_the_approval_record_before_honouring_discharged_causes():
    """Review 11."""
    from agentic_control.crypto import Signer
    sc, run = held()
    h = run.holds["n4"]
    forged = Signer("not-run").sign({"approval_ref": "x", "action_hash": h.action_hash, "kind": "grant",
                                     "causes_discharged": ["limit_band"]})
    pending = h.pending
    rq = sc.pep._request(run, sc.release.node("n4"), sc.platform.registry.tools["ship_replacement"], pending["parameters"], "normal",
                         {"agent": 1, "subject": 1, "destination": 1}, approval_ref=forged)
    d = sc.platform.pdp.decide(rq)
    assert d.result == "DENY" and d.rule_id == "approval_record"
