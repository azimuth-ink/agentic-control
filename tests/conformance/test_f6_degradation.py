"""F6. Fail-closed by component (6.1): what continues during an outage of EVS, PDP, RUN, IDS, or PIP, and
what stops; journals reconcile; parked runs recover; escalation and the OPS close on the owner's deadline."""
import pytest

from agentic_control.common import Refused
from conftest import events, last_decision, spec
from warranty import build_scenario, policy_values


def outage_at(node_id, sc, component):
    inner = sc.pep.enter_node

    def enter(run, node, inputs):
        inner(run, node, inputs)
        if node.id == node_id:
            sc.platform.outage(component)
    sc.pep.enter_node = enter


@spec("6.1", "A.2", "A.4", finding="F6")
def test_evs_outage_no_factor_effects_and_reads_continue_journaled_other_effects_park():
    sc = build_scenario(trigger="clean-ticket", internal_effect=True)
    run = sc.start()
    outage_at("n0", sc, "EVS")
    sc.execute(run)
    # the note (no factor, run neither exposed nor delegated) was made and journaled; the reads continued;
    # the shipment's destination resolves outside (factor external): the run parks at it
    assert run.state == "PARKED" and run.park["reason"] == "EVS unavailable"
    assert sc.systems["notes"].records and not sc.systems["fulfilment"].shipments
    j = sc.pep.journal.events()
    assert [e["type"] for e in j if e["type"] in {"decision", "effect.executed"} and e.get("node_id") == "n0"] == ["decision", "effect.executed"]
    assert any(e["type"] == "node.exited" and e["node_id"] == "n3" for e in j)
    assert sc.pep.degraded_calls > 0
    before = len(sc.platform.evs.events)
    sc.platform.outage("EVS", down=False)
    n = sc.platform.evs.reconcile(sc.pep.journal, sc.platform.trust)
    assert n > 0 and not sc.pep.journal.entries
    evs = sc.platform.evs
    assert evs.verify()
    rec = [e for e in evs.events if e["type"] == "journal.reconciled"][-1]
    assert rec["events_count"] == n and rec["scope"] == "wl-1"
    types = [(e["type"], e.get("node_id")) for e in evs.read_unchecked(run.run_id)]
    assert types.index(("decision", "n0")) < types.index(("effect.executed", "n0")) < types.index(("node.exited", "n0"))
    assert len(evs.events) == before + n + 1
    assert sc.platform.run.recover(run) == "RUNNING"
    sc.execute(run)
    assert run.state == "COMPLETED" and len(sc.systems["fulfilment"].shipments) == 1


@spec("6.1", "6.2", "A.4", finding="F6")
def test_evs_outage_an_exposed_or_delegated_run_makes_no_effect():
    sc = build_scenario(internal_effect=True)                     # untrusted ticket: exposed at start
    run = sc.start()
    sc.platform.outage("EVS")
    sc.execute(run)
    assert run.state == "PARKED" and not sc.systems["notes"].records
    sc2 = build_scenario(internal_effect=True, trigger="console")  # delegated: an acting user
    run2 = sc2.start(user="advisor-1")
    sc2.platform.outage("EVS")
    sc2.execute(run2)
    assert run2.state == "PARKED" and not sc2.systems["notes"].records


@spec("6.1", "A.2", finding="F6")
def test_a_tampered_journal_entry_does_not_reconcile():
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    outage_at("n4", sc, "EVS")
    sc.execute(run)
    sc.pep.journal.entries[0]["payload"]["decision"] = "ALLOW"
    sc.pep.journal.entries[0]["payload"]["parameters"] = {"amount": 1}
    sc.platform.outage("EVS", down=False)
    with pytest.raises(ValueError):
        sc.platform.evs.reconcile(sc.pep.journal, sc.platform.trust)


@spec("6.1", "A.4", finding="F6")
def test_pdp_outage_scope_anchored_no_factor_effect_continues_others_park():
    sc = build_scenario(trigger="clean-ticket", internal_effect=True)
    run = sc.start()
    sc.platform.outage("PDP")
    sc.execute(run)
    assert events(sc, run, "effect.executed", "n0") and last_decision(sc, run, "n0")["rule_id"] == "local_bundle"
    assert run.state == "PARKED"                       # n1 is anchored to the subject: not decidable locally
    sc.platform.outage("PDP", down=False)
    assert sc.platform.run.recover(run) == "RUNNING"
    sc.execute(run)
    assert run.state == "COMPLETED"


@spec("6.1", "A.4", finding="F6")
def test_pdp_outage_an_exposed_run_does_not_continue():
    sc = build_scenario(internal_effect=True)        # the untrusted ticket exposes the run at start
    run = sc.start()
    sc.platform.outage("PDP")
    sc.execute(run)
    assert run.state == "PARKED" and not sc.systems["notes"].records


@spec("6.1", "A.4", finding="F6")
def test_pdp_outage_a_hold_cannot_be_processed_locally():
    sc = build_scenario(trigger="clean-ticket", internal_effect=True)
    from agentic_control.release import Bound
    sc.release.node("n0").bounds.append(Bound("limit", param="priority", auto=0, hard=None))   # priority 1 > auto 0: a hold
    run = sc.start()
    sc.platform.outage("PDP")
    sc.execute(run)
    assert run.state == "PARKED" and not sc.systems["notes"].records


@spec("6.1", "A.4", "A.5", finding="F6")
def test_run_outage_pep_e_continues_on_local_checkpoints_and_parks_at_the_first_node_needing_run():
    sc = build_scenario(trigger="clean-ticket", internal_effect=True)
    run = sc.start()
    sc.platform.outage("RUN")
    sc.execute(run)
    assert events(sc, run, "node.hook", "n0") and events(sc, run, "effect.executed", "n0")
    # n1 reads under an anchored bound: decided by the PDP (up), but the read result must be acknowledged at
    # RUN before release; the loop's model call then needs RUN for usage; the run parks there
    assert run.state == "PARKED"
    sc.platform.outage("RUN", down=False)
    assert sc.platform.run.recover(run) == "RUNNING"
    sc.execute(run)
    assert run.state == "COMPLETED"


@spec("6.1", "A.4", finding="F6")
def test_run_outage_proxy_form_stops():
    sc = build_scenario(trigger="clean-ticket", internal_effect=True, form="proxy", surface="S1")
    run = sc.start()
    sc.platform.outage("RUN")
    sc.execute(run)
    assert run.state == "PARKED" and not sc.systems["notes"].records


@spec("6.1", "A.6", finding="F6")
def test_ids_outage_no_new_credential_so_effects_park():
    sc = build_scenario(trigger="clean-ticket", internal_effect=True)
    run = sc.start()
    sc.platform.outage("IDS")
    sc.execute(run)
    assert run.state == "PARKED" and not sc.systems["notes"].records
    sc.platform.outage("IDS", down=False)
    sc.platform.run.recover(run)
    sc.execute(run)
    assert run.state == "COMPLETED"


@spec("6.1", "A.3", finding="F6")
def test_pip_outage_pip_anchored_bounds_cannot_be_evaluated():
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    sc.platform.outage("PIP")
    sc.execute(run)
    assert run.state == "PARKED" and not sc.systems["fulfilment"].shipments


@spec("6.1", "A.4", finding="F6")
def test_compensation_continues_through_an_evs_outage_from_runs_signed_copy():
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    sc.execute(run)
    sc.platform.outage("EVS")
    res = sc.pep.instruct(run, "c1", "compensation", original_node="n4")
    assert res["status"] == "executed"
    assert sc.systems["fulfilment"].shipments["ship-1"]["status"] == "cancelled"
    j = [e for e in sc.pep.journal.events() if e["type"] == "decision" and e["purpose"] == "compensation"]
    assert j and j[-1]["decision"] == "ALLOW"


@spec("6.1", "A.4", "A.5", finding="F6")
def test_compensation_does_not_continue_through_a_run_outage():
    """Compensation is instructed by RUN; with RUN down nothing instructs, so a resolver's cancel waits."""
    from agentic_control.common import Unavailable
    sc = build_scenario(trigger="clean-ticket", policy=policy_values(consecutive_replays=0))
    sc.systems["fulfilment"].fail_next = "indeterminate_but_executed"
    run = sc.start()
    sc.execute(run)
    rc = sc.platform.run
    rc.record_outcome(run, "n4", "executed", "evidence:q", {"shipment_id": "ship-1"})
    assert run.state == "PARKED"
    sc.platform.outage("RUN")
    with pytest.raises(Unavailable):
        rc.resolver_cancel(run, "oncall-resolver")
    assert sc.systems["fulfilment"].shipments["ship-1"]["status"] == "created"
    sc.platform.outage("RUN", down=False)
    assert rc.resolver_cancel(run, "oncall-resolver") == "COMPENSATED"
    assert sc.systems["fulfilment"].shipments["ship-1"]["status"] == "cancelled"


@spec("4.8", "B.1", finding="F6")
def test_host_loss_parks_and_recovers():
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    sc.platform.clock.advance(61)
    sc.platform.run.tick()
    assert run.state == "PARKED" and run.park["reason"] == "host lost"
    assert sc.platform.run.recover(run) == "RUNNING"
    sc.platform.ops.republish_stop_list()
    sc.execute(run)
    assert run.state == "COMPLETED"


@spec("4.8", "B.1", "D", finding="F6")
def test_park_deadline_escalates_and_the_owner_deadline_closes_with_compensation():
    sc = build_scenario(trigger="clean-ticket", policy=policy_values(consecutive_replays=0))
    sc.systems["fulfilment"].fail_next = "indeterminate_but_executed"
    run = sc.start()
    sc.execute(run)
    assert run.state == "PARKED"
    sc.platform.run.record_outcome(run, "n4", "executed", "evidence:q", {"shipment_id": "ship-1"})
    rc = sc.platform.run
    sc.platform.clock.advance(rc.park_deadline + 1)
    rc.tick()
    assert run.state == "ESCALATED"
    esc = events(sc, run, "run.escalated")[-1]
    assert esc["resolver"] == "oncall-resolver" and esc["deadline"] > sc.platform.clock.now()
    with pytest.raises(Refused):
        rc.owner_close(run, "loss_accepted", "not-the-owner")
    sc.platform.clock.advance(rc.owner_deadline + 1)
    rc.tick()
    assert run.state == "CLOSED_WITH_EXCEPTION" and run.disposition == "owner_deadline_passed"
    assert sc.systems["fulfilment"].shipments["ship-1"]["status"] == "cancelled"
    fin = events(sc, run, "run.closed_with_exception")[-1]
    assert fin["disposition"] == "owner_deadline_passed" and fin["decided_by"] == "OPS"
    assert any("closed by OPS" in n for n in rc.notifications)


@spec("4.8", "B.1", finding="F6")
def test_owner_resumes_or_cancels_from_escalated():
    sc = build_scenario(trigger="clean-ticket", policy=policy_values(consecutive_replays=0))
    sc.systems["fulfilment"].fail_next = "indeterminate_but_executed"
    run = sc.start()
    sc.execute(run)
    rc = sc.platform.run
    rc.record_outcome(run, "n4", "executed", "evidence:q", {"shipment_id": "ship-1"})
    sc.platform.clock.advance(rc.park_deadline + 1)
    rc.tick()
    with pytest.raises(Refused):
        rc.owner_cancel(run, "someone-else")
    assert rc.owner_cancel(run, "owner-1") == "COMPENSATED"
    assert sc.systems["fulfilment"].shipments["ship-1"]["status"] == "cancelled"


@spec("4.8", finding="F6")
def test_wall_clock_budget_parks_with_a_resolver():
    sc = build_scenario(trigger="clean-ticket", policy=policy_values(wall_clock_budget=10, heartbeat_deadline=1e9))
    run = sc.start()
    sc.platform.clock.advance(11)
    sc.platform.run.tick()
    assert run.state == "PARKED" and not run.park["recoverable"] and "wall-clock" in run.park["reason"]
