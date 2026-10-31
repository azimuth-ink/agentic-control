"""F5. Effects in doubt: an indeterminate outcome is never retried blind; replay carries the recorded
idempotency key and action hash; a resolver records the outcome against the system; a stop cancels
unexecuted effects as failed (not in doubt); counters reconcile from evidence."""
import pytest

from agentic_control.common import Refused
from conftest import decisions, events, last_decision, spec
from warranty import build_scenario, policy_values


@spec("4.6", "A.5", "A.7", finding="F5")
def test_indeterminate_then_replay_with_the_recorded_key_executes_once():
    sc = build_scenario(trigger="clean-ticket")
    sc.systems["fulfilment"].fail_next = "indeterminate"
    run = sc.start()
    sc.execute(run)
    assert events(sc, run, "effect.indeterminate", "n4")
    replay = [d for d in decisions(sc, run, "n4", "replay")]
    assert replay and replay[-1]["decision"] == "ALLOW"
    normal = last_decision(sc, run, "n4")
    assert replay[-1]["action_hash"] == normal["action_hash"] and replay[-1]["idempotency_key"] == normal["idempotency_key"]
    executed = events(sc, run, "effect.executed", "n4")
    assert len(executed) == 1 and executed[0]["purpose"] == "replay"
    assert len(sc.systems["fulfilment"].shipments) == 1
    sc.execute(run)
    assert run.state == "COMPLETED" and "n4" not in run.in_doubt_cache


@spec("4.6", "A.7", finding="F5")
def test_replay_of_an_effect_that_did_execute_returns_the_recorded_result():
    sc = build_scenario(trigger="clean-ticket")
    sc.systems["fulfilment"].fail_next = "indeterminate_but_executed"     # the call landed, the response was lost
    run = sc.start()
    sc.execute(run)
    assert len(sc.systems["fulfilment"].shipments) == 1                  # the system de-duplicated on the key
    assert len(sc.systems["fulfilment"].calls) == 1
    sc.execute(run)
    assert run.state == "COMPLETED"


@spec("4.6", "A.5", finding="F5")
def test_replay_count_exhausted_parks_with_a_resolver():
    sc = build_scenario(trigger="clean-ticket", policy=policy_values(consecutive_replays=0))
    sc.systems["fulfilment"].fail_next = "indeterminate"
    run = sc.start()
    sc.execute(run)
    assert run.state == "PARKED" and "resolver" in run.park["reason"]
    assert not run.park["recoverable"]
    with pytest.raises(Refused):
        sc.platform.ops.resolver_resume(run)          # effects in doubt first


@spec("4.6", "A.5", "D", finding="F5")
def test_resolver_records_not_executed_and_the_node_is_re_entered():
    sc = build_scenario(trigger="clean-ticket", policy=policy_values(consecutive_replays=0))
    sc.systems["fulfilment"].fail_next = "indeterminate"
    run = sc.start()
    sc.execute(run)
    sc.platform.ops.record_outcome(run, "n4", "not_executed", "evidence:fulfilment-query")
    failed = events(sc, run, "effect.failed", "n4")[-1]
    assert failed["error"] == "not_executed" and failed["recorded_by"] == "resolver"
    assert run.next_node == "n4" and "n4" not in run.in_doubt_cache
    sc.platform.ops.resolver_resume(run)
    sc.execute(run)
    assert run.state == "COMPLETED" and len(sc.systems["fulfilment"].shipments) == 1
    # the second attempt was a fresh decision with a new reservation
    assert len(decisions(sc, run, "n4")) == 2


@spec("4.6", "A.5", "D", finding="F5")
def test_resolver_records_executed_and_the_run_moves_on():
    sc = build_scenario(trigger="clean-ticket", policy=policy_values(consecutive_replays=0))
    sc.systems["fulfilment"].fail_next = "indeterminate_but_executed"
    run = sc.start()
    sc.execute(run)
    assert run.state == "PARKED"
    sc.platform.ops.record_outcome(run, "n4", "executed", "evidence:fulfilment-query", {"shipment_id": "ship-1"})
    ex = events(sc, run, "effect.executed", "n4")[-1]
    assert ex["recorded_by"] == "resolver"
    assert "n4" in run.exited and run.next_node == "n5"
    sc.platform.ops.resolver_resume(run)
    sc.execute(run)
    assert run.state == "COMPLETED" and len(sc.systems["fulfilment"].calls) == 1


@spec("4.9", "A.5", finding="F5")
def test_a_stop_cancels_an_unexecuted_held_effect_as_failed_not_in_doubt():
    sc = build_scenario(trigger="clean-ticket")
    sc.model.amount = 500.0
    run = sc.start()
    sc.execute(run)
    assert run.state == "HELD"
    stop = sc.platform.ops.issue_stop("agent", "warranty-agent")
    failed = events(sc, run, "effect.failed", "n4")[-1]
    assert failed["error"] == "stopped"
    assert events(sc, run, "hold.resolved", "n4")[-1]["outcome"] == "stopped"
    assert run.state == "PARKED" and run.stop_ref == stop.stop_id
    assert not sc.platform.run.in_doubt(run, "n4")
    sc.platform.ops.lift_stop(stop.stop_id)
    sc.platform.ops.resolver_resume(run)
    assert run.next_node == "n4"
    sc.execute(run)
    assert run.state == "HELD"                                            # decided afresh: the band still holds


@spec("4.9", "A.5", finding="F5")
def test_a_stop_before_any_effect_node_cancels_the_run():
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    sc.platform.ops.issue_stop("surface", "S2")
    assert run.state == "CANCELLED"
    sc.execute(run)
    assert run.state == "CANCELLED" and not sc.systems["fulfilment"].shipments


@spec("4.9", "A.3", "A.4", "A.5", finding="F5")
def test_under_a_stop_no_run_starts_and_compensation_still_runs():
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    sc.execute(run)
    assert run.state == "COMPLETED"
    stop = sc.platform.ops.issue_stop("fleet")
    with pytest.raises(Refused, match="stop"):
        sc.start()
    # compensation of the completed run's shipment is instructed by RUN and allowed under the stop
    res = sc.platform.run.instruct_compensation(run, "n4")
    assert res["status"] == "executed"
    assert sc.systems["fulfilment"].shipments["ship-1"]["status"] == "cancelled"
    sc.platform.ops.lift_stop(stop.stop_id)
    run3 = sc.start()
    sc.execute(run3)
    assert run3.state == "COMPLETED"


@spec("4.9", "A.4", finding="F5")
def test_the_pep_enforces_its_own_list_when_run_has_not_reached_the_run():
    """The stop list reaches the PEP first (the PDP channel); RUN's apply_stop has not touched the run.
    The PEP refuses the effect from its list and the run leaves RUNNING, parked at that node."""
    from agentic_control.policy import Stop, StopList
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    ops = sc.platform.ops
    inner = sc.pep.enter_node

    def enter(r, node, inputs):
        inner(r, node, inputs)
        if node.id == "n4":
            sl = StopList(99, sc.platform.clock.now(), 600.0, [Stop("stop-local", "tool", "ship_replacement", 99)])
            sc.pep.update_stop_list(ops.signer.sign(sl.to_dict()), sl)
    sc.pep.enter_node = enter
    sc.execute(run)
    assert run.state == "PARKED" and "n4" in run.cancelled_effects
    dec = last_decision(sc, run, "n4")
    assert dec["decision"] == "DENY" and dec["rule_id"] == "stop_scope"
    assert not sc.systems["fulfilment"].shipments and not events(sc, run, "effect.indeterminate")


@spec("4.9", "A.4", finding="F5")
def test_a_stale_stop_list_refuses_effects_until_republished():
    sc = build_scenario(trigger="clean-ticket")
    sc.platform.clock.advance(601)
    run = sc.start()
    sc.execute(run)
    assert not sc.systems["fulfilment"].shipments
    assert run.state == "PARKED" and last_decision(sc, run, "n4")["reason"] == "stop list stale"
    sc.platform.ops.republish_stop_list()
    run2 = sc.start()
    sc.execute(run2)
    assert run2.state == "COMPLETED" and len(sc.systems["fulfilment"].shipments) == 1


@spec("4.6", "A.5", finding="F5")
def test_a_runtime_error_after_an_effect_parks_rather_than_fails():
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    sc.execute(run)
    assert run.state == "COMPLETED"
    sc2 = build_scenario(trigger="clean-ticket")
    run2 = sc2.start()
    assert sc2.platform.run.runtime_error(run2, "n1", "model host crashed") == "FAILED"
    sc3 = build_scenario(trigger="clean-ticket")
    run3 = sc3.start()
    orig = sc3.model.propose

    def propose(run, node, ctx):
        if node.id == "n5":
            raise RuntimeError("host crashed")
        return orig(run, node, ctx)
    sc3.model.propose = propose
    with pytest.raises(RuntimeError):
        sc3.execute(run3)
    assert sc3.platform.run.runtime_error(run3, "n5", "host crashed") == "PARKED"
    assert run3.park["recoverable"] is True
    assert sc3.platform.run.recover(run3) == "RUNNING"
    sc3.model.propose = orig
    sc3.execute(run3)
    assert run3.state == "COMPLETED"
