"""F3. Velocity: counters are reserved before the decision, released on deny or hold, confirmed on the
effect event, reconciled from evidence; exposed runs halve the limits; the hard cap is a denial."""
from conftest import decisions, events, last_decision, spec
from warranty import build_scenario, policy_values


def run_shipment(sc):
    run = sc.start()
    sc.execute(run)
    return run


@spec("4.6", "A.5", "A.3", finding="F3")
def test_reservation_is_confirmed_on_the_effect_event():
    sc = build_scenario(trigger="clean-ticket")
    run = run_shipment(sc)
    dec = last_decision(sc, run, "n4")
    assert dec["reservation_id"] and dec["counters_snapshot"]["agent"] == 1
    r = sc.platform.run.reservations[dec["reservation_id"]]
    assert r["status"] == "confirmed"
    assert sc.platform.run.counter_count("destination", "12 Main St") == 1
    assert sc.platform.run.counter_count("subject", "cust-1") == 2       # the shipment and the reply


@spec("4.6", "A.5", finding="F3")
def test_reservation_is_released_when_the_decision_is_a_hold_or_a_denial():
    sc = build_scenario(trigger="clean-ticket")
    sc.model.amount = 500.0
    run = run_shipment(sc)
    assert run.state == "HELD"
    dec = last_decision(sc, run, "n4")
    assert sc.platform.run.reservations[dec["reservation_id"]]["status"] == "released"
    assert sc.platform.run.counter_count("subject", "cust-1") == 0
    sc2 = build_scenario(behaviour="inject_address")
    run2 = sc2.start(ticket_address="99 Evil Rd")
    sc2.execute(run2)
    dec2 = last_decision(sc2, run2, "n4")
    assert dec2["decision"] == "DENY" and sc2.platform.run.reservations[dec2["reservation_id"]]["status"] == "released"


@spec("4.6", "A.3", finding="F3")
def test_velocity_limit_holds_and_hard_cap_denies():
    sc = build_scenario(trigger="clean-ticket")
    rc = sc.platform.run
    for _ in range(4):
        rc.confirm(rc.reserve({"destination": "12 Main St"}, 3600)[0])          # limit 4 reached
    run = run_shipment(sc)
    assert run.state == "HELD" and events(sc, run, "hold.created", "n4")[-1]["hold_causes"] == ["velocity:destination"]
    for _ in range(3):
        rc.confirm(rc.reserve({"destination": "12 Main St"}, 3600)[0])          # over the hard cap (6)
    sc2 = build_scenario(trigger="clean-ticket")
    sc2.platform.run.counters = rc.counters
    run2 = run_shipment(sc2)
    dec = last_decision(sc2, run2, "n4")
    assert dec["decision"] == "DENY" and dec["rule_id"] == "velocity_hard_cap"


@spec("4.6", "5.2", "A.3", finding="F3")
def test_exposed_runs_use_half_the_velocity_limit():
    sc = build_scenario()                           # the untrusted ticket exposes the run at start
    rc = sc.platform.run
    for _ in range(2):
        rc.confirm(rc.reserve({"destination": "12 Main St"}, 3600)[0])          # 2 = half of the limit 4
    run = run_shipment(sc)
    assert run.state == "HELD" and "velocity:destination" in events(sc, run, "hold.created", "n4")[-1]["hold_causes"]


@spec("4.6", "A.5", finding="F3")
def test_counters_are_reconciled_from_evidence():
    sc = build_scenario(trigger="clean-ticket")
    run = run_shipment(sc)
    rc = sc.platform.run
    rc.counters.clear()                              # RUN lost its in-memory counters
    assert rc.counter_count("agent", "warranty-agent") == 0
    merged = rc.reconcile_counters()
    assert merged == 2 and rc.counter_count("agent", "warranty-agent") == 2 and rc.counter_count("destination", "12 Main St") == 1


@spec("4.6", "6.1", "A.4", finding="F3")
def test_run_outage_uses_pep_local_counters_with_the_degraded_cap():
    sc = build_scenario(trigger="clean-ticket", internal_effect=True, policy=policy_values(degraded_caps={"effects_per_pep": 1}))
    run = sc.start()
    sc.platform.outage("RUN")
    sc.platform.outage("PDP")
    sc.execute(run)
    # the no-factor, scope-anchored note is made on the cached bundle, counted locally; the anchored read
    # that follows cannot be decided locally and the run parks
    assert events(sc, run, "effect.executed", "n0") and last_decision(sc, run, "n0")["rule_id"] == "local_bundle"
    assert sc.pep.local_counters["effects"] == 1 and sc.pep.journal.local_counters["effects"] == 1
    assert run.state == "PARKED"
    # a second effect on the same PEP in the same degraded window is denied by the cap
    sc2 = build_scenario(trigger="clean-ticket", internal_effect=True, policy=policy_values(degraded_caps={"effects_per_pep": 1}))
    sc2.pep.local_counters["effects"] = 1
    run2 = sc2.start()
    sc2.platform.outage("RUN"); sc2.platform.outage("PDP")
    sc2.execute(run2)
    assert last_decision(sc2, run2, "n0")["rule_id"] == "degraded_cap" and not sc2.systems["notes"].records
