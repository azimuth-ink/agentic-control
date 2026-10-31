"""F6 continued: the REG and MGW rows of the degradation matrix; the live schema-hash check; the S1
proxy form's event writers; evidence imported from ungoverned surfaces; the access review."""
import pytest

from agentic_control.common import Refused, Unavailable
from agentic_control.registry import ToolManifest
from conftest import events, last_decision, spec
from warranty import build_scenario


def outage_at(node_id, sc, component):
    inner = sc.pep.enter_node
    fired = []

    def enter(run, node, inputs):
        inner(run, node, inputs)
        if node.id == node_id and not fired:
            fired.append(1)
            sc.platform.outage(component)
    sc.pep.enter_node = enter


@spec("6.1", "A.1", "A.4", finding="F6")
def test_reg_outage_continues_on_cached_manifests_and_refuses_registrations():
    from warranty import policy_values
    v = policy_values()
    v.velocity["subject"]["limit"] = 20                     # two runs on one subject without a velocity hold
    sc = build_scenario(trigger="clean-ticket", policy=v)
    run = sc.start()
    sc.execute(run)                                   # warms the manifest cache
    sc.systems["fulfilment"].records["dev-1"]["replacement_issued"] = False   # a second claim on the device
    sc.platform.outage("REG")
    run2 = sc.start()
    sc.execute(run2)
    assert run2.state == "COMPLETED" and len(sc.systems["fulfilment"].shipments) == 2
    with pytest.raises(Unavailable):
        sc.platform.registry.register_tool(ToolManifest("x", "1", "notes", {"a": "string"}))
    with pytest.raises(Unavailable):
        sc.platform.registry.publish_release(sc.release, sc.platform.policy, {"pep-1.0"})


@spec("6.1", "A.4", finding="F6")
def test_reg_outage_parks_when_the_cached_manifest_expires():
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    sc.execute(run)
    sc.systems["fulfilment"].records["dev-1"]["replacement_issued"] = False
    sc.platform.outage("REG")
    sc.platform.clock.advance(3601)
    sc.platform.ops.republish_stop_list()
    run2 = sc.start()
    sc.execute(run2)
    assert run2.state == "PARKED" and run2.park["reason"] == "REG unavailable"
    sc.platform.outage("REG", down=False)
    assert sc.platform.run.recover(run2) == "RUNNING"
    sc.execute(run2)
    assert run2.state == "COMPLETED"


@spec("A.1", "I5", "3.9", finding="F8")
def test_a_live_schema_hash_mismatch_unregisters_the_tool_until_re_registered():
    sc = build_scenario(trigger="clean-ticket")
    reg = sc.platform.registry
    f = sc.systems["fulfilment"]
    m = reg.tools["ship_replacement"]
    f.advertise("ship_replacement", m.schema, m.description)             # matches: no effect
    run = sc.start()
    sc.execute(run)
    assert run.state == "COMPLETED"
    f.advertise("ship_replacement", {**m.schema, "gift_note": "string"}, "ships a replacement (now with a note)")
    run2 = sc.start()
    sc.execute(run2)
    dec = last_decision(sc, run2, "n4")
    assert dec["rule_id"] == "schema_hash" and dec["decision"] == "DENY"
    assert "ship_replacement" not in reg.tools and "ship_replacement" in reg.unregistered
    assert any("unregistered" in n for n in reg.notifications)
    assert len(sc.systems["fulfilment"].shipments) == 1
    with pytest.raises(Refused):
        reg.get_tool_manifest("ship_replacement")
    # the dependent release no longer lints; re-registration with the new schema restores it
    assert any("unregistered tool ship_replacement" in e for e in reg.lint_release(sc.release, sc.platform.policy, {"pep-1.0"}))
    f.advertise("ship_replacement", m.schema, m.description)
    reg.register_tool(m)
    assert reg.lint_release(sc.release, sc.platform.policy, {"pep-1.0"}) == []


@spec("6.1", "A.8", finding="F6")
def test_mgw_outage_parks_at_the_next_model_call_and_routes_only_within_the_release():
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    outage_at("n2", sc, "MGW")
    sc.execute(run)
    assert run.state == "PARKED" and run.park["reason"] == "MGW unavailable"
    sc.platform.outage("MGW", down=False)
    sc.platform.run.recover(run)
    sc.execute(run)
    assert run.state == "COMPLETED"
    sc2 = build_scenario(trigger="clean-ticket")
    sc2.runtime.model_name = "model-z"                                  # outside the declared route
    run2 = sc2.start()
    sc2.execute(run2)
    assert not events(sc2, run2, "usage.recorded")


@spec("A.8", "4.1", finding="F6")
def test_the_agent_token_budget_is_applied_at_the_gateway():
    from warranty import policy_values
    sc = build_scenario(trigger="clean-ticket", policy=policy_values(token_budget_per_agent=60))
    run = sc.start()
    sc.execute(run)
    assert len(events(sc, run, "usage.recorded")) == 1                 # the second 50-token call exceeded 60
    assert sc.platform.mgw.budgets["warranty-agent"] == 50


@spec("A.4", "A.5", "7", finding="F9")
def test_on_s1_run_writes_the_node_events_from_the_hooks():
    sc = build_scenario(trigger="clean-ticket", surface="S1", form="proxy")
    run = sc.start()
    sc.execute(run)
    assert run.state == "COMPLETED"
    entered = events(sc, run, "node.entered")
    exited = events(sc, run, "node.exited")
    assert entered and all(e["written_by"] == "run" for e in entered)
    assert exited and all(e["written_by"] == "run" for e in exited)
    assert [e["node_id"] for e in entered] == ["n1", "n2", "n3", "n4", "n5", "n6"]
    sc2 = build_scenario(trigger="clean-ticket")
    run2 = sc2.start()
    sc2.execute(run2)
    assert all(e["written_by"] == "pep" for e in events(sc2, run2, "node.entered"))


@spec("7", "D", finding="F6")
def test_vendor_logs_are_imported_as_external_imported(scenario):
    evs = scenario.platform.evs
    eid = evs.import_external("vendor-crm", {"actor": "bot-7", "action": "update_record", "at": "2026-10-31T00:00:00Z"},
                              ["actor", "action", "target", "at", "outcome"])
    e = next(x for x in evs.events if x["event_id"] == eid)
    assert e["type"] == "external.imported" and e["scope"] == "external:vendor-crm"
    assert e["fields_present"] == ["actor", "action", "at"] and e["fields_missing"] == ["target", "outcome"]
    assert evs.payloads.get(e["raw_ref"])["actor"] == "bot-7" and evs.verify()


@spec("A.1", finding="F8")
def test_access_review_compares_grants_with_the_registry(scenario):
    reg = scenario.platform.registry
    clean = reg.access_review(scenario.bundle.entitlements)
    # the example bundle over-grants on purpose: two systems with no tool and a child agent not registered
    assert all(("unused grant" in f) or ("may invoke unregistered agent" in f) for f in clean), clean
    ent = {"warranty-agent": {"tools": ["ship_replacement", "ghost_tool"], "systems": ["fulfilment", "mystery"], "agents": ["agent:nobody"]},
           "ghost-agent": {"tools": [], "systems": [], "agents": []}}
    findings = reg.access_review(ent)
    assert any("unregistered tool ghost_tool" in f for f in findings)
    assert any("unregistered system mystery" in f for f in findings)
    assert any("unregistered agent agent:nobody" in f for f in findings)
    assert any("ghost-agent" in f and "not in the registry" in f for f in findings)
