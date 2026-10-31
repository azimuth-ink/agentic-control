"""F9. Bounds and the node-type matrix at run time: the PEP calls only what the node declares; bounds are
denials, never holds; loop caps cut planning; deliveries are bounded to declared sinks and cleared
recipients; a spawn is decided per principal; the run-state hook order is enforced."""
import pytest

from agentic_control.common import Denied
from agentic_control.release import Bound, Node
from conftest import decisions, events, last_decision, spec
from warranty import build_scenario


@spec("A.3", "A.1", finding="F9")
def test_an_undeclared_tool_is_denied_before_any_other_rule(scenario):
    run = scenario.start()
    scenario.model.propose = (lambda orig: lambda r, n, c: {**orig(r, n, c), "__tool__": "add_note"} if n.id == "n1" else orig(r, n, c))(scenario.model.propose)
    scenario.execute(run)
    dec = last_decision(scenario, run, "n1")
    assert dec["decision"] == "DENY" and dec["rule_id"] == "node_declaration"


@spec("A.3", "4.3", finding="F9")
def test_a_wrong_device_fails_the_owner_anchor():
    sc = build_scenario(behaviour="wrong_device")
    run = sc.start()
    sc.execute(run)
    dec = last_decision(sc, run, "n1")
    assert dec["decision"] == "DENY" and dec["rule_id"] == "bounds" and "owner" in dec["reason"]
    assert not sc.systems["fulfilment"].shipments


@spec("A.3", "4.3", finding="F9")
def test_bounds_are_never_a_hold_cause():
    sc = build_scenario(behaviour="over_limit", trigger="clean-ticket")        # 5000 > hard 1000
    run = sc.start()
    sc.execute(run)
    dec = last_decision(sc, run, "n4")
    assert dec["decision"] == "DENY" and dec["rule_id"] == "hard_limit"
    assert not events(sc, run, "hold.created")
    assert run.state == "COMPLETED" and len(sc.systems["mail_relay"].sent) == 1   # the denial branch replied


@spec("A.3", "4.3", finding="F9")
def test_a_template_outside_the_release_scope_is_denied():
    sc = build_scenario(trigger="clean-ticket")
    orig = sc.model.propose
    sc.model.propose = lambda r, n, c: {**orig(r, n, c), "template_id": "tpl-free-text"} if n.id == "n5" else orig(r, n, c)
    run = sc.start()
    sc.execute(run)
    dec = last_decision(sc, run, "n5")
    assert dec["decision"] == "DENY" and "not in scope templates" in dec["reason"]
    assert not sc.systems["mail_relay"].sent


@spec("A.3", "5.4", finding="F9")
def test_reply_destination_must_equal_the_address_on_file():
    sc = build_scenario(behaviour="inject_reply")
    run = sc.start(ticket_address="attacker@example.net")
    sc.execute(run)
    dec = last_decision(sc, run, "n5")
    assert dec["decision"] == "DENY" and "address_on_file" in dec["reason"]
    assert not sc.systems["mail_relay"].sent


@spec("A.3", "4.3", finding="F9")
def test_predicate_bounds_deny_a_repeat_replacement():
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    sc.execute(run)
    assert len(sc.systems["fulfilment"].shipments) == 1
    run2 = sc.start()
    sc.execute(run2)
    dec = last_decision(sc, run2, "n4")
    assert dec["decision"] == "DENY" and "replacement_issued" in dec["reason"]
    assert len(sc.systems["fulfilment"].shipments) == 1


@spec("A.3", "A.4", "4.1", finding="F9")
def test_loop_step_cap_and_token_cap_cut_planning():
    sc = build_scenario(trigger="clean-ticket")
    sc.release.node("n2").step_cap = 1
    run = sc.start()
    sc.execute(run)
    assert run.state == "COMPLETED"
    n2_decisions = decisions(sc, run, "n2")
    assert len(n2_decisions) == 1                                 # the second read was refused by the cap, not decided
    assert sc.pep.step_counts[(run.run_id, "n2")] >= 2
    sc2 = build_scenario(trigger="clean-ticket")
    sc2.release.node("n2").token_cap = 50
    run2 = sc2.start()
    sc2.execute(run2)
    usage = events(sc2, run2, "usage.recorded", "n2")
    assert len(usage) == 1                                         # cap reached on the first call: no second credential
    assert (run2.run_id, "n2") in sc2.pep.capped_nodes


@spec("A.3", "A.7", "4.2", finding="F9")
def test_delivery_to_an_undeclared_sink_is_denied(scenario):
    orig = scenario.model.propose
    scenario.model.propose = lambda r, n, c: {**orig(r, n, c), "sink": "public-feed"} if n.id == "n6" else orig(r, n, c)
    run = scenario.start()
    scenario.execute(run)
    assert events(scenario, run, "delivery.failed", "n6")
    assert not scenario.systems["case_log"].records


@spec("A.3", "A.7", "4.2", finding="F9")
def test_delivery_to_an_interface_recipient_is_bounded_by_clearance():
    from agentic_control.dbs import Interface
    from agentic_control.registry import SystemCapability, ToolManifest
    sc = build_scenario(trigger="clean-ticket")
    p = sc.platform
    p.boundary.inside_systems.add("chat")
    chat = Interface("chat", p.ids)
    p.systems["chat"] = chat
    p.registry.register_system(SystemCapability("chat", "interface"))
    p.registry.register_tool(ToolManifest("post_message", "1", "chat", {"recipient": "string", "content": "string"}, resource_none_justification="delivery"))
    sc.release.nodes[:] = [n for n in sc.release.nodes if n.id != "n6"] + [
        Node("n6", "output", tool="post_message", bounds=[Bound("in_scope", param="recipient", scope="recipients")])]
    sc.release.scopes["recipients"] = ["ops-channel", "cust-1"]
    sc.release.tools["post_message"] = "1"
    sc.bundle.entitlements["warranty-agent"]["tools"].append("post_message")
    sc.bundle.entitlements["warranty-agent"]["systems"].append("chat")
    sc.bundle.recipient_clearance["ops-channel"] = "internal"
    p.publish_bundle(sc.bundle)
    p.registry.publish_release(sc.release, p.policy, {"pep-1.0"})
    orig = sc.model.propose
    sc.model.propose = lambda r, n, c: {"recipient": "ops-channel", "content": "done"} if n.id == "n6" else orig(r, n, c)
    run = sc.start()
    sc.execute(run)
    dec = last_decision(sc, run, "n6", "delivery")
    assert dec["decision"] == "DENY" and dec["rule_id"] == "delivery_recipient"     # confidential data, internal channel
    sc.model.propose = lambda r, n, c: {"recipient": "cust-1", "content": "done"} if n.id == "n6" else orig(r, n, c)
    run2 = sc.start()
    sc.execute(run2)
    assert chat.delivered and chat.delivered[-1]["recipient"] == "cust-1"


@spec("A.3", "4.7", finding="F9")
def test_spawn_is_decided_per_principal():
    sc = build_scenario(with_child=True, trigger="clean-ticket")
    sc.bundle.entitlements["warranty-agent"]["agents"] = []
    sc.platform.publish_bundle(sc.bundle)
    run = sc.start()
    sc.execute(run)
    dec = last_decision(sc, run, "h1", "spawn")
    assert dec["decision"] == "DENY" and dec["rule_id"] == "intersection"
    assert not sc.child["runs"]


@spec("A.3", "I2", finding="F9")
def test_intersection_denies_a_tool_or_system_outside_the_agents_entitlement():
    sc = build_scenario(trigger="clean-ticket")
    sc.bundle.entitlements["warranty-agent"]["tools"].remove("ship_replacement")
    sc.platform.publish_bundle(sc.bundle)
    run = sc.start()
    sc.execute(run)
    dec = last_decision(sc, run, "n4")
    assert dec["decision"] == "DENY" and dec["rule_id"] == "intersection"


@spec("A.5", "A.4", finding="F9")
def test_calls_for_a_node_are_rejected_until_run_confirms_node_entered(scenario):
    run = scenario.start()
    n4 = scenario.release.node("n4")
    with pytest.raises(Denied, match="node_entered"):
        scenario.pep.call(run, n4, "ship_replacement", {"device_id": "dev-1"})
    # out of order: n4 is not the checkpointed next node
    assert scenario.platform.run.node_entered(run, "n4", "effect", "p:x") is False
    assert scenario.platform.run.node_entered(run, "n1", "read", "p:x") is True


@spec("A.4", "A.5", finding="F9")
def test_a_held_or_parked_run_makes_no_runtime_originated_calls():
    sc = build_scenario(trigger="clean-ticket")
    sc.model.amount = 500.0
    run = sc.start()
    sc.execute(run)
    assert run.state == "HELD"
    with pytest.raises(Denied, match="held or parked"):
        sc.pep.call(run, sc.release.node("n4"), "ship_replacement", run.holds["n4"].pending["parameters"])


@spec("A.3", "A.4", finding="F9")
def test_effects_only_from_effect_nodes_and_sanitizers_only_from_sanitize_nodes(scenario):
    run = scenario.start()
    scenario.platform.run.node_entered(run, "n1", "read", "p:x")
    with pytest.raises(Denied):
        scenario.pep.call(run, scenario.release.node("n1"), "ship_replacement", {"device_id": "dev-1"})
    with pytest.raises(Denied):
        scenario.pep.call(run, scenario.release.node("n1"), "proposal_extractor", {"device_id": "dev-1"})


@spec("A.4", "4.4", finding="F9")
def test_dlp_rejection_is_a_definitive_negative_on_the_failure_branch():
    sc = build_scenario(trigger="clean-ticket")
    sc.platform.dlp.patterns = [__import__("re").compile("PART-100")]
    run = sc.start()
    sc.execute(run)
    failed = events(sc, run, "effect.failed", "n4")[-1]
    assert failed["error"] == "dlp" and not sc.systems["fulfilment"].shipments
    assert run.state == "COMPLETED" and len(sc.systems["mail_relay"].sent) == 1     # failure branch = denial branch here
    assert "n4" not in run.in_doubt_cache


@spec("4.5", "A.5", finding="F9")
def test_a_child_run_shares_the_trace_and_extends_the_principal_chain():
    sc = build_scenario(with_child=True, trigger="clean-ticket")
    run = sc.start()
    sc.execute(run)
    child = sc.child["runs"][0]
    assert child.trace_id == run.trace_id and child.parent_run_id == run.run_id
    assert child.agents == ["warranty-agent", "triage-agent"]
    created = events(sc, child, "run.created")[0]
    assert created["trigger_kind"] == "child" and created["principal_chain"]["agents"] == ["warranty-agent", "triage-agent"]
