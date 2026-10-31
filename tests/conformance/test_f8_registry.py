"""F8. The registry and the release linter: derived trust fields cannot be authored; a release is
publishable only when every effect is tiered within the surface cap, anchored, and has a compensation
and a resumption path; anchor capability is recomputed and a lost anchor suspends dependent releases."""
import pytest

from agentic_control.common import Refused
from agentic_control.registry import Agent, SystemCapability, ToolManifest
from agentic_control.release import Bound, Node, Release
from conftest import decisions, events, last_decision, spec
from warranty import AGENT, build_scenario, policy_values


def lint(sc, rel):
    return sc.platform.registry.lint_release(rel, sc.platform.policy, {"pep-1.0"})


@spec("A.1", "7", finding="F8")
def test_tier_caps_by_surface_and_form():
    with pytest.raises(Refused, match="exceeds the cap"):
        build_scenario(surface="S4", form="sidecar", tier_n4="A2")        # S4 with PEP-E: A1, every call held
    with pytest.raises(Refused, match="exceeds the cap"):
        build_scenario(surface="S2", form="sdk", tier_n4="A3")            # SDK form: A2 at most
    sc = build_scenario(surface="S2", form="sdk", tier_n4="A2")
    assert sc.release.release_id in sc.platform.registry.releases
    with pytest.raises(Refused, match="no tier cap"):
        build_scenario(surface="S1", form="sidecar")                      # S1 runs a proxy


@spec("A.1", "4.4", finding="F8")
def test_a_factored_effect_is_never_A3():
    with pytest.raises(Refused, match="never A3"):
        build_scenario(regulated_irreversible=True, tier_n4="A3", trigger="clean-ticket")


@spec("A.1", finding="F8")
def test_effect_without_compensation_or_with_a_wrong_compensate_node_is_refused(scenario):
    sc = scenario
    rel = sc.release
    nodes = [n for n in rel.nodes]
    n4 = rel.node("n4")
    n4.compensate = None
    assert any("compensate node or irreversible" in e for e in lint(sc, rel))
    n4.compensate = "n6"
    assert any("must name a compensate node" in e for e in lint(sc, rel))
    n4.compensate = "c1"
    assert lint(sc, rel) == []


@spec("A.1", "4.3", finding="F8")
def test_unanchored_resource_or_destination_role_is_refused(scenario):
    rel = scenario.release
    n4 = rel.node("n4")
    saved = list(n4.bounds)
    n4.bounds = [b for b in saved if b.param != "destination"]
    errs = lint(scenario, rel)
    assert any("destination with role destination is not anchored" in e for e in errs)
    n4.bounds = [b for b in saved if b.param != "device_id" or b.form == "pred"]
    assert any("device_id with role resource is not anchored" in e for e in lint(scenario, rel))
    n4.bounds = saved
    assert lint(scenario, rel) == []


@spec("A.1", finding="F8")
def test_read_tools_with_a_resource_role_must_be_anchored(scenario):
    rel = scenario.release
    n1 = rel.node("n1")
    saved = n1.bounds
    n1.bounds = []
    assert any("read tool lookup_devices has a resource role that is not anchored" in e for e in lint(scenario, rel))
    n1.bounds = saved


@spec("A.1", "A.2", finding="F8")
def test_resumption_path_required_for_A1_and_A2_effects():
    sc = build_scenario(trigger="clean-ticket")
    pol = policy_values(grants_permitted=False, substitution_permitted=False)
    errs = sc.platform.registry.lint_release(sc.release, pol, {"pep-1.0"})
    assert any("no resumption path" in e for e in errs)
    pol = policy_values(grants_permitted=False, substitution_permitted=True)
    assert sc.platform.registry.lint_release(sc.release, pol, {"pep-1.0"}) == []
    # substitution does not count for a node anchored to the acting user
    sc2 = build_scenario(trigger="console")
    errs = sc2.platform.registry.lint_release(sc2.release, pol, {"pep-1.0"})
    assert any("no resumption path" in e for e in errs)


@spec("A.1", "4.4", finding="F8")
def test_a_new_bundle_without_grants_flags_held_effects_to_the_owner():
    sc = build_scenario(trigger="console")
    sc.model.amount = 500.0
    run = sc.start(user="advisor-1")
    sc.execute(run)
    assert run.state == "HELD"
    reg = sc.platform.registry
    reg.on_bundle_published(policy_values(grants_permitted=False, substitution_permitted=True))
    assert sc.release.denied_effects == {"n4", "n5"} or "n4" in sc.release.denied_effects
    assert any("lost their resumption path" in n for n in reg.notifications)
    res = sc.platform.ops.approve(run, "n4", "approver-1")
    assert res["status"] == "denied" and last_decision(sc, run, "n4")["rule_id"] == "no_resumption_path"


@spec("A.1", finding="F8")
def test_regulated_irreversible_auto_limit_at_or_below_the_two_approver_threshold():
    with pytest.raises(Refused, match="two-approver threshold"):
        build_scenario(regulated_irreversible=True, trigger="clean-ticket", policy=policy_values(two_approver_threshold=50))


@spec("A.1", finding="F8")
def test_derived_classes_cannot_be_authored(scenario):
    reg = scenario.platform.registry
    with pytest.raises(Refused):
        reg.register_tool(ToolManifest("fake_delivery", "1", "mail_relay", {"recipient": "string"}, side_effect_class="delivery"))
    with pytest.raises(Refused):
        reg.register_tool(ToolManifest("fake_spawn", "1", "notes", {"x": "string"}, side_effect_class="spawn"))
    with pytest.raises(Refused):
        reg.register_tool(ToolManifest("fake_store", "1", "notes", {"x": "string"}, side_effect_class="internal_store"))


@spec("A.1", "ADR-25", finding="F8")
def test_a_tool_with_an_external_target_or_outward_destination_cannot_be_class_none(scenario):
    reg = scenario.platform.registry
    scenario.platform.boundary.inside_systems.discard("web-api")
    reg.register_system(SystemCapability("web-api", "system_of_record"))
    with pytest.raises(Refused, match="none"):
        reg.register_tool(ToolManifest("web_read", "1", "web-api", {"url": "string"}))
    with pytest.raises(Refused, match="none"):
        reg.register_tool(ToolManifest("lookup_by_email", "1", "notes", {"email": "string"},
                                       parameter_roles={"email": "destination"}, destination_class="email"))


@spec("A.1", "A.7", "ADR-26", finding="F8")
def test_memory_sink_and_interface_kinds_only_inside_the_boundary(scenario):
    reg = scenario.platform.registry
    for kind in ("memory", "sink_store", "interface"):
        with pytest.raises(Refused):
            reg.register_system(SystemCapability(f"outside-{kind}", kind))


@spec("A.1", finding="F8")
def test_one_system_is_registered_once_under_one_kind(scenario):
    reg = scenario.platform.registry
    scenario.platform.boundary.inside_systems.add("fulfilment-2")
    with pytest.raises(Refused, match="already registered"):
        reg.register_system(SystemCapability("fulfilment-2", "sink_store", endpoint="fulfilment"))


@spec("A.1", "4.3", finding="F8")
def test_a_registration_that_would_break_a_published_anchor_is_refused():
    with pytest.raises(Refused, match="not anchor-capable"):
        build_scenario(ship_address_editable=True)          # a writing tool on the anchor field, before publish
    sc = build_scenario()
    reg = sc.platform.registry
    with pytest.raises(Refused, match="remove anchor capability"):
        reg.register_tool(ToolManifest("update_ship_address", "1", "fulfilment", {"device_id": "string", "ship_address": "string"},
                                       side_effect_class="reversible_internal", writes_fields=[("fulfilment", "ship_address")],
                                       parameter_roles={"device_id": "resource"}, compensation="irreversible"))


@spec("A.1", "4.3", finding="F8")
def test_a_failed_feed_review_suspends_dependent_releases_and_the_pdp_denies():
    sc = build_scenario(trigger="clean-ticket")
    reg = sc.platform.registry
    sc.platform.boundary.inside_systems.add("address_feed")
    reg.register_system(SystemCapability("address_feed", "system_of_record", provenance_tag=True))
    reg.register_feed_review("fulfilment", "address_feed", True)
    f = reg.systems["fulfilment"]
    reg.register_system(SystemCapability("fulfilment", "system_of_record", provenance_tag=True, presentation="per_agent",
                                         preview_tool="preview_shipment", idempotency=True, verified_fields={"ship_address"},
                                         pip_relations=f.pip_relations, sources=["address_feed"], feed_reviews={"address_feed": True}))
    assert reg.relation_capable("verified_ship_address") and not sc.release.suspended
    v = reg.anchor_version
    reg.register_feed_review("fulfilment", "address_feed", False)            # a change REG cannot refuse
    assert reg.anchor_version == v + 1 and sc.release.suspended
    assert any("suspended" in n for n in reg.notifications)
    run = sc.start()
    sc.execute(run)
    # every decision under a suspended release is denied; the first read ends the run
    assert last_decision(sc, run, "n1")["rule_id"] == "release_suspended" and not sc.systems["fulfilment"].shipments
    assert run.state == "COMPLETED" and not events(sc, run, "effect.executed")
    # republishing is refused until the anchor is capable again
    with pytest.raises(Refused, match="not anchor-capable"):
        reg.publish_release(sc.release, sc.platform.policy, {"pep-1.0"})
    reg.register_feed_review("fulfilment", "address_feed", True)
    reg.publish_release(sc.release, sc.platform.policy, {"pep-1.0"})
    assert not sc.release.suspended


@spec("A.1", "A.6", "I5", finding="F8")
def test_a_release_for_an_unregistered_agent_or_surface_mismatch_is_refused(scenario):
    reg = scenario.platform.registry
    rel = scenario.release
    bad = Release("ghost", "1.0", "S2", "sidecar", "pep-1.0", rel.nodes, rel.tools, rel.scopes)
    assert lint(scenario, bad) == ["unknown agent"]
    reg.register_agent(Agent("other", owner="o", builder="b", surface="S1"))
    bad = Release("other", "1.0", "S2", "sidecar", "pep-1.0", rel.nodes, rel.tools, rel.scopes)
    assert any("surface must equal" in e for e in lint(scenario, bad))


@spec("A.1", finding="F8")
def test_fast_path_releases_carry_no_effects_and_read_only_internal(scenario):
    rel = scenario.release
    fast = Release(AGENT, "1.1", "S2", "sidecar", "pep-1.0", rel.nodes, rel.tools, rel.scopes, fast_path=True)
    errs = lint(scenario, fast)
    assert any("fast path: graph has an effect node" in e for e in errs)
    assert any("reads above internal" in e for e in errs)


@spec("A.1", finding="F8")
def test_pep_version_must_be_allow_listed(scenario):
    rel = scenario.release
    errs = scenario.platform.registry.lint_release(rel, scenario.platform.policy, {"pep-0.9"})
    assert "PEP version not on the allow-list" in errs
