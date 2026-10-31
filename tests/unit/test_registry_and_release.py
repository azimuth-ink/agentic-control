"""Unit: derived trust fields, factor derivation, the anchoring rule, scope-only bounds, policy evaluation
helpers and the compensation mapping."""
import pytest

from agentic_control.common import Refused
from agentic_control.policy import StopList, Stop, apply_mapping, _op
from agentic_control.registry import Boundary, Registry, SystemCapability, ToolManifest, Trigger
from agentic_control.release import Bound, Node, anchored_params, scope_only


@pytest.fixture
def reg():
    b = Boundary(inside_systems={"crm", "mem", "sink", "ui", "feed"},
                 resolvers={"email": lambda v: str(v).endswith("@corp.example"), "postal_address": lambda v: False},
                 can_resolve_outside={"email": True, "postal_address": True, "internal_queue": False})
    r = Registry(b)
    r.register_system(SystemCapability("crm", "system_of_record", provenance_tag=True, verified_fields={"email"},
                                       pip_relations={"owner": [("crm", "owner")], "email_on_file": [("crm", "email")]}))
    r.register_system(SystemCapability("feed", "system_of_record", external_ingress=True))
    r.register_system(SystemCapability("mem", "memory"))
    r.register_system(SystemCapability("sink", "sink_store"))
    r.register_system(SystemCapability("ui", "interface"))
    return r


def test_derived_classes_follow_the_target_kind(reg):
    m = reg.register_tool(ToolManifest("remember", "1", "mem", {"key": "string", "value": "string"}, writes_fields=[("mem", "value")], parameter_roles={"key": "resource"}))
    assert m.side_effect_class == "internal_store"
    d = reg.register_tool(ToolManifest("post", "1", "ui", {"recipient": "string", "content": "string"}, resource_none_justification="delivery"))
    assert d.side_effect_class == "delivery"
    s = reg.register_tool(ToolManifest("log", "1", "sink", {"sink": "string", "content": "string"}, writes_fields=[("sink", "content")], resource_none_justification="delivery"))
    assert s.side_effect_class == "delivery"
    with pytest.raises(Refused):
        reg.register_tool(ToolManifest("bad", "1", "mem", {"k": "string"}, writes_fields=[("mem", "k")], side_effect_class="external", parameter_roles={"k": "resource"}))


def test_trust_derivations(reg):
    assert reg.external_ingress("feed") and not reg.external_ingress("crm")
    assert reg.agent_writable("mem") and reg.agent_writable("sink") and not reg.agent_writable("crm")
    assert reg.provenance_tag("crm") and reg.provenance_tag("mem") and not reg.provenance_tag("feed")
    read_crm = ToolManifest("read_crm", "1", "crm", {"id": "string"}, parameter_roles={"id": "resource"})
    read_feed = ToolManifest("read_feed", "1", "feed", {"q": "string"})
    assert reg.untrusted_source(read_crm) == "per_item" and reg.untrusted_source(read_feed) == "always"
    reg.register_system(SystemCapability("warehouse", "system_of_record")) if reg.boundary.inside_systems.add("warehouse") is None else None
    assert reg.untrusted_source(ToolManifest("w", "1", "warehouse", {"q": "string"})) == "never"
    reg.register_tool(ToolManifest("write_w", "1", "warehouse", {"q": "string"}, side_effect_class="reversible_internal",
                                   writes_fields=[("warehouse", "q")], parameter_roles={"q": "resource"}))
    assert reg.agent_writable("warehouse") and reg.untrusted_source(ToolManifest("w", "1", "warehouse", {"q": "string"})) == "always"
    assert reg.payload_trust(Trigger("t", "feed", "subject_claim")) == "untrusted"
    assert reg.payload_trust(Trigger("t", "crm", "subject_claim")) == "per_item"
    assert reg.payload_trust(Trigger("t", "warehouse", "subject_claim")) == "untrusted"


def test_anchor_capability(reg):
    assert reg.relation_capable("email_on_file")             # verified, tagged field
    assert reg.relation_capable("owner")                      # clean system (no ingress, not agent-writable)
    reg.register_tool(ToolManifest("edit_owner", "1", "crm", {"id": "string", "owner": "string"}, side_effect_class="reversible_internal",
                                   writes_fields=[("crm", "owner")], parameter_roles={"id": "resource"}))
    assert not reg.relation_capable("owner")                  # a registered tool writes the field
    assert reg.relation_capable("email_on_file")              # still verified
    assert not reg.relation_capable("nonexistent")


def test_factor_derivation(reg):
    reg.boundary.inside_systems.add("pay")
    reg.register_system(SystemCapability("pay", "system_of_record"))
    m = ToolManifest("wire", "1", "pay", {"to": "string", "amount": "number"}, side_effect_class="financial_legal",
                     parameter_roles={"to": "destination", "amount": "amount"}, destination_class="email", compensation="irreversible")
    assert reg.static_factors(m) == {"irreversible", "external", "regulated"}
    assert reg.derive_factors(m, {"to": "ops@corp.example"}) == {"irreversible", "external", "regulated"}   # class alone makes it external
    note = ToolManifest("note", "1", "pay", {"to": "string"}, side_effect_class="reversible_internal", parameter_roles={"to": "destination"},
                        destination_class="email", compensation={"reversing_tool": "x", "params": {}})
    assert reg.derive_factors(note, {"to": "ops@corp.example"}) == set()
    assert reg.derive_factors(note, {"to": "someone@gmail.example"}) == {"external"}
    assert reg.static_factors(note) == {"external"}           # the class can resolve outside: the linter assumes it
    sens = ToolManifest("dump", "1", "pay", {"q": "string"}, reads_data_class="restricted", bulk=True)
    assert reg.derive_factors(sens, {}) == {"sensitive"}


def test_anchoring_rule_and_scope_only():
    scopes = {"templates"}
    bounds = [Bound("anchor_rel", param="device_id", rel="owner", anchor="subject"),
              Bound("eq_rel_param", param="destination", rel="verified_ship_address", q="device_id"),
              Bound("in_scope", param="template_id", scope="templates"),
              Bound("op", param="amount", op="<=", const=10),
              Bound("pred", param="device_id", rel="replacement_issued", value=False)]
    assert anchored_params(bounds, scopes) == {"device_id", "destination", "template_id"}
    # a relation of a parameter that is itself unanchored anchors nothing
    assert anchored_params([Bound("eq_rel_param", param="destination", rel="r", q="free")], scopes) == set()
    assert anchored_params([Bound("eq_rel_anchor", param="destination", rel="address_on_file", anchor="acting_user")], scopes) == {"destination"}
    assert anchored_params([Bound("anchor_rel", param="x", rel="r", anchor="unknown_anchor")], scopes) == set()
    assert scope_only([Bound("in_scope", param="t", scope="s"), Bound("limit", param="a", auto=1, hard=2)])
    assert not scope_only(bounds)


def test_node_declared_tools_and_stop_scope():
    n = Node("n", "loop", tools=["a", "b"])
    assert n.declared_tools() == {"a", "b"}
    assert Node("m", "effect", tool="x").declared_tools() == {"x"}
    sl = StopList(1, 0, 10, [Stop("s1", "tool", "ship", 1), Stop("s2", "surface", "S4", 1)])
    assert sl.in_scope("agent", "ship", "S2").stop_id == "s1"
    assert sl.in_scope("agent", None, "S4").stop_id == "s2"
    assert sl.in_scope("agent", "other", "S2") is None
    assert StopList(1, 0, 10, [Stop("f", "fleet", None, 1)]).in_scope("anyone", None, "S1") is not None


def test_compensation_mapping_and_operators():
    mapping = {"reversing_tool": "cancel", "params": {"shipment_id": "result.shipment_id", "device": "parameters.device_id"}}
    assert apply_mapping(mapping, {"device_id": "dev-1"}, {"shipment_id": "s-9"}) == {"shipment_id": "s-9", "device": "dev-1"}
    assert _op(3, "<=", 3) and _op(2, "<", 3) and not _op(4, "<=", 3) and _op("a", "==", "a") and _op(1, "!=", 2)
