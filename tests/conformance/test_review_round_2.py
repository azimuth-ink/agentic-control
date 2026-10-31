"""Regressions pinned after the second independent review: the runtime is builder code and gets nothing
of the control plane; people act through OPS with identity-provider assertions; IDS holds the run's
delegation state and honours revocation."""
import pytest

from agentic_control.common import Denied, Refused
from agentic_control.crypto import Signer
from agentic_control.release import Node
from conftest import events, last_decision, spec
from warranty import AGENT, build_scenario


@spec("A.4", "A.5", "4.3", finding="F9")
def test_a_forged_node_object_with_a_real_id_does_not_change_the_bounds():
    """Review-2 item 1: the PEP evaluates the release's node, not the runtime's object."""
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    forged = Node("n1", "read", tool="lookup_devices", bounds=[])          # no owner bound
    sc.pep.enter_node(run, forged, {})
    with pytest.raises(Denied):
        sc.pep.call(run, forged, "lookup_devices", {"device_id": "dev-9"})  # another customer's device
    dec = last_decision(sc, run, "n1")
    assert dec["decision"] == "DENY" and dec["rule_id"] == "bounds"


@spec("A.5", "4.2", finding="F9")
def test_a_runtime_cannot_jump_to_an_undeclared_branch():
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    n1 = sc.release.node("n1")
    sc.pep.enter_node(run, n1, {})
    sc.pep.call(run, n1, "lookup_devices", {"device_id": "dev-1"})
    with pytest.raises(Denied, match="not a declared branch"):
        sc.pep.exit_node(run, n1, {}, branch="n6")
    with pytest.raises(Denied, match="not a declared branch"):
        sc.platform.run.checkpoint(run, "n1", {}, {}, branch="n6")


@spec("A.4", "A.5", "B.2", finding="F7")
def test_only_a_run_signed_single_use_instruction_reaches_the_pep():
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    sc.execute(run)
    with pytest.raises(Denied, match="RUN-signed"):
        sc.pep.instruct(run, "c1", "compensation", original_node="n4")
    forged = Signer("not-run").sign({"run": run.run_id, "node": "c1", "purpose": "compensation", "nonce": "x"})
    with pytest.raises(Denied, match="RUN-signed"):
        sc.pep.instruct(run, "c1", "compensation", instruction=forged, original_node="n4")
    real = sc.platform.run.signer.sign({"run": run.run_id, "node": "c1", "purpose": "replay", "nonce": "y"})
    with pytest.raises(Denied, match="does not name"):
        sc.pep.instruct(run, "c1", "compensation", instruction=real, original_node="n4")
    ok = sc.platform.run.signer.sign({"run": run.run_id, "node": "c1", "purpose": "compensation", "nonce": "z"})
    assert sc.pep.instruct(run, "c1", "compensation", instruction=ok, original_node="n4")["status"] == "executed"
    with pytest.raises(Denied, match="already used"):
        sc.pep.instruct(run, "c1", "compensation", instruction=ok, original_node="n4")
    assert sc.systems["fulfilment"].shipments["ship-1"]["status"] == "cancelled"


@spec("A.9", "A.5", "I8", finding="F5")
def test_resolver_and_owner_actions_need_an_identity_provider_assertion():
    from warranty import policy_values
    sc = build_scenario(trigger="clean-ticket", policy=policy_values(consecutive_replays=0))
    sc.systems["fulfilment"].fail_next = "indeterminate_but_executed"
    run = sc.start()
    sc.execute(run)
    rc = sc.platform.run
    with pytest.raises(Refused, match="assertion"):
        rc.record_outcome(run, "n4", "not_executed", "evidence:q")               # no assertion at all
    forged = Signer("imposter").sign({"approver": "oncall-resolver"})
    with pytest.raises(Refused, match="assertion"):
        rc.record_outcome(run, "n4", "not_executed", "evidence:q", assertion=forged)
    with pytest.raises(Refused, match="not the resolver"):
        sc.platform.ops.record_outcome(run, "n4", "not_executed", "evidence:q", resolver="someone-else")
    with pytest.raises(Refused):
        sc.platform.ops.owner_close(run, "loss_accepted", "not-the-owner")
    sc.platform.ops.record_outcome(run, "n4", "executed", "evidence:q", {"shipment_id": "ship-1"})
    assert events(sc, run, "effect.executed", "n4")[-1]["resolver"] == "oncall-resolver"


@spec("A.5", "5.1", finding="F1")
def test_human_input_carries_an_asserted_role_not_a_claimed_one():
    sc = build_scenario(trigger="clean-ticket")
    sc.platform.registry.agents[AGENT].input_roles_internal = {"advisor"}
    sc.release.nodes.insert(1, Node("h0", "human", input_role="advisor"))
    run = sc.start()
    sc.execute(run)
    assert run.state == "HELD"
    with pytest.raises(Refused, match="assertion"):
        sc.platform.run.provide_input(run, "h0", "text", {"payload": {"approver": "x", "role": "advisor"}})
    sc.platform.ops.provide_input(run, "h0", "a customer pasted this", person="cust-1", role="customer")
    assert run.exposed is True and any(t.startswith("human:") for t in run.tainted_reads)
    sc2 = build_scenario(trigger="clean-ticket")
    sc2.platform.registry.agents[AGENT].input_roles_internal = {"advisor"}
    sc2.release.nodes.insert(1, Node("h0", "human", input_role="advisor"))
    run2 = sc2.start()
    sc2.execute(run2)
    sc2.platform.ops.provide_input(run2, "h0", "internal note", person="advisor-1", role="advisor")
    assert run2.exposed is False


@spec("A.6", "A.2", "4.4", finding="F4")
def test_ids_issues_delegated_credentials_only_against_the_runs_own_delegation_state():
    sc = build_scenario(trigger="console")
    run = sc.start(user="advisor-1")
    ids = sc.platform.ids
    rel = {"agent_id": AGENT, "version": "1.0", "surface": "S2", "pep_form": "sidecar"}
    ids.create_session("someone-else")
    with pytest.raises(Refused, match="no delegation"):
        ids.issue_credential("wl-1", run.run_id, rel, "n4", {}, {"acting_user": "someone-else", "agents": [AGENT]}, "fulfilment", "normal")
    cred = ids.issue_credential("wl-1", run.run_id, rel, "n4", {}, {"acting_user": "advisor-1", "agents": [AGENT]}, "fulfilment", "normal")
    assert ids.verify_credential(cred, "wl-1", "fulfilment")
    ids.revoke(run=run.run_id)
    assert not ids.verify_credential(cred, "wl-1", "fulfilment")               # revocation reaches live credentials
    ids.allowlist.clear()
    with pytest.raises(Refused, match="allow-list"):
        ids.issue_credential("wl-1", "other", rel, "n4", {}, {"acting_user": None, "agents": [AGENT]}, "fulfilment", "normal")


@spec("A.6", "4.4", finding="F4")
def test_substitution_leaves_the_approver_with_no_standing_delegation():
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
    assert "approver-1" not in sc.platform.ids.delegations


@spec("4.7", "A.6", finding="F4")
def test_a_child_run_gets_the_parents_delegation_state_from_ids():
    sc = build_scenario(with_child=True, trigger="console")
    run = sc.start(user="advisor-1")
    sc.execute(run)
    child = sc.child["runs"][0]
    assert sc.platform.ids.run_users[child.run_id] == "advisor-1"
    assert run.state == "COMPLETED"


@spec("4.3", "A.3", "5.3", finding="F9")
def test_a_non_finite_or_missing_amount_cannot_pass_a_limit():
    """Review-2 item 2."""
    from agentic_control.dbs import identifier_numeric_extractor
    fn = identifier_numeric_extractor(r"[A-Za-z]+-\d+", {"amount": "number", "sku": "identifier"})
    acc, rej = fn({"amount": "nan", "sku": "PART-1"})
    assert "amount" in rej and acc == {"sku": "PART-1"}
    acc, rej = fn({"amount": float("inf"), "sku": "PART-1"})
    assert "amount" in rej
    sc = build_scenario(trigger="clean-ticket")
    orig = sc.model.propose
    sc.model.propose = lambda r, n, c: {**orig(r, n, c), "amount": float("nan")} if n.id == "n4" else orig(r, n, c)
    run = sc.start()
    sc.execute(run)
    dec = last_decision(sc, run, "n4")
    assert dec["decision"] == "DENY" and dec["rule_id"] == "hard_limit" and "finite" in dec["reason"]
    sc2 = build_scenario(trigger="clean-ticket")
    orig2 = sc2.model.propose
    sc2.model.propose = lambda r, n, c: {k: v for k, v in orig2(r, n, c).items() if k != "amount"} if n.id == "n4" else orig2(r, n, c)
    run2 = sc2.start()
    sc2.execute(run2)
    assert last_decision(sc2, run2, "n4")["rule_id"] == "schema" and not sc2.systems["fulfilment"].shipments


@spec("5.1", "A.1", finding="F1")
def test_untagged_fields_from_a_tagged_source_are_tainted():
    """Review-2 item 4: a per_item trigger payload and a tagging system's record with an untagged field."""
    sc = build_scenario(trigger="clean-ticket")
    env = sc.registry_signer.sign({"trigger_id": "clean-ticket", "kind": "subject_claim", "subject": "cust-1", "timestamp": 0})
    sc.platform.registry.triggers["clean-ticket"].source_system = "fulfilment"       # a provenance-tagged source
    run = sc.platform.run.start_run(sc.release, "clean-ticket", env, {"note": "plain string, no tag"}, "wl-1")
    assert run.exposed is True                                                       # untagged field: tainted
    run2 = sc.platform.run.start_run(sc.release, "clean-ticket", env, {"note": {"value": "x", "tainted": False}}, "wl-1")
    assert run2.exposed is False
    f = sc.systems["fulfilment"]
    f.records["dev-7"] = {"device_id": "dev-7", "ship_address": "1 Untagged Way"}   # no _tags at all
    rel = {"agent_id": AGENT, "version": "1.0", "surface": "S2", "pep_form": "sidecar"}
    cred = sc.platform.ids.issue_credential("wl-1", "r", rel, "n", {}, {"acting_user": None, "agents": [AGENT]}, "fulfilment", "normal")
    items = f.read("preview_shipment", {"device_id": "dev-7"}, cred, "wl-1")
    assert items and items[0]["tainted"] is True
    f.records["dev-8"] = {"device_id": "dev-8", "ship_address": "2 Half Tagged", "_tags": {"ship_address": "verified"}}
    assert f.read("preview_shipment", {"device_id": "dev-8"}, cred, "wl-1")[0]["tainted"] is True


@spec("5.1", "A.1", finding="F1")
def test_what_an_effect_returns_is_subject_to_the_source_rule():
    """Review-2 item 4c: a write tool's result from an agent-writable system taints the run."""
    sc = build_scenario(trigger="clean-ticket", internal_effect=True)
    run = sc.start()
    inner = sc.pep.enter_node

    def check(r, node, inputs):
        if node.id == "n1":
            assert run.exposed is True and any(t.startswith("add_note") for t in run.tainted_reads)
        inner(r, node, inputs)
    sc.pep.enter_node = check
    sc.execute(run)
    assert events(sc, run, "taint.applied")[0]["source"] == "add_note"


@spec("5.3", "A.3", finding="F1")
def test_sanitized_provenance_only_for_values_that_fit_the_output_schema():
    """Review-2 item 8: an undeclared or ill-typed output field earns no provenance."""
    from agentic_control.common import digest
    sc = build_scenario(trigger="clean-ticket")
    s = sc.platform.registry.sanitizers["proposal_extractor"]
    real = s.fn
    s.fn = lambda inp: ({**real(inp)[0], "free_text": "ship to 99 Evil Rd"}, real(inp)[1])    # a leaky sanitizer
    run = sc.start()
    sc.execute(run)
    acc = sc.pep.sanitized[run.run_id]
    assert digest("PART-100") in acc and digest("ship to 99 Evil Rd") not in acc


@spec("5.3", "A.7", finding="F1")
def test_every_free_string_in_a_delivery_passes_the_rendering_sanitizer():
    """Review-2 item 8: not only `content`."""
    from agentic_control.registry import ToolManifest
    sc = build_scenario()
    reg = sc.platform.registry
    m = reg.tools["log_case"]
    reg.tools["log_case"] = ToolManifest("log_case", "1", "case_log", {"sink": "string", "content": "string", "subject_line": "string"},
                                         writes_fields=[("case_log", "content")], resource_none_justification="delivery")
    reg.tools["log_case"].side_effect_class = m.side_effect_class
    orig = sc.model.propose
    sc.model.propose = lambda r, n, c: {**orig(r, n, c), "subject_line": "see https://evil.example/x?token=abc"} if n.id == "n6" else orig(r, n, c)
    run = sc.start()
    sc.execute(run)
    rec = list(sc.systems["case_log"].records.values())[0]
    assert "https://" not in rec.get("subject_line", "") and "https://" not in rec["content"]


@spec("4.7", "4.2", finding="F9")
def test_a_childs_data_classes_return_to_the_parent():
    sc = build_scenario(with_child=True, trigger="clean-ticket")
    sc.platform.registry.tools["read_ticket"].reads_data_class = "restricted"
    run = sc.start()
    sc.execute(run)
    assert "restricted" in run.data_classes_touched


@spec("8", "4.3", finding="F9")
def test_the_denied_shipment_routes_to_a_person_and_the_record_tag_follows_the_write():
    """Review-2 item 6."""
    sc = build_scenario(behaviour="inject_address")
    run = sc.start(ticket_address="99 Evil Rd")
    sc.execute(run)
    sent = sc.systems["mail_relay"].sent
    assert len(sent) == 1 and sent[0]["template_id"] == "tpl-routed-to-advisor"
    sc2 = build_scenario()                                       # exposed run: the write is tagged exposed
    run2 = sc2.start()
    sc2.execute(run2)
    tags = sc2.systems["fulfilment"].records["dev-1"]["_tags"]
    assert tags["replacement_issued"] == "exposed" and tags["ship_address"] == "verified"


@spec("A.2", "A.6", finding="F7")
def test_erasing_a_payload_removes_personal_data_and_leaves_the_chain_standing():
    """Review-2 item 3: parameters are never inline; references are keyed hashes."""
    sc = build_scenario(trigger="clean-ticket")
    run = sc.start()
    sc.execute(run)
    evs = sc.platform.evs
    dec = last_decision(sc, run, "n4")
    assert "parameters" not in dec and "reservation_keys" not in dec
    refs = [dec["parameters_ref"], dec["reservation_keys_ref"]]
    assert evs.payloads.get(refs[1])["destination"] == "12 Main St"
    evs.erase(run.run_id, refs, "data-protection")
    for r in refs:
        with pytest.raises(KeyError):
            evs.payloads.get(r)
    assert evs.verify() and evs.events[-1]["type"] == "erasure.applied"
    # the reference is an HMAC, not a plain hash of a guessable payload
    from agentic_control.common import digest
    assert dec["parameters_ref"] != "p:" + digest({"device_id": "dev-1", "part_sku": "PART-100", "amount": 120.0, "destination": "12 Main St"})
    # the event stands: a compensation whose mapping references only the recorded result still verifies and runs
    res = sc.platform.run.instruct_compensation(run, "n4")
    assert res["status"] == "executed"


@spec("A.1", "4.2", "4.3", finding="F8")
def test_linter_clauses_added_after_the_second_review():
    """Review-2 item 7."""
    from agentic_control.release import Bound, Node, Release
    sc = build_scenario(trigger="clean-ticket")
    reg, pol = sc.platform.registry, sc.platform.policy
    rel = sc.release

    def errs():
        return reg.lint_release(rel, pol, {"pep-1.0"})
    assert errs() == []
    n2 = rel.node("n2"); n2.token_cap = None
    assert any("step cap and a token cap" in e for e in errs()); n2.token_cap = 200
    n4 = rel.node("n4"); n4.tools = ["send_reply"]
    assert any("exactly one tool" in e for e in errs()); n4.tools = []
    c1 = rel.node("c1"); c1.tool = "delete_note"
    assert any("reversing tool" in e for e in errs()); c1.tool = "cancel_shipment"
    c1.reverses = "n1"
    assert any("must name an effect node" in e for e in errs()); c1.reverses = "n4"
    n4.bounds.append(Bound("anchor_rel", param="device_id", rel=None, anchor="subject"))
    assert any("names no relation" in e for e in errs()); n4.bounds.pop()
    n4.bounds.append(Bound("eq_rel_anchor", param="destination", rel="address_on_file", anchor="nobody"))
    assert any("unknown anchor" in e for e in errs()); n4.bounds.pop()
    assert errs() == []
    # the p == acting_user output form anchors a recipient
    from agentic_control.release import anchored_params
    assert anchored_params([Bound("eq_anchor", param="recipient", anchor="acting_user")], set()) == {"recipient"}
    assert anchored_params([Bound("anchor_rel", param="x", rel=None, anchor="subject")], set()) == set()
    # a handoff names agent:<target>
    h = Node("h9", "handoff", tool="agent:other", target_agent="triage-agent")
    bad = Release(AGENT, "9", "S2", "sidecar", "pep-1.0", [h], tools={}, scopes={})
    assert any("agent:<target_agent>" in e for e in reg.lint_release(bad, pol, {"pep-1.0"}))


@spec("A.1", finding="F8")
def test_stores_are_never_the_target_of_a_side_effect_tool_and_a_new_source_can_be_refused():
    from agentic_control.registry import SystemCapability, ToolManifest
    sc = build_scenario(trigger="clean-ticket")
    reg = sc.platform.registry
    with pytest.raises(Refused, match="never the target"):
        reg.register_tool(ToolManifest("purge_log", "1", "case_log", {"sink": "string"}, side_effect_class="reversible_internal",
                                       parameter_roles={"sink": "resource"}))
    # a brand-new registration that would remove anchor capability from a published release is refused, not applied
    with pytest.raises(Refused, match="remove anchor capability"):
        reg.register_system(SystemCapability("fulfilment", "system_of_record", provenance_tag=True, presentation="per_agent",
                                             preview_tool="preview_shipment", idempotency=True, verified_fields=set(),
                                             pip_relations=reg.systems["fulfilment"].pip_relations))
    assert reg.systems["fulfilment"].verified_fields == {"ship_address"} and not sc.release.suspended


@spec("D", "A.2", finding="F6")
def test_evidence_details_from_the_second_review():
    """Review-2 item 9: inputs_ref carries the run's recorded inputs and taint; normal effect decisions carry
    a reservation; the journal is cleared only after its entries are chained; memory writes carry no factor."""
    from agentic_control import events as schema
    from agentic_control.registry import ToolManifest
    sc = build_scenario()
    run = sc.start()
    sc.execute(run)
    evs = sc.platform.evs
    entered = events(sc, run, "node.entered", "n4")[0]
    inputs = evs.payloads.get(entered["inputs_ref"])
    assert inputs["exposed"] is True and "n3" in inputs["outputs"] and inputs["tainted_reads"]
    hdr = {"trace_id": "t", "run_id": "r", "agent_id": "a", "release_version": "1", "surface": "S2"}
    bad = {"type": "decision", **hdr, "node_id": "n", "purpose": "normal", "tool": "t", "version": "1", "schema_hash": "h",
           "parameters_ref": "p", "parameter_roles": {}, "action_hash": "a", "factors": [], "decision": "ALLOW", "rule_id": "allow",
           "obligations": [], "stop_list_seq": 1, "tier": "A2"}
    with pytest.raises(schema.SchemaError, match="reservation"):
        schema.validate(bad)
    schema.validate({**bad, "reservation": "local"})
    reg = sc.platform.registry
    m = ToolManifest("remember", "1", "agent_memory", {"key": "string", "value": "string"}, writes_fields=[("agent_memory", "value")],
                     parameter_roles={"key": "resource"})
    m.side_effect_class = "internal_store"
    assert reg.derive_factors(m, {"key": "k", "value": "v"}) == set()
    # the journal keeps its entries until the chain has them
    from agentic_control.common import Unavailable
    sc2 = build_scenario(trigger="clean-ticket", internal_effect=True)
    run2 = sc2.start()
    sc2.platform.outage("EVS")
    sc2.execute(run2)
    n = len(sc2.pep.journal.entries)
    assert n > 0
    with pytest.raises(Unavailable):
        sc2.platform.evs.reconcile(sc2.pep.journal, sc2.platform.trust)       # still down: nothing drained
    assert len(sc2.pep.journal.entries) == n
    sc2.platform.outage("EVS", down=False)
    assert sc2.platform.evs.reconcile(sc2.pep.journal, sc2.platform.trust) == n and not sc2.pep.journal.entries
