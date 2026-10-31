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
