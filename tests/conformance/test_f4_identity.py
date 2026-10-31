"""F4. Identity: only an attested PEP presents credentials; a credential binds workload, audience, purpose,
run, node and action hash; delegation is checked at approval and again at redemption; substitution
runs the approver as the acting user and is refused where a bound anchors to the acting user."""
import pytest

from agentic_control.common import Refused
from agentic_control.dbs import SystemRefused
from conftest import events, last_decision, spec
from warranty import AGENT, build_scenario, policy_values


@spec("A.6", "A.7", "1", finding="F4")
def test_a_system_accepts_only_a_credential_presented_by_the_bound_workload(scenario):
    run = scenario.start()
    scenario.execute(run)
    cred = scenario.platform.ids.issued[-1]
    f = scenario.systems["fulfilment"]
    with pytest.raises(SystemRefused):
        f.execute("ship_replacement", {"device_id": "dev-1"}, cred, "some-other-process")        # wrong presenter
    with pytest.raises(SystemRefused):
        f.execute("ship_replacement", {"device_id": "dev-1"}, None, "wl-1")                      # no credential
    forged = dict(cred); forged["payload"] = {**cred["payload"], "audience": "fulfilment", "workload": "wl-1", "expires_at": 9e12}
    with pytest.raises(SystemRefused):
        f.execute("ship_replacement", {"device_id": "dev-1"}, forged, "wl-1")                    # signature breaks


@spec("A.6", finding="F4")
def test_an_unlisted_build_gets_no_workload_key(scenario):
    with pytest.raises(Refused):
        scenario.platform.ids.bind_workload("wl-x", AGENT, "S2", "tampered-build")


@spec("A.6", "A.1", finding="F4")
def test_release_form_or_surface_mismatch_with_the_attested_workload_is_refused(scenario):
    ids = scenario.platform.ids
    rel = {"agent_id": AGENT, "version": "1.0", "surface": "S2", "pep_form": "sdk"}
    with pytest.raises(Refused, match="form"):
        ids.issue_credential("wl-1", "r", rel, "n4", {}, {"acting_user": None, "agents": [AGENT]}, "fulfilment", "normal")
    rel = {"agent_id": AGENT, "version": "1.0", "surface": "S4", "pep_form": "sidecar"}
    with pytest.raises(Refused, match="surface"):
        ids.issue_credential("wl-1", "r", rel, "n4", {}, {"acting_user": None, "agents": [AGENT]}, "fulfilment", "normal")


@spec("A.6", "I5", finding="F4")
def test_identity_is_issued_only_against_a_current_registry_entry(scenario):
    ids = scenario.platform.ids
    with pytest.raises(Refused):
        ids.issue_agent_identity("ghost-agent")
    ids.revoke(agent=AGENT)
    run = scenario.start()
    scenario.execute(run)
    # no credential is issued to a suspended identity: no model call, no effect; the run ends on its branches
    assert not scenario.systems["fulfilment"].shipments and not scenario.systems["mail_relay"].sent
    assert {e["error"] for e in events(scenario, run, "effect.failed")} == {"revoked"}
    assert run.state == "COMPLETED" and not events(scenario, run, "usage.recorded")


@spec("A.6", "4.4", finding="F4")
def test_credential_expiry_is_enforced_by_the_system(scenario):
    run = scenario.start()
    scenario.execute(run)
    cred = next(c for c in scenario.platform.ids.issued if c["payload"]["audience"] == "fulfilment")
    assert scenario.platform.ids.verify_credential(cred, "wl-1", "fulfilment")
    scenario.platform.clock.advance(4000)
    assert not scenario.platform.ids.verify_credential(cred, "wl-1", "fulfilment")


@spec("4.2", "A.3", "A.6", finding="F4")
def test_console_run_evaluates_the_acting_user_through_the_pip():
    sc = build_scenario(trigger="console")
    run = sc.start(user="advisor-1")
    assert run.acting_user == "advisor-1"
    sc.execute(run)
    assert run.state == "COMPLETED"
    created = events(sc, run, "run.created")[0]
    assert created["principal_chain"]["acting_user"] == "advisor-1"
    sc2 = build_scenario(trigger="console")
    sc2.pip.entitled = lambda user, system, resource: False
    run2 = sc2.start(user="advisor-1")
    sc2.execute(run2)
    assert last_decision(sc2, run2, "n1")["rule_id"] == "intersection"
    assert not sc2.systems["fulfilment"].shipments


@spec("4.4", "A.6", finding="F4")
def test_delegation_revoked_before_approval_substitutes_the_approver():
    sc = build_scenario(trigger="console")
    sc.model.amount = 500.0
    run = sc.start(user="advisor-1")
    sc.execute(run)
    assert run.state == "HELD"
    # the console graph anchors bounds to the acting user: substitution is not permitted there
    sc.platform.ids.revoke_delegation("advisor-1")
    res = sc.platform.ops.approve(run, "n4", "approver-1")
    assert res["status"] == "revoked"
    assert events(sc, run, "hold.resolved", "n4")[-1]["outcome"] == "revoked"


@spec("4.4", "A.6", finding="F4")
def test_substitution_where_no_bound_anchors_to_the_acting_user():
    """A delegated run whose effect bounds anchor to the subject (not the acting user) may be completed
    under the approver's own authority: the credential names the approver as acting user and records the
    original user as the requested principal."""
    sc = build_scenario(trigger="console")
    sc.model.amount = 500.0
    # re-anchor the effect to the subject so substitution is admissible
    for n in sc.release.nodes:
        for b in n.bounds:
            if b.anchor == "acting_user":
                b.anchor = "subject"
    run = sc.start(user="advisor-1")
    run.subject = "advisor-1"
    sc.execute(run)
    assert run.state == "HELD"
    sc.platform.ids.revoke_delegation("advisor-1")
    res = sc.platform.ops.approve(run, "n4", "approver-1")
    assert res["status"] == "executed"
    resolved = events(sc, run, "hold.resolved", "n4")[-1]
    assert resolved["substitution"] is True
    cred = sc.platform.ids.issued[-1]["payload"]
    assert cred["principal_chain"]["acting_user"] == "approver-1" and cred["principal_chain"]["requested_principal"] == "advisor-1"
    assert events(sc, run, "approved_action.used")


@spec("4.4", "A.6", finding="F4")
def test_delegation_revoked_at_redemption_opens_a_substitution_hold(monkeypatch):
    sc = build_scenario(trigger="console")
    sc.model.amount = 500.0
    for n in sc.release.nodes:
        for b in n.bounds:
            if b.anchor == "acting_user":
                b.anchor = "subject"
    run = sc.start(user="advisor-1")
    run.subject = "advisor-1"
    sc.execute(run)
    ids = sc.platform.ids
    real = ids.delegation_status
    # RUN sees the delegation valid at approval; IDS finds it revoked when the grant is redeemed
    monkeypatch.setattr(ids, "delegation_status", lambda user: "valid")
    original_redeem = ids.redeem_resumption_grant

    def redeem(workload, token, record, assertion):
        ids.delegations["advisor-1"] = "revoked"
        return original_redeem(workload, token, record, assertion)
    monkeypatch.setattr(ids, "redeem_resumption_grant", redeem)
    res = sc.platform.ops.approve(run, "n4", "approver-1")
    assert res["status"] == "held_again"
    failed = events(sc, run, "effect.failed", "n4")
    assert failed and failed[-1]["error"] == "revoked"
    hold = events(sc, run, "hold.created", "n4")[-1]
    assert hold["hold_causes"] == ["substitution_required"] and hold["substitution_only"] is True
    assert "n4" not in run.in_doubt_cache and not sc.systems["fulfilment"].shipments
    monkeypatch.setattr(ids, "delegation_status", real)
    res = sc.platform.ops.approve(run, "n4", "approver-1")
    assert res["status"] == "executed" and events(sc, run, "hold.resolved", "n4")[-1]["substitution"] is True


@spec("4.4", "A.6", finding="F4")
def test_revoked_at_redemption_with_substitution_forbidden_is_a_denial(monkeypatch):
    sc = build_scenario(trigger="console", policy=policy_values(substitution_permitted=False))
    sc.model.amount = 500.0
    run = sc.start(user="advisor-1")
    sc.execute(run)
    ids = sc.platform.ids
    monkeypatch.setattr(ids, "delegation_status", lambda user: "valid")
    orig = ids.redeem_resumption_grant

    def redeem(*a):
        ids.delegations["advisor-1"] = "revoked"
        return orig(*a)
    monkeypatch.setattr(ids, "redeem_resumption_grant", redeem)
    res = sc.platform.ops.approve(run, "n4", "approver-1")
    assert res["status"] == "denied"
    assert events(sc, run, "effect.failed", "n4")[-1]["error"] == "revoked"
    assert run.next_node == "n5"


@spec("A.6", "4.4", finding="F4")
def test_a_grant_is_single_use_and_bound_to_its_action_hash():
    sc = build_scenario(trigger="clean-ticket")
    sc.model.amount = 500.0
    run = sc.start()
    sc.execute(run)
    h = run.holds["n4"]
    ids = sc.platform.ids
    assertion = sc.platform.run.status_assertion(run, h)
    forged = sc.platform.run.signer.sign({**{"action_hash": "other", "kind": "grant", "approver_assertion": ids.approver_assertion("approver-1"),
                                             "approvals": [], "acting_user": None, "agents": [AGENT], "approval_ref": "x",
                                             "release": {"agent_id": AGENT, "version": "1.0", "surface": "S2", "pep_form": "sidecar"},
                                             "audience": "fulfilment", "causes_discharged": ["limit_band"], "approved_at": 0}})
    assert ids.redeem_resumption_grant("wl-1", h.grant_token, forged, assertion)["status"] == "invalid"
    sc.platform.ops.approve(run, "n4", "approver-1")
    # the real record, after the grant was redeemed once
    assert ids.redeem_resumption_grant("wl-1", h.grant_token, h.approval_record, assertion)["status"] == "invalid"


@spec("6.3", "A.6", finding="F4")
def test_recovery_identity_needs_two_named_people_and_opens_an_incident(scenario):
    ids, ops = scenario.platform.ids, scenario.platform.ops
    ids.vault_recovery_identity("break-glass", {"alice", "bob", "carol"})
    with pytest.raises(Refused):
        ids.release_recovery_identity("break-glass", ("alice", "alice"), "INC-1")
    with pytest.raises(Refused):
        ids.release_recovery_identity("break-glass", ("alice", "mallory"), "INC-1")
    cred = ops.recovery("break-glass", ("alice", "bob"), "INC-1", ["cancel shipment ship-1"])
    assert cred["payload"]["purpose"] == "recovery"
    assert ops.incidents[-1]["incident"] == "INC-1"
    rec = [e for e in scenario.platform.evs.events if e["type"] == "recovery.used"][-1]
    assert rec["releasers"] == ["alice", "bob"] and rec["incident_id"] == "INC-1"
