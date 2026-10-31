"""IDS, the Identity Service (spec A.2).

Holds agent identities, workload bindings and the PEP build allow-list, delegation state for acting
users, resumption grants, the record of approved-action credentials it issued, and recovery
identities. Issues every credential a PEP presents downstream: sender-constrained to the PEP's
workload, audience-bound, with a purpose."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .common import Availability, Clock, Refused, new_id
from .crypto import Sealer, Signer, TrustStore
from .registry import PolicyValues, Registry


@dataclass
class WorkloadBinding:
    workload_id: str
    agent_id: str
    surface: str
    build_hash: str
    form: str                  # proxy | sidecar | sdk
    signer: Signer             # the workload key IDS issued to the attested build


@dataclass
class GrantRecord:
    grant_id: str
    action_hash: str
    run_id: str
    node_id: str
    agent_id: str
    status: str = "valid"      # valid | redeemed | invalidated


class IdentityService(Availability):
    name = "IDS"

    def __init__(self, registry: Registry, clock: Clock, policy: PolicyValues, trust: TrustStore) -> None:
        self.registry = registry
        self.clock = clock
        self.policy = policy
        self.trust = trust
        self.signer = Signer("IDS")
        trust.trust(self.signer, "ids")
        self.sealer = Sealer()
        self.identities: dict[str, dict[str, Any]] = {}
        self.workloads: dict[str, WorkloadBinding] = {}
        self.allowlist: dict[str, str] = {}             # build hash -> form
        self.sessions: dict[str, str] = {}              # session token -> user id
        self.delegations: dict[str, str] = {}           # user -> valid | revoked
        self.grants: dict[str, GrantRecord] = {}
        self.approved_action_issuances: list[dict[str, Any]] = []
        self.recovery_vault: dict[str, set[str]] = {}   # identity -> named releasers
        self.recovery_uses: list[dict[str, Any]] = []
        self.revoked_agents: set[str] = set()
        self.revoked_runs: set[str] = set()
        self.issued: list[dict[str, Any]] = []
        self.identity_provider = Signer("identity-provider")
        trust.trust(self.identity_provider, "identity_provider")

    # ------------------------------------------------------------------ identities and workloads
    def issue_agent_identity(self, agent_id: str) -> dict[str, Any]:
        self._check()
        agent = self.registry.agents.get(agent_id)
        if agent is None or (agent.expiry is not None and agent.expiry < self.clock.now()):
            raise Refused("IDS issues an agent identity only against a current REG entry (I5)")
        ident = {"agent_id": agent_id, "issued_at": self.clock.now(), "root_trust": new_id("key")}
        self.identities[agent_id] = ident
        return ident

    def allow_build(self, build_hash: str, form: str) -> None:
        self.allowlist[build_hash] = form

    def bind_workload(self, workload_id: str, agent_id: str, surface: str, build_hash: str) -> WorkloadBinding:
        """A workload proves itself by attestation; IDS issues a workload key only to an allow-listed build."""
        self._check()
        if build_hash not in self.allowlist:
            raise Refused("PEP build hash is not on the allow-list; an altered build gets no credentials")
        if agent_id not in self.identities:
            raise Refused("no identity for agent")
        signer = Signer(f"workload:{workload_id}")
        self.trust.trust(signer, "workload")
        b = WorkloadBinding(workload_id, agent_id, surface, build_hash, self.allowlist[build_hash], signer)
        self.workloads[workload_id] = b
        return b

    def _binding(self, workload_id: str) -> WorkloadBinding:
        b = self.workloads.get(workload_id)
        if b is None:
            raise Refused("unbound workload")
        return b

    def _identity_current(self, agent_id: str) -> None:
        agent = self.registry.agents.get(agent_id)
        if agent_id in self.revoked_agents or agent is None or (agent.expiry is not None and agent.expiry < self.clock.now()):
            raise Refused("agent identity suspended: lapsed or absent REG entry (I5)")

    # ------------------------------------------------------------------ sessions and delegation
    def create_session(self, user: str) -> str:
        tok = new_id("sess")
        self.sessions[tok] = user
        self.delegations[user] = "valid"
        return tok

    def exchange(self, session_token: str) -> dict[str, Any]:
        """Exchanges a user's session token for the acting user it names (the delegated chain head)."""
        self._check()
        user = self.sessions.get(session_token)
        if user is None:
            raise Refused("unknown session")
        return {"acting_user": user}

    def delegation_status(self, user: str | None) -> str:
        self._check()
        if user is None:
            return "none"
        return self.delegations.get(user, "revoked")

    def revoke_delegation(self, user: str) -> None:
        self.delegations[user] = "revoked"

    # ------------------------------------------------------------------ credentials
    def issue_credential(self, workload: str, run: str, release: dict[str, Any], node: str, call: dict[str, Any],
                         principal_chain: dict[str, Any], audience: str, purpose: str) -> dict[str, Any]:
        """purpose ∈ {normal, compensation, replay, model}. Refuses when the release's declared form or
        surface differs from the attested workload's (caps cannot be evaded by declaration)."""
        self._check()
        b = self._binding(workload)
        self._identity_current(b.agent_id)
        if run in self.revoked_runs:
            raise Refused("run revoked")
        if release.get("pep_form") != b.form:
            raise Refused(f"release declares form {release.get('pep_form')} but the attested build is {b.form}")
        if release.get("surface") != b.surface:
            raise Refused(f"release declares surface {release.get('surface')} but the workload is bound to {b.surface}")
        if release.get("agent_id") != b.agent_id:
            raise Refused("release belongs to another agent")
        acting = principal_chain.get("acting_user")
        if purpose == "normal" and acting is not None and self.delegations.get(acting) != "valid":
            raise Refused("revoked")
        now = self.clock.now()
        cred = {
            "credential_id": new_id("cred"), "workload": workload, "agent_id": b.agent_id, "audience": audience,
            "purpose": purpose, "run": run, "node": node, "action_hash": call.get("action_hash"),
            "principal_chain": principal_chain if purpose == "normal" else None,
            "record_claim": principal_chain if purpose in {"compensation", "replay"} else None,
            "delegated": purpose == "normal" and acting is not None,
            "issued_at": now, "expires_at": now + min(self.policy.credential_lifetime, 3600.0),
            "per_call": purpose in {"compensation", "replay"} or b.surface == "S4",
        }
        signed = self.signer.sign(cred)
        self.issued.append(signed)
        return signed

    def verify_credential(self, signed: dict[str, Any], presenter_workload: str, audience: str) -> bool:
        """What a system of record checks: signature, presenter equals the bound workload, audience, expiry."""
        if not self.trust.verify(signed, role="ids"):
            return False
        c = signed["payload"]
        return c["workload"] == presenter_workload and c["audience"] == audience and c["expires_at"] >= self.clock.now()

    # ------------------------------------------------------------------ approval records and grants
    def approver_assertion(self, approver: str) -> dict[str, Any]:
        """The identity provider's assertion of the approver, forwarded by OPS."""
        return self.identity_provider.sign({"approver": approver, "at": self.clock.now()})

    def mint_resumption_grant(self, run_id: str, node_id: str, action_hash: str, agent_id: str) -> tuple[str, str]:
        """Single-use, bound to the action hash, audience IDS, sealed, stored by RUN. No clock inside."""
        self._check()
        if not self.policy.grants_permitted:
            raise Refused("policy does not permit grants")
        gid = new_id("grant")
        self.grants[gid] = GrantRecord(gid, action_hash, run_id, node_id, agent_id)
        token = self.sealer.seal({"grant_id": gid, "action_hash": action_hash, "aud": "IDS"})
        return gid, token

    def invalidate_grant(self, grant_id: str) -> None:
        g = self.grants.get(grant_id)
        if g and g.status == "valid":
            g.status = "invalidated"

    def _check_timers(self, assertion: dict[str, Any]) -> str | None:
        """Expiry without a clock: IDS computes it from RUN-signed timer state and its own clock."""
        now = self.clock.now()
        suspended = sum(min(e, now) - s for s, e in assertion.get("suspensions", []))
        suspended = min(suspended, self.policy.max_park)
        if assertion.get("approval_time") is None:
            if now - assertion["hold_time"] - suspended > self.policy.approval_timeout:
                return "timeout"
            return None
        if now - assertion["approval_time"] - suspended > self.policy.resume_window:
            return "expired"
        return None

    def redeem_resumption_grant(self, workload: str, grant_token: str, approval_record: dict[str, Any],
                                run_status_assertion: dict[str, Any]) -> dict[str, Any]:
        """Verifies grant, signature, presenter binding, delegation status and timer state, then issues a
        credential to that workload. Returns {status: ok|revoked|expired|invalid, credential?}."""
        self._check()
        opened = self.sealer.open(grant_token)
        if not opened:
            return {"status": "invalid", "reason": "grant does not open"}
        g = self.grants.get(opened["grant_id"])
        if g is None or g.status != "valid":
            return {"status": "invalid", "reason": "grant not valid"}
        b = self._binding(workload)
        if b.agent_id != g.agent_id:
            return {"status": "invalid", "reason": "presenter not bound to the agent's workload"}
        if not self.trust.verify(approval_record, role="run") or not self.trust.verify(run_status_assertion, role="run"):
            return {"status": "invalid", "reason": "RUN signature"}
        ap, st = approval_record["payload"], run_status_assertion["payload"]
        if ap["action_hash"] != g.action_hash or st["action_hash"] != g.action_hash:
            return {"status": "invalid", "reason": "action hash mismatch"}
        if not self.trust.verify(ap["approver_assertion"], role="identity_provider"):
            return {"status": "invalid", "reason": "approver assertion"}
        if st["record_status"] != "valid":
            return {"status": "invalid", "reason": "approved-action record not valid"}
        exp = self._check_timers(st)
        if exp:
            g.status = "invalidated"
            return {"status": "expired", "reason": exp}
        acting = ap.get("acting_user")
        if acting is not None and self.delegations.get(acting) != "valid":
            return {"status": "revoked"}
        g.status = "redeemed"
        cred = self.issue_credential(workload, g.run_id, ap["release"], g.node_id, {"action_hash": g.action_hash},
                                     {"acting_user": acting, "agents": ap["agents"]}, ap["audience"], "normal")
        return {"status": "ok", "credential": cred, "grant_id": g.grant_id}

    def credential_for_approved_action(self, workload: str, approval_record: dict[str, Any],
                                       run_status_assertion: dict[str, Any]) -> dict[str, Any]:
        """The substitution path: a credential with the approver as acting user and the original user
        recorded as the requested principal. No grant is involved."""
        self._check()
        if not self.trust.verify(approval_record, role="run") or not self.trust.verify(run_status_assertion, role="run"):
            return {"status": "invalid", "reason": "RUN signature"}
        ap, st = approval_record["payload"], run_status_assertion["payload"]
        if ap["kind"] != "substitution":
            return {"status": "invalid", "reason": "not a substitution record"}
        if not self.trust.verify(ap["approver_assertion"], role="identity_provider"):
            return {"status": "invalid", "reason": "approver assertion"}
        if st["record_status"] != "valid" or st["action_hash"] != ap["action_hash"]:
            return {"status": "invalid", "reason": "approved-action record not valid"}
        exp = self._check_timers(st)
        if exp:
            return {"status": "expired", "reason": exp}
        approver = ap["approver_assertion"]["payload"]["approver"]
        self.delegations.setdefault(approver, "valid")
        b = self._binding(workload)
        cred = self.issue_credential(workload, st["run_id"], ap["release"], st["node_id"], {"action_hash": ap["action_hash"]},
                                     {"acting_user": approver, "agents": ap["agents"], "requested_principal": ap.get("acting_user")},
                                     ap["audience"], "normal")
        self.approved_action_issuances.append({"approval_ref": ap["approval_ref"], "action_hash": ap["action_hash"],
                                               "presenter_workload": workload, "agent": b.agent_id})
        return {"status": "ok", "credential": cred}

    # ------------------------------------------------------------------ recovery and revocation
    def vault_recovery_identity(self, identity: str, releasers: set[str]) -> None:
        self.recovery_vault[identity] = set(releasers)

    def release_recovery_identity(self, identity: str, two_approvers: tuple[str, str], incident: str) -> dict[str, Any]:
        """Released by two named people; every use is an incident (6.3)."""
        a, b = two_approvers
        named = self.recovery_vault.get(identity, set())
        if a == b or a not in named or b not in named:
            raise Refused("a recovery identity is released by two distinct named people")
        rec = {"identity": identity, "releasers": sorted({a, b}), "incident_id": incident, "at": self.clock.now()}
        self.recovery_uses.append(rec)
        return self.signer.sign({"recovery_identity": identity, "incident": incident, "purpose": "recovery"})

    def revoke(self, agent: str | None = None, run: str | None = None) -> None:
        if agent:
            self.revoked_agents.add(agent)
        if run:
            self.revoked_runs.add(run)
