"""RUN, the Run Coordinator (spec A.5, 4.8, 4.9, Appendix B).

Owns the lifecycle of every governed run: run records, node checkpoints, holds and sealed grants, the
park queue, counters, token usage, the stop register, heartbeats, and the signing key for approval
records and status assertions. Always central: a runtime integrates through the hook contract."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .common import Availability, Clock, Denied, Refused, Unavailable, new_id
from .crypto import Signer, TrustStore
from .evidence import EvidenceStore
from .identity import IdentityService
from .registry import PolicyValues, Registry
from .release import Node, Release

if TYPE_CHECKING:
    from .enforcement import EnforcementPoint

TERMINAL = {"COMPLETED", "COMPENSATED", "CANCELLED", "FAILED", "CLOSED_WITH_EXCEPTION"}


COUNTER_WINDOW = 3600.0


@dataclass
class Hold:
    hold_id: str
    node_id: str
    action_hash: str
    kind: str                                  # effect | input
    causes: list[str]
    approver_set: list[str]
    approvers_required: int
    hold_time: float
    substitution_only: bool
    grant_id: str | None = None
    grant_token: str | None = None
    discharged: set[str] = field(default_factory=set)
    approval_time: float | None = None
    approvals: list[dict[str, Any]] = field(default_factory=list)
    approval_record: dict[str, Any] | None = None
    record_kind: str | None = None             # grant | substitution
    status: str = "open"                       # open | approved | resolved
    approved_action_valid: bool = False
    suspensions: list[list[float]] = field(default_factory=list)
    preview_ref: str | None = None
    view_ref: str | None = None
    pending: dict[str, Any] = field(default_factory=dict)   # the pending effect: tool, parameters, provenance
    timers_suspended_since: float | None = None


@dataclass
class EffectRecord:
    node_id: str
    action_hash: str
    decision_event: str
    parameters: dict[str, Any]
    result_fields: dict[str, Any]
    result_ref: str | None
    event_hashes: list[str]
    tool: str
    executed: bool = True


@dataclass
class Run:
    run_id: str
    trace_id: str
    agent_id: str
    release: Release
    surface: str
    parent_run_id: str | None = None
    state: str = "CREATED"
    subject: str | None = None
    acting_user: str | None = None
    agents: list[str] = field(default_factory=list)
    service_identity: str | None = None
    exposed: bool = False
    tainted_reads: list[str] = field(default_factory=list)
    data_classes_touched: set[str] = field(default_factory=set)
    step_counts: dict[str, int] = field(default_factory=dict)
    tokens: dict[str, int] = field(default_factory=dict)
    spend_to_date: int = 0
    next_node: str | None = None
    outputs: dict[str, Any] = field(default_factory=dict)
    entered: list[str] = field(default_factory=list)       # node_entered hooks RUN recorded
    exited: set[str] = field(default_factory=set)
    effects: list[EffectRecord] = field(default_factory=list)   # executed effects, in order
    holds: dict[str, Hold] = field(default_factory=dict)        # node_id -> hold
    rehold_counts: dict[str, int] = field(default_factory=dict)  # action_hash -> count
    effect_node_entered: bool = False
    last_heartbeat: float = 0.0
    started_at: float = 0.0
    park: dict[str, Any] | None = None
    escalation: dict[str, Any] | None = None
    stop_ref: str | None = None
    children: dict[str, str] = field(default_factory=dict)   # node_id -> child run id
    cancelled_effects: set[str] = field(default_factory=set)  # nodes cancelled by a stop: re-enter on resume
    not_executed: set[str] = field(default_factory=set)       # resolver-recorded not_executed: re-enter
    replay_attempts: dict[str, int] = field(default_factory=dict)
    disposition: str | None = None
    held_before_park: bool = False
    in_doubt_cache: set[str] = field(default_factory=set)
    deferred_branch: tuple[str, str] | None = None     # a denial recorded while PARKED, applied on recovery
    unreconciled_journal: bool = False
    workload: str | None = None

    @property
    def principal_chain(self) -> dict[str, Any]:
        return {"acting_user": self.acting_user, "agents": list(self.agents)}

    def header(self) -> dict[str, Any]:
        return {"trace_id": self.trace_id, "run_id": self.run_id, "agent_id": self.agent_id,
                "release_version": self.release.version, "surface": self.surface,
                **({"parent_run_id": self.parent_run_id} if self.parent_run_id else {})}

    def run_state(self) -> dict[str, Any]:
        return {"exposed": self.exposed, "tainted_reads": list(self.tainted_reads),
                "data_classes_touched": sorted(self.data_classes_touched),
                "step_count": dict(self.step_counts), "spend_to_date": self.spend_to_date,
                "state": self.state, "next_node": self.next_node}


class RunCoordinator(Availability):
    name = "RUN"

    def __init__(self, registry: Registry, ids: IdentityService, evs: EvidenceStore, clock: Clock,
                 policy: PolicyValues, trust: TrustStore) -> None:
        self.registry = registry
        self.ids = ids
        self.evs = evs
        self.clock = clock
        self.policy = policy
        self.trust = trust
        self.signer = Signer("RUN")
        trust.trust(self.signer, "run")
        self.runs: dict[str, Run] = {}
        self.peps: dict[str, "EnforcementPoint"] = {}   # workload -> PEP
        self.counters: dict[str, list[dict[str, Any]]] = {}   # key -> reservations
        self.reservations: dict[str, dict[str, Any]] = {}
        self.stop_register: list[dict[str, Any]] = []
        self.park_queue: list[str] = []
        self.resolver = "oncall-resolver"
        self.park_deadline = 3600.0
        self.owner_deadline = 7200.0
        self.outage_window: list[float] | None = None
        self.grace_until: float = 0.0
        self.notifications: list[str] = []

    # ------------------------------------------------------------------ helpers
    def _ev(self, run: Run, event: dict[str, Any]) -> str:
        """RUN writes its own events to EVS; during an EVS outage they go to the PEP journal if one exists."""
        ev = {**run.header(), **event}
        try:
            return self.evs.append(ev)
        except Unavailable:
            pep = self.peps.get(run.workload or "")
            if pep is None:
                raise
            return pep.journal.append(ev)["event_id"]

    def _transition(self, run: Run, state: str, event: str, **fields: Any) -> None:
        if state == "RUNNING" and run.state != "RUNNING":
            run.last_heartbeat = self.clock.now()   # the host-lost timer runs from the return to RUNNING
        run.state = state
        self._ev(run, {"type": event, **fields})

    def instruct(self, run: Run, node_id: str, purpose: str, **kw: Any) -> dict[str, Any]:
        """Every PEP instruction (preview, resume, compensation, replay) is RUN-originated and RUN-signed;
        the PEP refuses an instruction that does not verify (A.4, A.5)."""
        signed = self.signer.sign({"run": run.run_id, "node": node_id, "purpose": purpose, "nonce": new_id("ins")})
        return self._pep(run).instruct(run, node_id, purpose, instruction=signed, **kw)

    def instruct_compensation(self, run: Run, original_node: str) -> dict[str, Any]:
        """Compensation of one executed effect, as the cancel path performs it (4.9); exposed for resolvers
        and tests acting as RUN."""
        node = run.release.node(original_node)
        if node.compensate in (None, "irreversible"):
            return {"status": "denied", "reason": "effect declared irreversible"}
        return self.instruct(run, node.compensate, "compensation", original_node=original_node)

    def _person(self, assertion: dict[str, Any]) -> str:
        """A person acts through OPS with an identity-provider assertion; RUN verifies it (A.9, I8)."""
        if not isinstance(assertion, dict) or not self.trust.verify(assertion, role="identity_provider"):
            raise Refused("identity-provider assertion does not verify")
        return assertion["payload"]["approver"]

    def register_pep(self, workload: str, pep: "EnforcementPoint") -> None:
        self.peps[workload] = pep

    def _pep(self, run: Run) -> "EnforcementPoint":
        pep = self.peps.get(run.workload or "")
        if pep is None:
            raise Denied("no PEP bound to this run's workload")
        return pep

    # ------------------------------------------------------------------ run start (A.5)
    def start_run(self, release: Release, trigger_id: str, envelope: dict[str, Any], payload: dict[str, Any],
                  workload: str, session_token: str | None = None, parent: Run | None = None,
                  as_service: bool = False, inherited_state: dict[str, Any] | None = None) -> Run:
        self._check()
        trig = self.registry.triggers.get(trigger_id)
        verified = False
        if parent is None:
            if trig is None or trig.signing_key is None or not trig.signing_key.verify(envelope):
                raise Refused("trigger signature does not verify against REG")
            verified = True
            env = envelope["payload"]
            if env.get("trigger_id") != trigger_id or env.get("kind") != trig.kind:
                raise Refused("envelope does not match the registered trigger")
        if release.release_id not in self.registry.releases:
            raise Refused("unknown release")
        stop = self.stop_in_scope(release.agent_id, release.surface, release)
        if stop is not None:
            raise Refused(f"stop {stop['stop_id']} in scope: no run starts under a current stop (4.9)")
        b = self.ids.workloads.get(workload)
        if b is None or b.agent_id != release.agent_id:
            raise Refused("IDS has no binding for the hosting workload and agent")
        run = Run(run_id=new_id("run"), trace_id=parent.trace_id if parent else new_id("trace"),
                  agent_id=release.agent_id, release=release, surface=release.surface,
                  parent_run_id=parent.run_id if parent else None, workload=workload)
        run.started_at = run.last_heartbeat = self.clock.now()
        if parent is None:
            if trig.kind == "subject_claim":
                run.subject = envelope["payload"].get("subject")
            elif trig.kind == "user_session":
                if not session_token:
                    raise Refused("user_session trigger without a session token")
                run.acting_user = self.ids.exchange(session_token, run.run_id)["acting_user"]
            trust = self.registry.payload_trust(trig)
            run.exposed = trust == "untrusted" or (trust == "per_item" and any(v.get("tainted") for v in payload.values() if isinstance(v, dict)))
            run.agents = [release.agent_id]
        else:
            run.subject = parent.subject
            run.acting_user = parent.acting_user
            if parent.acting_user is not None:
                self.ids.exchange_child(parent.run_id, run.run_id)     # exchange(run_ref, target_agent): the parent's delegation state
            if as_service:
                run.agents = list(parent.agents)
                run.service_identity = release.agent_id
            else:
                run.agents = list(parent.agents) + [release.agent_id]
            st = inherited_state or parent.run_state()
            run.exposed = bool(st.get("exposed"))
            run.tainted_reads = list(st.get("tainted_reads", []))
            run.data_classes_touched = set(st.get("data_classes_touched", []))
        fwd = release.forward_nodes()
        run.next_node = fwd[0].id if fwd else None
        self.runs[run.run_id] = run
        self._ev(run, {"type": "run.created", "trigger": trigger_id, "trigger_kind": trig.kind if trig else "child",
                       "signature_verified": verified, "subject": run.subject, "principal_chain": run.principal_chain,
                       "exposed_at_start": run.exposed})
        if run.exposed and parent is None:
            self._ev(run, {"type": "taint.applied", "source": f"trigger:{trigger_id}", "items": ["payload"]})
        self._transition(run, "RUNNING", "run.started", cause="trigger" if parent is None else "spawn")
        return run

    # ------------------------------------------------------------------ hook contract
    def node_entered(self, run: Run, node_id: str, node_type: str, inputs_ref: str) -> bool:
        """RUN rejects a hook for any node other than the checkpointed next node or the declared denial
        or failure branch target; a node in doubt is never re-entered; a handoff or service node whose
        child exists is not re-spawned."""
        self._check()
        if run.state != "RUNNING":
            return False
        allowed = {run.next_node} | self._branch_targets(run)
        if node_id not in allowed:
            return False
        if node_id in run.in_doubt_cache:
            return False
        if node_id not in run.entered:
            run.entered.append(node_id)
        run.not_executed.discard(node_id)          # a re-entry after a resolver's not_executed happens once
        run.cancelled_effects.discard(node_id)
        if node_type == "effect":
            run.effect_node_entered = True
        run.last_heartbeat = self.clock.now()
        self._ev(run, {"type": "node.hook", "node_id": node_id, "node_type": node_type, "inputs_ref": inputs_ref})
        if run.release.pep_form == "proxy":
            # S1: RUN writes node.entered from the platform's hook, which carries the inputs reference (A.4)
            self._ev(run, {"type": "node.entered", "node_id": node_id, "node_type": node_type, "inputs_ref": inputs_ref,
                           "provenance_claimed": False, "written_by": "run"})
        if node_type == "human":
            self.input_hold(run, run.release.node(node_id))   # node entry has one source; RUN opens the input hold
        return True

    def _branch_targets(self, run: Run) -> set[str]:
        out: set[str] = set()
        for nid in run.entered[-1:]:
            try:
                n = run.release.node(nid)
            except KeyError:
                continue
            if n.denial_branch:
                out.add(n.denial_branch)
            if n.failure_branch:
                out.add(n.failure_branch)
        return out

    def checkpoint(self, run: Run, node_id: str, outputs: Any, run_state: dict[str, Any], branch: str | None = None) -> None:
        """At every node boundary RUN persists node outputs, run state, and the next node."""
        self._check()
        if node_id not in run.entered:
            raise Denied(f"checkpoint for {node_id} without its node_entered hook")
        node = run.release.node(node_id)
        if branch is not None and branch not in {node.denial_branch, node.failure_branch}:
            raise Denied(f"{branch} is not a declared branch of {node_id}")
        run.outputs[node_id] = outputs
        run.exited.add(node_id)
        run.in_doubt_cache.discard(node_id)
        self.update_run_state(run, run_state)
        if run.release.pep_form == "proxy":
            self._ev(run, {"type": "node.exited", "node_id": node_id, "outputs_ref": self.evs.payloads.put(outputs) if self.evs.available else "journaled",
                           "data_classes_touched": sorted(run.data_classes_touched), "exposed": run.exposed, "written_by": "run"})
        run.next_node = branch if branch else run.release.next_after(node_id)
        run.last_heartbeat = self.clock.now()
        if run.next_node is None and run.state == "RUNNING":
            self._complete(run)

    def heartbeat(self, run: Run) -> None:
        self._check()
        run.last_heartbeat = self.clock.now()

    def get_run_state(self, run: Run) -> dict[str, Any]:
        self._check()
        return run.run_state()

    def update_run_state(self, run: Run, delta: dict[str, Any]) -> dict[str, Any]:
        """Acknowledged run-state update: data classes read and taint, before the PEP releases a result."""
        self._check()
        for dc in delta.get("data_classes_touched", []):
            run.data_classes_touched.add(dc)
        for t in delta.get("tainted_reads", []):
            if t not in run.tainted_reads:
                run.tainted_reads.append(t)
        if delta.get("exposed"):
            run.exposed = True
        for nid, c in delta.get("step_count", {}).items():
            run.step_counts[nid] = c
        return run.run_state()

    def record_usage(self, run: Run, node_id: str, tokens: int, model: str) -> bool:
        """MGW reports usage; RUN enforces the loop node's token cap and returns cap_reached."""
        run.tokens[node_id] = run.tokens.get(node_id, 0) + tokens
        run.spend_to_date += tokens
        self._ev(run, {"type": "usage.recorded", "node_id": node_id, "tokens": tokens, "model": model})
        n = run.release.node(node_id)
        return n.token_cap is not None and run.tokens[node_id] >= n.token_cap

    def effect_confirmed(self, run: Run, rec: EffectRecord) -> None:
        """The PEP supplies each executed effect's record with `confirm`; RUN keeps a signed copy in the
        checkpoint, an admitted source for compensation when EVS is unreachable."""
        run.effects.append(rec)
        run.in_doubt_cache.discard(rec.node_id)

    def signed_effect_copy(self, run: Run, node_id: str) -> dict[str, Any] | None:
        for r in run.effects:
            if r.node_id == node_id:
                return self.signer.sign({"node_id": r.node_id, "action_hash": r.action_hash, "parameters": r.parameters,
                                         "result": r.result_fields, "decision_event": r.decision_event,
                                         "event_hashes": r.event_hashes, "tool": r.tool})
        return None

    # ------------------------------------------------------------------ counters (A.5)
    def reserve(self, keys: dict[str, str], window: float) -> tuple[str, dict[str, int]]:
        self._check()
        rid = new_id("res")
        now = self.clock.now()
        counts: dict[str, int] = {}
        for kind, key in keys.items():
            full = f"{kind}:{key}"
            lst = self.counters.setdefault(full, [])
            lst[:] = [r for r in lst if r["t"] > now - window and r["status"] != "released"]
            lst.append({"t": now, "rid": rid, "status": "reserved"})
            counts[kind] = len(lst)
        self.reservations[rid] = {"keys": keys, "window": window, "status": "reserved", "t": now}
        return rid, counts

    def release(self, rid: str) -> None:
        """Idempotent; the PEP is the sole releaser."""
        r = self.reservations.get(rid)
        if r is None or r["status"] in {"released", "confirmed"}:
            return
        r["status"] = "released"
        for lst in self.counters.values():
            for x in lst:
                if x["rid"] == rid:
                    x["status"] = "released"

    def confirm(self, rid: str) -> None:
        r = self.reservations.get(rid)
        if r is None:
            return
        if r["status"] == "expired":
            # on an expired reservation, re-increment the window
            self.reserve(r["keys"], r["window"])
            r["status"] = "confirmed"
            return
        r["status"] = "confirmed"
        for lst in self.counters.values():
            for x in lst:
                if x["rid"] == rid:
                    x["status"] = "confirmed"

    def reconcile_counters(self) -> int:
        """RUN reconciles unconfirmed reservations against effect.executed events, matched by action hash
        to the decision's reservation id, at the end of each window and whenever a resolver records an outcome."""
        executed_rids: set[str] = set()
        decision_rid: dict[str, str] = {}
        by_rid: dict[str, dict[str, Any]] = {}
        for e in self.evs.events:
            if e.get("type") == "decision" and e.get("reservation_id"):
                decision_rid[e["action_hash"]] = e["reservation_id"]
                by_rid[e["reservation_id"]] = e
        for e in self.evs.events:
            if e.get("type") == "effect.executed" and e.get("action_hash") in decision_rid:
                executed_rids.add(decision_rid[e["action_hash"]])
        now = self.clock.now()
        fixed = 0
        for rid, r in self.reservations.items():
            if r["status"] == "reserved":
                if rid in executed_rids:
                    self.confirm(rid); fixed += 1
                elif now - r["t"] > r["window"]:
                    r["status"] = "expired"
        # a RUN that lost its windows rebuilds them from the executed effects' recorded keys
        for rid in executed_rids:
            e = by_rid[rid]
            keys = e.get("reservation_keys") or {}
            if not keys or e.get("timestamp", now) <= now - COUNTER_WINDOW:
                continue
            present = any(x["rid"] == rid for lst in self.counters.values() for x in lst)
            if present:
                continue
            for kind, key in keys.items():
                self.counters.setdefault(f"{kind}:{key}", []).append({"t": e["timestamp"], "rid": rid, "status": "confirmed"})
            self.reservations.setdefault(rid, {"keys": keys, "window": COUNTER_WINDOW, "status": "confirmed", "t": e["timestamp"]})
            fixed += 1
        return fixed

    def counter_count(self, kind: str, key: str) -> int:
        return len([x for x in self.counters.get(f"{kind}:{key}", []) if x["status"] != "released"])

    # ------------------------------------------------------------------ holds (A.5, A.2)
    def hold(self, run: Run, node: Node, decision: Any, pending: dict[str, Any], action_hash: str,
             substitution_only: bool = False) -> Hold:
        self._check()
        now = self.clock.now()
        existing = run.holds.get(node.id)
        discharged = existing.discharged if existing and existing.action_hash == action_hash else set()
        h = Hold(hold_id=new_id("hold"), node_id=node.id, action_hash=action_hash, kind="effect",
                 causes=list(decision.hold_causes), approver_set=list(decision.approver_set),
                 approvers_required=decision.approvers_required, hold_time=now,
                 substitution_only=substitution_only, discharged=set(discharged), pending=pending)
        if existing and existing.grant_id:
            self._invalidate_grant(run, existing)
        anchored_to_user = any(b.anchor == "acting_user" for b in node.bounds)
        try:
            if substitution_only:
                pass                      # no grant: the approver's own authority completes the action
            elif self.policy.grants_permitted and not anchored_to_user:
                h.grant_id, h.grant_token = self.ids.mint_resumption_grant(run.run_id, node.id, action_hash, run.agent_id)
                self._ev(run, {"type": "grant.minted", "grant_id": h.grant_id, "action_hash": action_hash})
            elif self.policy.grants_permitted:
                h.grant_id, h.grant_token = self.ids.mint_resumption_grant(run.run_id, node.id, action_hash, run.agent_id)
                self._ev(run, {"type": "grant.minted", "grant_id": h.grant_id, "action_hash": action_hash})
            elif decision.substitution_allowed and not anchored_to_user:
                h.substitution_only = True
            else:
                raise Refused("no resumption path")
        except Unavailable:
            if decision.substitution_allowed and not anchored_to_user and not self.policy.grants_permitted:
                h.substitution_only = True
            else:
                run.holds[node.id] = h
                self._park(run, "IDS unreachable at hold", recoverable=True)
                run.held_before_park = True
                h.timers_suspended_since = now
                return h
        run.holds[node.id] = h
        # preview, PEP-originated, decided like any read
        self._pep(run)
        sysc = self.registry.systems.get(self.registry.tools[node.tool].target_system)
        if node.preview and sysc and sysc.preview_tool:
            try:
                res = self.instruct(run, node.id, "preview", parameters=pending["parameters"])
                h.preview_ref = res.get("result_ref")
            except (Denied, Unavailable, Refused):
                h.preview_ref = None
        view = {"tool": pending["tool"], "parameters": pending["parameters"], "preview": h.preview_ref or "none exists",
                "subject": run.subject, "factors": sorted(pending.get("factors", [])), "bounds": [b.to_dict() for b in node.bounds],
                "causes": h.causes, "discharged": sorted(h.discharged), "counters": pending.get("counters", {}),
                "tainted_reads": list(run.tainted_reads), "provenance_claim": None}
        h.view_ref = self.evs.payloads.put(view) if self.evs.available else "view:journaled"
        self._transition(run, "HELD", "run.held", cause="hold", node_id=node.id)
        self._ev(run, {"type": "hold.created", "node_id": node.id, "kind": "effect", "action_hash": action_hash,
                       "hold_causes": h.causes, "approver_set": h.approver_set, "grant_id": h.grant_id,
                       "substitution_only": h.substitution_only, "preview_ref": h.preview_ref, "view_ref": h.view_ref})
        return h

    def input_hold(self, run: Run, node: Node) -> Hold:
        now = self.clock.now()
        h = Hold(hold_id=new_id("hold"), node_id=node.id, action_hash="", kind="input", causes=["input"],
                 approver_set=list(node.approver_set), approvers_required=1, hold_time=now, substitution_only=False)
        h.view_ref = self.evs.payloads.put({"input_schema": "see release", "tainted_reads": list(run.tainted_reads)}) if self.evs.available else "journaled"
        run.holds[node.id] = h
        self._transition(run, "HELD", "run.held", cause="input", node_id=node.id)
        self._ev(run, {"type": "hold.created", "node_id": node.id, "kind": "input", "hold_causes": ["input"],
                       "approver_set": h.approver_set, "substitution_only": False, "view_ref": h.view_ref})
        return h

    def provide_input(self, run: Run, node_id: str, value: Any, assertion: dict[str, Any]) -> None:
        """Input from a human node enters through RUN with an identity-provider assertion of the person and
        their role; it is tainted unless that role is registered as internal (5.1, A.5)."""
        self._person(assertion)
        role = assertion["payload"].get("role", "")
        h = run.holds[node_id]
        if h.kind != "input" or h.status != "open" or run.state != "HELD":
            raise Refused("no open input hold")
        agent = self.registry.agents[run.agent_id]
        tainted = role not in agent.input_roles_internal
        if tainted:
            run.exposed = True
            run.tainted_reads.append(f"human:{node_id}")
            self._ev(run, {"type": "taint.applied", "source": f"human:{role}", "items": [node_id]})
        run.outputs[node_id] = {"input": value, "tainted": tainted}
        h.status = "resolved"
        self._ev(run, {"type": "hold.resolved", "node_id": node_id, "outcome": "approved", "approvers": [role], "substitution": False})
        self._transition(run, "RUNNING", "run.resumed", cause="approved")
        run.exited.add(node_id)
        run.next_node = run.release.next_after(node_id)

    def status_assertion(self, run: Run, h: Hold) -> dict[str, Any]:
        """RUN-signed assertion of the approved-action record's status and the timer state."""
        susp = [list(s) for s in h.suspensions]
        if h.timers_suspended_since is not None:
            susp.append([h.timers_suspended_since, self.clock.now()])
        return self.signer.sign({"record_status": "valid" if h.approved_action_valid else "invalidated",
                                 "action_hash": h.action_hash, "run_id": run.run_id, "node_id": h.node_id,
                                 "hold_time": h.hold_time, "approval_time": h.approval_time, "suspensions": susp})

    def approve(self, run: Run, node_id: str, approver: str, approver_assertion: dict[str, Any]) -> dict[str, Any]:
        """An approver decides through OPS. RUN embeds the identity-provider assertion, signs the record,
        marks it grant or substitution, and instructs the PEP to resume."""
        self._check()
        h = run.holds[node_id]
        if h.status != "open" or run.state not in {"HELD", "PARKED"}:
            raise Refused("no open hold")
        if approver not in h.approver_set:
            raise Refused("approver not in the approver set")
        if any(a["approver"] == approver for a in h.approvals):
            raise Refused("an approver approves once")
        h.approvals.append({"approver": approver, "assertion": approver_assertion, "at": self.clock.now()})
        if len(h.approvals) < h.approvers_required:
            return {"status": "awaiting_second_approver"}
        h.approval_time = self.clock.now()
        status = "none"
        ids_unreachable = False
        if run.acting_user is not None:
            try:
                status = self.ids.delegation_status(run.acting_user)
            except Unavailable:
                ids_unreachable = True     # the approval is recorded; redemption will check the delegation
        if run.acting_user is not None and not ids_unreachable and status != "valid":
            if self.policy.substitution_permitted and not any(b.anchor == "acting_user" for b in run.release.node(node_id).bounds):
                h.record_kind = "substitution"
            else:
                return self._deny_hold(run, h, "revoked")
        else:
            h.record_kind = "grant" if h.grant_id else "substitution"
        h.discharged |= set(h.causes)
        h.status = "approved"
        h.approved_action_valid = True
        tool = self.registry.tools[run.release.node(node_id).tool]
        h.approval_record = self.signer.sign({
            "approval_ref": h.hold_id, "action_hash": h.action_hash, "kind": h.record_kind,
            "approver_assertion": h.approvals[0]["assertion"], "approvals": [a["assertion"] for a in h.approvals],
            "acting_user": run.acting_user, "agents": list(run.agents),
            "release": {"agent_id": run.release.agent_id, "version": run.release.version, "surface": run.release.surface, "pep_form": run.release.pep_form},
            "audience": tool.target_system, "causes_discharged": sorted(h.discharged),
            "approved_at": h.approval_time})
        self._ev(run, {"type": "hold.resolved", "node_id": node_id, "outcome": "approved",
                       "approvers": [a["approver"] for a in h.approvals], "causes_discharged": sorted(h.discharged),
                       "causes_remaining": [], "substitution": h.record_kind == "substitution"})
        if run.state == "HELD":
            self._transition(run, "RUNNING", "run.resumed", cause="approved")
            try:
                return self.instruct(run, node_id, "resume", approval_ref=h.approval_record, grant=h.grant_token)
            except Unavailable as e:
                # the approval stands; the resume is retried on recovery with the record (6.1)
                self._park(run, f"{e.component} unreachable at resume", recoverable=True)
                run.held_before_park = True
                h.timers_suspended_since = self.clock.now()
                return {"status": "approved_while_parked"}
        return {"status": "approved_while_parked"}

    def _deny_hold(self, run: Run, h: Hold, outcome: str, approver: str | None = None) -> dict[str, Any]:
        h.status = "resolved"
        self._invalidate_grant(run, h)
        self._ev(run, {"type": "hold.resolved", "node_id": h.node_id, "outcome": outcome,
                       "approvers": [approver] if approver else [], "substitution": False})
        try:
            self._pep(run).release_pending(run, h.node_id)
        except Denied:
            pass
        if run.state == "PARKED":
            run.deferred_branch = (h.node_id, "denial")      # applied when the run leaves PARKED
            return {"status": f"{outcome}_while_parked"}
        self._transition(run, "RUNNING", "run.resumed", cause="denial_branch")
        self._follow_branch(run, h.node_id, "denial")
        return {"status": outcome}

    def deny(self, run: Run, node_id: str, approver: str) -> dict[str, Any]:
        self._check()
        h = run.holds.get(node_id)
        if h is None or h.status != "open" or run.state not in {"HELD", "PARKED"}:
            raise Refused("no open hold")
        if approver not in h.approver_set:
            raise Refused("approver not in the approver set")
        return self._deny_hold(run, h, "denied", approver)

    def _invalidate_grant(self, run: Run, h: Hold) -> None:
        if h.grant_id:
            try:
                self.ids.invalidate_grant(h.grant_id)
            except Unavailable:
                pass
            self._ev(run, {"type": "grant.invalidated", "grant_id": h.grant_id, "action_hash": h.action_hash})
        h.approved_action_valid = False

    def rehold(self, run: Run, node: Node, decision: Any, pending: dict[str, Any], action_hash: str) -> Hold:
        """A resubmission held again with only the new causes: the discharged set is kept, the approval
        record superseded, and the re-hold counts toward the maximum."""
        prev = run.holds.get(node.id)
        if prev:
            prev.status = "resolved"
            self._ev(run, {"type": "hold.resolved", "node_id": node.id, "outcome": "superseded", "approvers": [],
                           "causes_discharged": sorted(prev.discharged), "causes_remaining": decision.hold_causes, "substitution": False})
        run.rehold_counts[action_hash] = run.rehold_counts.get(action_hash, 0) + 1
        return self.hold(run, node, decision, pending, action_hash)

    def substitution_hold(self, run: Run, node: Node, pending: dict[str, Any], action_hash: str) -> Hold:
        """Delegation found revoked at redemption: a new hold with the single cause substitution_required."""
        from .policy import Decision
        d = Decision("HOLD", "substitution", None, ["substitution_required"], list(node.approver_set) or ["approver-1"], True, [], 1)
        run.rehold_counts[action_hash] = run.rehold_counts.get(action_hash, 0) + 1
        if run.rehold_counts[action_hash] > self.policy.rehold_maximum:
            self._ev(run, {"type": "hold.resolved", "node_id": node.id, "outcome": "denied", "approvers": [], "substitution": True})
            self._transition(run, "RUNNING", "run.resumed", cause="denial_branch")
            self._follow_branch(run, node.id, "denial")
            raise Denied("re-hold maximum")
        return self.hold(run, node, d, pending, action_hash, substitution_only=True)

    def approved_action_used(self, run: Run, node_id: str, event: str) -> None:
        """The approved-action record is invalidated on effect.executed, effect.failed, a later hold or
        denial of the same action hash, or stop."""
        h = run.holds.get(node_id)
        if h:
            h.approved_action_valid = False
            if h.status == "approved":
                h.status = "resolved"

    # ------------------------------------------------------------------ effects in doubt (A.5)
    def evidence_for(self, run: Run) -> list[dict[str, Any]]:
        evs = self.evs.read_unchecked(run.run_id)
        pep = self.peps.get(run.workload or "")
        if pep is not None and pep.journal.entries:
            run.unreconciled_journal = True
        return evs

    def in_doubt(self, run: Run, node_id: str) -> bool:
        """RUN has the entry hook, no exit checkpoint, the latest purpose = normal decision for the
        effect's own action hash is ALLOW, and there is no effect event or the latest one is indeterminate."""
        if node_id not in run.entered or node_id in run.exited:
            return False
        pep = self.peps.get(run.workload or "")
        if pep is not None and pep.journal.entries:
            run.unreconciled_journal = True
            return False
        evs = self.evs.read_unchecked(run.run_id)
        decisions = [e for e in evs if e["type"] == "decision" and e["node_id"] == node_id and e["purpose"] == "normal"]
        if not decisions or decisions[-1]["decision"] != "ALLOW":
            return False
        ah = decisions[-1]["action_hash"]
        effects = [e for e in evs if e["type"].startswith("effect.") and e.get("action_hash") == ah
                   and not (e["type"] == "effect.failed" and e.get("purpose") == "replay")]
        return not effects or effects[-1]["type"] == "effect.indeterminate"

    def resolve_in_doubt(self, run: Run, node_id: str) -> str:
        """Replay with the recorded key up to a policy-set count, else park with the resolver."""
        node = run.release.node(node_id)
        sysc = self.registry.systems[self.registry.tools[node.tool].target_system]
        run.in_doubt_cache.add(node_id)
        while sysc.idempotency and run.replay_attempts.get(node_id, 0) < self.policy.consecutive_replays:
            run.replay_attempts[node_id] = run.replay_attempts.get(node_id, 0) + 1
            res = self.instruct(run, node_id, "replay")
            status = res.get("status")
            if status == "executed":
                self._node_resolved_executed(run, node_id, res.get("outputs"))
                return "replayed"
            if status == "denied":
                self._park(run, "replay denied", recoverable=False)
                return "parked"
            if status == "failed":
                self._park(run, "replay refused by the system; effect in doubt needs a resolver", recoverable=False)
                return "parked"
            if status == "not_attempted":
                break                     # no credential: nothing was sent; park recoverably, retry on recovery
            # indeterminate again: try the next replay within the count
        if run.state == "PARKED":
            return "parked"
        if res.get("status") == "not_attempted" if sysc.idempotency and run.replay_attempts.get(node_id, 0) else False:
            run.replay_attempts[node_id] -= 1
            self._park(run, "replay needs a credential", recoverable=True)
            return "parked"
        self._park(run, "effect in doubt needs a resolver", recoverable=False)
        return "parked"

    def _resolver(self, run: Run, assertion: dict[str, Any]) -> str:
        person = self._person(assertion)
        expected = (run.park or {}).get("resolver") or self.resolver
        if person != expected:
            raise Refused(f"{person} is not the resolver of this run")
        return person

    def _owner(self, run: Run, assertion: dict[str, Any]) -> str:
        person = self._person(assertion)
        if person != self.registry.agents[run.agent_id].owner:
            raise Refused("only the owner closes, resumes, or cancels a run with an exception")
        return person

    def record_outcome(self, run: Run, node_id: str, outcome: str, evidence_ref: str,
                       result_fields: dict[str, Any] | None = None, assertion: dict[str, Any] | None = None) -> None:
        """A resolver verifies against the system and records the outcome; RUN writes the matching
        effect event with recorded_by = resolver."""
        self._check()
        if run.state not in {"PARKED", "ESCALATED"}:
            raise Refused("outcomes are recorded on a parked run")
        if not self.in_doubt(run, node_id):
            raise Refused(f"{node_id} is not in doubt")
        resolver = self._resolver(run, assertion)
        node = run.release.node(node_id)
        tool = self.registry.tools[node.tool]
        evs = self.evs.read_unchecked(run.run_id)
        decisions = [e for e in evs if e["type"] == "decision" and e["node_id"] == node_id and e["purpose"] == "normal"]
        ah = decisions[-1]["action_hash"] if decisions else ""
        presentation = self.registry.systems[tool.target_system].presentation
        if outcome == "executed":
            self._ev(run, {"type": "effect.executed", "node_id": node_id, "purpose": "normal", "credential_presentation": presentation,
                           "result_ref": evidence_ref, "recorded_by": "resolver", "resolver": resolver, "action_hash": ah})
            self.effect_confirmed(run, EffectRecord(node_id, ah, decisions[-1]["event_id"] if decisions else "",
                                                    decisions[-1].get("parameters", {}) if decisions else {}, result_fields or {},
                                                    evidence_ref, [], tool.tool_id))
            self._node_resolved_executed(run, node_id, result_fields or {})
        else:
            self._ev(run, {"type": "effect.failed", "node_id": node_id, "purpose": "normal", "credential_presentation": presentation,
                           "error": "not_executed", "recorded_by": "resolver", "resolver": resolver, "action_hash": ah})
            run.not_executed.add(node_id)
            run.in_doubt_cache.discard(node_id)
            run.entered = [n for n in run.entered if n != node_id]
            run.next_node = node_id
        self.approved_action_used(run, node_id, "resolver")
        self.reconcile_counters()

    def _node_resolved_executed(self, run: Run, node_id: str, outputs: Any) -> None:
        """When a replay or a resolver outcome resolves a node as executed, RUN writes node.exited with the
        recorded result, advances the checkpoint, and the restarted runtime enters the successor."""
        run.in_doubt_cache.discard(node_id)
        self._ev(run, {"type": "node.exited", "node_id": node_id, "outputs_ref": self.evs.payloads.put(outputs) if self.evs.available else "journaled",
                       "data_classes_touched": sorted(run.data_classes_touched), "exposed": run.exposed})
        run.outputs[node_id] = outputs
        run.exited.add(node_id)
        run.next_node = run.release.next_after(node_id)

    # ------------------------------------------------------------------ parks, stops, timers
    def _park(self, run: Run, reason: str, recoverable: bool) -> None:
        if run.state == "HELD":
            run.held_before_park = True
            h = next((x for x in run.holds.values() if x.status in {"open", "approved"}), None)
            if h and h.timers_suspended_since is None:
                h.timers_suspended_since = self.clock.now()
        elif run.state == "RUNNING":
            run.held_before_park = False
        run.park = {"reason": reason, "resolver": self.resolver, "deadline": self.clock.now() + self.park_deadline,
                    "recoverable": recoverable, "from": run.state}
        self.park_queue.append(run.run_id)
        self._transition(run, "PARKED", "run.parked", cause=reason, resolver=self.resolver, deadline=run.park["deadline"])
        self.notifications.append(f"owner of {run.agent_id}: run {run.run_id} parked: {reason}")

    def park(self, run: Run, reason: str) -> None:
        self._park(run, reason, recoverable=True)

    def recover(self, run: Run) -> str:
        """A run parked by degradation, host loss, an unreconciled journal, or an unreachable IDS at hold
        resumes without a resolver once the cause has cleared and any effect in doubt is resolved."""
        self._check()
        if run.state != "PARKED" or not run.park or not run.park.get("recoverable"):
            return run.state
        pep = self.peps.get(run.workload or "")
        if pep is not None and pep.journal.entries:
            try:
                self.evs.reconcile(pep.journal, self.trust)
                run.unreconciled_journal = False
            except Unavailable:
                return run.state
        for nid in list(run.entered):
            if self.in_doubt(run, nid):
                r = self.resolve_in_doubt(run, nid)
                if r != "replayed":
                    return run.state
        self._end_suspension(run)
        if run.deferred_branch:
            nid, kind = run.deferred_branch
            run.deferred_branch = None
            run.park = None
            self._transition(run, "RUNNING", "run.resumed", cause="denial_branch")
            self._follow_branch(run, nid, kind)
            return run.state
        if run.held_before_park:
            h = next((x for x in run.holds.values() if x.status in {"open", "approved"}), None)
            if h and h.status == "approved":
                if self._approval_expired(h):
                    return self._reopen_expired(run, h)
                self._transition(run, "RUNNING", "run.resumed", cause="recovered")
                self.instruct(run, h.node_id, "resume", approval_ref=h.approval_record, grant=h.grant_token)
                return run.state
            if h and h.grant_id is None and not h.substitution_only:
                try:
                    h.grant_id, h.grant_token = self.ids.mint_resumption_grant(run.run_id, h.node_id, h.action_hash, run.agent_id)
                    self._ev(run, {"type": "grant.minted", "grant_id": h.grant_id, "action_hash": h.action_hash})
                except Unavailable:
                    return run.state
            if h and self._approval_timed_out(h):
                run.park = None
                self._transition(run, "RUNNING", "run.resumed", cause="recovered")
                self._deny_hold(run, h, "timeout")
                return run.state
            run.park = None
            run.state = "HELD"
            self._ev(run, {"type": "run.held", "cause": "recovered"})
            return run.state
        run.park = None
        self._transition(run, "RUNNING", "run.resumed", cause="recovered")
        for nid in list(run.not_executed) + list(run.cancelled_effects):
            run.next_node = nid
        return run.state

    def _end_suspension(self, run: Run) -> None:
        for h in run.holds.values():
            if h.timers_suspended_since is not None:
                end = min(self.clock.now(), h.timers_suspended_since + self.policy.max_park)
                h.suspensions.append([h.timers_suspended_since, end])
                h.timers_suspended_since = None

    def _suspended_total(self, h: Hold, since: float | None = None) -> float:
        """Suspended time credited to a timer, clipped to intervals after `since` and capped at max_park."""
        now = self.clock.now()
        intervals = [list(x) for x in h.suspensions]
        if h.timers_suspended_since is not None:
            intervals.append([h.timers_suspended_since, now])
        total = 0.0
        for s, e in intervals:
            if since is not None:
                s = max(s, since)
            if e > s:
                total += e - s
        return min(total, self.policy.max_park)

    def _approval_timed_out(self, h: Hold) -> bool:
        return h.approval_time is None and self.clock.now() - h.hold_time - self._suspended_total(h, h.hold_time) > self.policy.approval_timeout

    def _approval_expired(self, h: Hold) -> bool:
        return h.approval_time is not None and self.clock.now() - h.approval_time - self._suspended_total(h, h.approval_time) > self.policy.resume_window

    def _reopen_expired(self, run: Run, h: Hold) -> str:
        """If the window expires after an approval, the hold is re-opened with the same causes and the same
        approver set, the discharged set cleared, counting toward the re-hold maximum."""
        self._ev(run, {"type": "hold.resolved", "node_id": h.node_id, "outcome": "expired", "approvers": [], "substitution": False})
        self._invalidate_grant(run, h)
        run.rehold_counts[h.action_hash] = run.rehold_counts.get(h.action_hash, 0) + 1
        if run.rehold_counts[h.action_hash] > self.policy.rehold_maximum:
            h.status = "resolved"
            run.park = None
            self._transition(run, "RUNNING", "run.resumed", cause="recovered")
            self._deny_hold(run, h, "denied")
            return run.state
        from .policy import Decision
        d = Decision("HOLD", "expired", None, list(h.causes), list(h.approver_set), self.policy.substitution_permitted, [], h.approvers_required)
        h.status = "resolved"
        run.park = None
        run.state = "RUNNING"
        new = self.hold(run, run.release.node(h.node_id), d, h.pending, h.action_hash)
        new.discharged = set()
        return run.state

    def tick(self) -> None:
        """Timers: approval timeouts, host loss, wall-clock budgets, park and owner deadlines."""
        now = self.clock.now()
        for run in list(self.runs.values()):
            if run.state == "HELD":
                for h in list(run.holds.values()):
                    if h.status == "open" and self._approval_timed_out(h):
                        self._deny_hold(run, h, "timeout")
            if run.state == "RUNNING" and self.available:
                if now > self.grace_until and now - run.last_heartbeat > self.policy.heartbeat_deadline:
                    self._park(run, "host lost", recoverable=True)
                elif now - run.started_at > self.policy.wall_clock_budget:
                    self._park(run, "wall-clock budget exceeded", recoverable=False)
            if run.state == "PARKED" and run.park and now > run.park["deadline"]:
                run.escalation = {"owner": self.registry.agents[run.agent_id].owner, "deadline": now + self.owner_deadline}
                self._transition(run, "ESCALATED", "run.escalated", cause="deadline", resolver=self.resolver, deadline=run.escalation["deadline"])
            if run.state == "ESCALATED" and run.escalation and now > run.escalation["deadline"]:
                self.ops_close(run)
        self.reconcile_counters()

    def mark_outage_end(self) -> None:
        """On return from a RUN outage: reconstruct suspension intervals and apply a grace period."""
        if self.outage_window:
            start, end = self.outage_window
            for run in self.runs.values():
                for h in run.holds.values():
                    if h.status in {"open", "approved"}:
                        h.suspensions.append([start, min(end, start + self.policy.max_park)])
            self.outage_window = None
        self.grace_until = self.clock.now() + self.policy.heartbeat_deadline

    # ------------------------------------------------------------------ stops (4.9)
    def record_stop(self, stop: dict[str, Any]) -> None:
        self.stop_register.append(stop)

    def lift_stop(self, stop_id: str) -> None:
        self.stop_register = [s for s in self.stop_register if s["stop_id"] != stop_id]

    def stop_in_scope(self, agent_id: str, surface: str, release: Release | None = None) -> dict[str, Any] | None:
        """A current stop in RUN's register whose scope reaches the agent, the surface, or (for a tool
        scope) a tool the release declares."""
        for st in self.stop_register:
            k, v = st["scope_kind"], st["scope_value"]
            if k == "fleet" or (k == "agent" and v == agent_id) or (k == "surface" and v == surface):
                return st
            if k == "tool" and release is not None and any(v in n.declared_tools() for n in release.nodes):
                return st
        return None

    def stop_refusal(self, run: Run, node_id: str, stop_ref: str | None) -> None:
        """The PEP refused an effect, delivery, or spawn from its own list: the run leaves RUNNING. It is
        cancelled if no effect node was entered, else parked at that node for the resolver (4.9)."""
        if run.state != "RUNNING":
            return
        run.stop_ref = stop_ref
        run.cancelled_effects.add(node_id)
        run.entered = [n for n in run.entered if n != node_id]
        self._transition(run, "STOPPING", "run.stopping", cause="stop", stop_ref=stop_ref)
        if not run.effect_node_entered:
            self._transition(run, "CANCELLED", "run.cancelled", final_state="CANCELLED", exposed=run.exposed,
                             data_classes_touched=sorted(run.data_classes_touched))
        else:
            self._park(run, f"stop {stop_ref or 'list stale'} at {node_id}", recoverable=False)

    def apply_stop(self, stop: dict[str, Any], in_scope) -> None:
        """Effect of a stop on runs in flight: cancel unexecuted held effects (effect.failed, stopped),
        cut loops, then CANCELLED if no effect node was ever entered, else PARKED."""
        for run in list(self.runs.values()):
            if run.state not in {"RUNNING", "HELD"} or not in_scope(run):
                continue
            run.stop_ref = stop["stop_id"]
            self._transition(run, "STOPPING", "run.stopping", cause="stop", stop_ref=stop["stop_id"])
            for h in list(run.holds.values()):
                if h.status in {"open", "approved"}:
                    if h.kind == "effect":
                        self._pep(run).cancel_pending(run, h.node_id)
                        run.cancelled_effects.add(h.node_id)
                    h.status = "resolved"
                    self._invalidate_grant(run, h)
                    self._ev(run, {"type": "hold.resolved", "node_id": h.node_id, "outcome": "stopped", "approvers": [], "substitution": False})
            if not run.effect_node_entered:
                self._transition(run, "CANCELLED", "run.cancelled", final_state="CANCELLED", exposed=run.exposed,
                                 data_classes_touched=sorted(run.data_classes_touched))
                for cid in run.children.values():
                    child = self.runs.get(cid)
                    if child and child.state not in TERMINAL:
                        self.notifications.append(f"child {cid} of cancelled run continues to its own declared state")
            else:
                for nid in list(run.entered):
                    if self.in_doubt(run, nid):
                        self.resolve_in_doubt(run, nid)
                if run.state == "STOPPING":
                    self._park(run, f"stop {stop['stop_id']}", recoverable=False)

    def resolver_resume(self, run: Run, assertion: dict[str, Any]) -> str:
        """A resolver resumes a parked run (after a stop lifts, or after recording an outcome)."""
        self._check()
        if run.state not in {"PARKED", "ESCALATED"}:
            raise Refused("not parked")
        resolver = self._resolver(run, assertion)
        for nid in list(run.entered):
            if self.in_doubt(run, nid):
                raise Refused("resolve effects in doubt first")
        run.park = None
        self._transition(run, "RUNNING", "run.resumed", cause="resolver", decided_by=resolver)
        for nid in list(run.cancelled_effects):
            run.next_node = nid
            run.cancelled_effects.discard(nid)
            run.entered = [n for n in run.entered if n != nid]
        return run.state

    def resolver_cancel(self, run: Run, assertion: dict[str, Any]) -> str:
        """Cancelling compensates every executed effect in reverse order; a failed or irreversible one parks."""
        self._check()
        if run.state not in {"PARKED", "ESCALATED"}:
            raise Refused("not parked")
        resolver = self._resolver(run, assertion)
        return self._compensate_all(run, "resolver", resolver)

    def _compensate_all(self, run: Run, cause: str, actor: str, unconditional: bool = False) -> str:
        self._transition(run, "COMPENSATING", "run.compensating", cause=cause, decided_by=actor)
        for rec in reversed(run.effects):
            if not rec.executed:
                continue
            node = run.release.node(rec.node_id)
            if node.compensate == "irreversible":
                if unconditional:
                    continue
                self._park(run, f"effect {rec.node_id} is irreversible", recoverable=False)
                return run.state
            res = self.instruct(run, node.compensate, "compensation", original_node=rec.node_id)
            if res.get("status") != "executed":
                if unconditional:
                    self.notifications.append(f"compensation of {rec.node_id} failed during the OPS close; recorded, not re-parked")
                    continue
                self._park(run, f"compensation of {rec.node_id} failed", recoverable=False)
                return run.state
            rec.executed = False
        if unconditional:
            return run.state
        self._transition(run, "COMPENSATED", "run.compensated", final_state="COMPENSATED", exposed=run.exposed,
                         data_classes_touched=sorted(run.data_classes_touched))
        return run.state

    def owner_close(self, run: Run, disposition: str, assertion: dict[str, Any]) -> str:
        self._check()
        owner = self._owner(run, assertion)
        if run.state not in {"PARKED", "ESCALATED"}:
            raise Refused("not parked or escalated")
        return self._close(run, disposition, owner)

    def owner_resume(self, run: Run, assertion: dict[str, Any]) -> str:
        self._check()
        owner = self._owner(run, assertion)
        if run.state != "ESCALATED":
            raise Refused("owner resume from ESCALATED only")
        run.park = None; run.escalation = None
        self._transition(run, "RUNNING", "run.resumed", cause="owner", decided_by=owner)
        return run.state

    def owner_cancel(self, run: Run, assertion: dict[str, Any]) -> str:
        self._check()
        owner = self._owner(run, assertion)
        if run.state != "ESCALATED":
            raise Refused("owner cancel from ESCALATED only")
        return self._compensate_all(run, "owner", owner)

    def ops_close(self, run: Run) -> str:
        """When the owner's deadline passes, OPS runs the declared compensations and closes the run with
        disposition owner_deadline_passed; the owner is notified."""
        self._compensate_all(run, "owner_deadline", "OPS", unconditional=True)
        self.notifications.append(f"owner of {run.agent_id}: run {run.run_id} closed by OPS on the owner's deadline")
        return self._close(run, "owner_deadline_passed", "OPS")

    def _close(self, run: Run, disposition: str, actor: str) -> str:
        run.disposition = disposition
        self._transition(run, "CLOSED_WITH_EXCEPTION", "run.closed_with_exception", final_state="CLOSED_WITH_EXCEPTION",
                         exposed=run.exposed, data_classes_touched=sorted(run.data_classes_touched),
                         disposition=disposition, decided_by=actor)
        return run.state

    def _complete(self, run: Run) -> None:
        self._transition(run, "COMPLETED", "run.completed", final_state="COMPLETED", exposed=run.exposed,
                         data_classes_touched=sorted(run.data_classes_touched),
                         effects_in_doubt=[n for n in run.entered if n in run.in_doubt_cache])

    def runtime_error(self, run: Run, node_id: str, error: str) -> str:
        """A runtime error: FAILED only if no effect node was ever entered, else PARKED with effects in
        doubt resolved first."""
        if run.state != "RUNNING":
            return run.state
        if not run.effect_node_entered:
            self._transition(run, "FAILED", "run.failed", final_state="FAILED", exposed=run.exposed,
                             data_classes_touched=sorted(run.data_classes_touched))
            return run.state
        for nid in list(run.entered):
            if self.in_doubt(run, nid):
                r = self.resolve_in_doubt(run, nid)
                if r == "parked":
                    return run.state
        self._park(run, f"runtime error: {error}", recoverable=True)
        return run.state

    def _follow_branch(self, run: Run, node_id: str, kind: str) -> None:
        """Denial branch on deny/timeout/cancel; failure branch on a definitive effect.failed; a node
        with no failure branch takes its denial branch; no branch declared ends the run on that branch."""
        node = run.release.node(node_id)
        target = node.failure_branch if kind == "failure" and node.failure_branch else node.denial_branch
        run.exited.add(node_id)
        run.in_doubt_cache.discard(node_id)
        if target is None:
            run.next_node = None
            if run.state == "RUNNING":
                self._complete(run)
        else:
            run.next_node = target

    def cancel(self, run: Run) -> None:
        """cancel(run) from the contract: RUN's own cancellation (used by OPS on its own authority)."""
        if run.state not in {"PARKED", "ESCALATED"}:
            raise Refused("not parked")
        self._compensate_all(run, "resolver", self.resolver)

    # ------------------------------------------------------------------ child runs (4.7, A.2)
    def spawn(self, parent: Run, node: Node, inputs: dict[str, Any]) -> Run:
        """On ALLOW of a spawn decision, RUN starts the child through the target agent's registered launcher.
        The spawn is synchronous from the parent's PEP; the child's final exposure comes back."""
        target = self.registry.agents[node.target_agent]
        if node.id in parent.children:
            child = self.runs[parent.children[node.id]]
            return child
        if target.launcher is None:
            raise Refused("target agent has no registered launcher")
        child = target.launcher(parent=parent, inputs=inputs, as_service=node.type == "service", run=self)
        parent.children[node.id] = child.run_id
        return child
