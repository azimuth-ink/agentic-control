"""PEP, the Policy Enforcement Point (spec A.4), embedded form.

Every call a governed agent makes passes through it: tool calls, reads, retrieval, memory, sanitizers,
previews, deliveries, model calls, and child-run spawns. Per call it resolves parameter roles,
derives factors, computes the action hash, reserves counters with RUN, writes the decision to EVS
before any effect (I3), obtains and presents sender-constrained credentials, applies obligations, and
updates run state at RUN before releasing a result. It holds the signed bundle and stop list and keeps
a signed local journal for degraded mode."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .common import Clock, Denied, Refused, Unavailable, digest, new_id
from .coordinator import EffectRecord, Run, RunCoordinator
from .crypto import TrustStore
from .dbs import DLP, Indeterminate, System, SystemRefused
from .evidence import EvidenceStore, Journal
from .identity import IdentityService
from .policy import Decision, DecisionRequest, PolicyBundle, PolicyDecisionPoint, StopList, apply_mapping
from .registry import Registry, ToolManifest
from .release import Node, scope_only

COUNTER_WINDOW = 3600.0


class Held(Exception):
    """Raised to the runtime when a call is held; the run continues on resume."""

    def __init__(self, node_id: str) -> None:
        super().__init__(f"held at {node_id}")
        self.node_id = node_id


class NodeFailed(Exception):
    """A definitive effect.failed: the runtime follows the node's failure branch (RUN already moved the checkpoint)."""


@dataclass
class PendingEffect:
    node_id: str
    tool: ToolManifest
    parameters: dict[str, Any]
    provenance: dict[str, str]
    action_hash: str
    factors: set[str]
    keys: dict[str, str]
    reservation: str | None = None


class EnforcementPoint:
    """One PEP per hosting workload. `form` is sidecar, sdk, or proxy; `surface` is the workload's."""

    def __init__(self, workload: str, form: str, surface: str, build_hash: str, registry: Registry, pdp: PolicyDecisionPoint,
                 run: RunCoordinator, ids: IdentityService, evs: EvidenceStore, clock: Clock, trust: TrustStore,
                 systems: dict[str, System], dlp: DLP, mgw: Any = None) -> None:
        self.workload = workload
        self.form = form
        self.surface = surface
        self.build_hash = build_hash
        self.registry, self.pdp, self.run, self.ids, self.evs, self.clock, self.trust = registry, pdp, run, ids, evs, clock, trust
        self.systems = systems
        self.dlp = dlp
        self.mgw = mgw
        self.binding = None   # set by `bind`, which attests the build to IDS
        self.journal: Journal | None = None
        self.bundle: PolicyBundle | None = None
        self.signed_bundle: dict[str, Any] | None = None
        self.stop_list: StopList | None = None
        self.stop_list_signed: dict[str, Any] | None = None
        self.pending: dict[tuple[str, str], PendingEffect] = {}       # (run_id, node_id) -> pending held effect
        self.sanitized: dict[str, set[str]] = {}                       # run_id -> accepted value hashes
        self.credential_cache: dict[tuple[str, str, str], dict[str, Any]] = {}  # (run, node, audience)
        self.capped_nodes: set[tuple[str, str]] = set()
        self.local_counters: dict[str, int] = {}
        self.local_checkpoint: dict[str, str | None] = {}              # run_id -> next node (degraded mode)
        self.local_entered: dict[str, list[str]] = {}
        self.degraded_calls = 0
        self.step_counts: dict[tuple[str, str], int] = {}
        self.last_decision_event: dict[tuple[str, str], str] = {}
        self.instructions: list[dict[str, Any]] = []
        run.register_pep(workload, self)

    def bind(self, agent_id: str) -> None:
        """Attests the build to IDS and receives the workload key that signs the journal."""
        self.binding = self.ids.bind_workload(self.workload, agent_id, self.surface, self.build_hash)
        self.journal = Journal(self.workload, self.binding.signer, self.clock)

    # ------------------------------------------------------------------ bundle and stop list
    def load_bundle(self, signed: dict[str, Any], bundle: PolicyBundle) -> None:
        if not self.trust.verify(signed, role="policy_authority"):
            raise Denied("bundle signature")
        self.signed_bundle, self.bundle = signed, bundle

    def update_stop_list(self, signed: dict[str, Any], sl: StopList) -> None:
        if not self.trust.verify(signed, role="ops"):
            raise Denied("stop list signature")
        self.stop_list_signed, self.stop_list = signed, sl
        for run in list(self.run.runs.values()):
            if run.workload == self.workload and run.state == "RUNNING":
                for nid in run.entered:
                    n = run.release.node(nid)
                    if n.type == "loop" and nid not in run.exited and sl.in_scope(run.agent_id, None, run.surface):
                        self.capped_nodes.add((run.run_id, nid))

    def _stale(self) -> bool:
        if self.stop_list is None:
            return False
        return self.clock.now() > self.stop_list.issued_at + self.stop_list.validity

    def _stopped(self, run: Run, tool_id: str | None) -> bool:
        if self._stale():
            return True
        return self.stop_list is not None and self.stop_list.in_scope(run.agent_id, tool_id, run.surface) is not None

    # ------------------------------------------------------------------ evidence
    def _write(self, run: Run, event: dict[str, Any]) -> str:
        """Writes to EVS and waits for the durable acknowledgement; in degraded mode, to the journal."""
        ev = {**run.header(), **event}
        try:
            return self.evs.append(ev)
        except Unavailable:
            assert self.journal is not None
            self.degraded_calls += 1
            return self.journal.append(ev)["event_id"]

    def _evidence(self, run: Run) -> list[dict[str, Any]]:
        try:
            evs = self.evs.read(run_id=run.run_id)
        except Unavailable:
            evs = []
        if self.journal:
            evs = evs + [e for e in self.journal.events() if e.get("run_id") == run.run_id]
        return evs

    # ------------------------------------------------------------------ node lifecycle (hook contract)
    def enter_node(self, run: Run, node: Node, inputs: Any) -> None:
        """PEP-E calls the node_entered hook itself; the PEP rejects calls for a node until RUN confirms it."""
        inputs_ref = self._payload(inputs)
        try:
            ok = self.run.node_entered(run, node.id, node.type, inputs_ref)
            if not ok:
                raise Denied(f"RUN rejected node_entered for {node.id}: not the checkpointed next node, or in doubt")
        except Unavailable:
            if self.form == "proxy":
                raise
            nxt = self.local_checkpoint.get(run.run_id, run.next_node)
            if node.id != nxt:
                raise Denied(f"local next-node rule rejects {node.id}")
            self.local_entered.setdefault(run.run_id, []).append(node.id)
            run.entered.append(node.id)
            if node.type == "effect":
                run.effect_node_entered = True
            self._write(run, {"type": "node.hook", "node_id": node.id, "node_type": node.type, "inputs_ref": inputs_ref})
        self._write(run, {"type": "node.entered", "node_id": node.id, "node_type": node.type, "inputs_ref": inputs_ref,
                          "provenance_claimed": False})
        self.step_counts[(run.run_id, node.id)] = 0

    def exit_node(self, run: Run, node: Node, outputs: Any, branch: str | None = None) -> None:
        self._write(run, {"type": "node.exited", "node_id": node.id, "outputs_ref": self._payload(outputs),
                          "data_classes_touched": sorted(run.data_classes_touched), "exposed": run.exposed})
        try:
            self.run.checkpoint(run, node.id, outputs, {"step_count": {node.id: self.step_counts.get((run.run_id, node.id), 0)}}, branch)
        except Unavailable:
            if self.form == "proxy":
                raise
            run.outputs[node.id] = outputs
            run.exited.add(node.id)
            run.next_node = branch or run.release.next_after(node.id)
            self.local_checkpoint[run.run_id] = run.next_node

    def heartbeat(self, run: Run) -> None:
        try:
            self.run.heartbeat(run)
        except Unavailable:
            pass

    def _payload(self, obj: Any) -> str:
        try:
            return self.evs.payloads.put(obj)
        except Exception:
            return "p:" + digest(obj)

    # ------------------------------------------------------------------ per-call duties
    def _accepted(self, run: Run) -> set[str]:
        """Values a qualifying sanitizer accepted in this run. A replacement PEP has no local record and
        rebuilds the set from the run's sanitize.result events (the accepted payload is evidence, 5.3)."""
        acc = self.sanitized.get(run.run_id)
        if acc is None:
            acc = set()
            for e in self._evidence(run):
                if e.get("type") != "sanitize.result":
                    continue
                s = self.registry.sanitizers.get(e.get("sanitizer", ""))
                if s is None or not s.qualifies_for_sanitized_provenance:
                    continue
                try:
                    payload = self.evs.payloads.get(e["accepted_ref"])
                except Exception:
                    continue
                if isinstance(payload, dict):
                    acc |= {digest(v) for v in payload.values()}
            self.sanitized[run.run_id] = acc
        return acc

    def _provenance(self, run: Run, node: Node, m: ToolManifest, params: dict[str, Any]) -> dict[str, str]:
        out: dict[str, str] = {}
        accepted = self._accepted(run)
        for p, v in params.items():
            if node.template_param == p and v in (run.release.scopes.get("templates") or []):
                out[p] = "template"
            elif digest(v) in accepted:
                out[p] = "sanitized"
            else:
                out[p] = "model"
        return out

    def _action_hash(self, m: ToolManifest, params: dict[str, Any], run: Run, node_id: str) -> str:
        return digest({"tool": m.tool_id, "version": m.version, "parameters": params, "run": run.run_id, "node": node_id})

    def _keys(self, run: Run, m: ToolManifest, params: dict[str, Any]) -> dict[str, str]:
        subj = run.subject or run.acting_user or run.agent_id
        keys = {"agent": run.agent_id, "subject": str(subj)}
        dp = m.destination_param()
        if dp and dp in params:
            keys["destination"] = str(params[dp])
        return keys

    def _request(self, run: Run, node: Node, m: ToolManifest, params: dict[str, Any], purpose: str, counters: dict[str, int],
                 approval_ref: dict[str, Any] | None = None, original_ref: dict[str, Any] | None = None,
                 preview_instructed: bool = False) -> DecisionRequest:
        factors = self.registry.derive_factors(m, params) if purpose in {"normal", "replay", "compensation"} and m.side_effect_class != "none" else set()
        state = run.run_state()
        return DecisionRequest(
            purpose=purpose, principal_chain=run.principal_chain, agent=run.agent_id, release=run.release, run=run.run_id,
            trace=run.trace_id, node=node, tool=m, parameters=params, provenance=self._provenance(run, node, m, params),
            action_hash=self._action_hash(m, params, run, node.id), subject=run.subject, run_state=state,
            counters=counters, factors=factors, stop_list_seq=self.stop_list.sequence if self.stop_list else 0,
            anchor_version=run.release.anchor_version, approval_ref=approval_ref, original_ref=original_ref,
            rehold_count=run.rehold_counts.get(self._action_hash(m, params, run, node.id), 0),
            destination_outside=self.registry.destination_outside(m, params), preview_instructed=preview_instructed)

    def _decide(self, rq: DecisionRequest, run: Run, counted_locally: bool = False) -> Decision:
        """Submit to the PDP; on a PDP outage, local evaluation of the cached bundle for what 6.1 allows."""
        try:
            return self.pdp.decide(rq)
        except Unavailable:
            return self._local_decide(rq, run, counted_locally)

    def _local_decide(self, rq: DecisionRequest, run: Run, counted_locally: bool = False) -> Decision:
        """Degraded mode against the PDP (6.1): scope-anchored no-factor effects on runs neither exposed
        nor delegated continue on the cached bundle until the stop list is stale; compensation and replay
        continue; everything else stops."""
        if self.bundle is None:
            raise Unavailable("PDP")
        if rq.purpose in {"compensation", "replay"}:
            pdp = PolicyDecisionPoint.__new__(PolicyDecisionPoint)
            pdp.registry, pdp.clock, pdp.trust, pdp.bundle, pdp.stop_list, pdp.pip = self.registry, self.clock, self.trust, self.bundle, self.stop_list, None
            pdp.decisions = []
            return pdp._decide_compensation(rq) if rq.purpose == "compensation" else pdp._decide_replay(rq)
        if self._stale():
            raise Unavailable("PDP")
        if rq.factors or run.exposed or run.acting_user is not None:
            raise Unavailable("PDP")
        if rq.tool.reads_data_class == "restricted":
            raise Unavailable("PDP")
        if not scope_only(rq.node.bounds):
            raise Unavailable("PDP")
        if rq.tool.tool_id not in rq.node.declared_tools():
            return Decision("DENY", "node_declaration", "undeclared tool")
        for b in rq.node.bounds:
            if b.form == "in_scope" and rq.parameters.get(b.param) not in (run.release.scopes.get(b.scope) or []):
                return Decision("DENY", "bounds", f"{b.param} not in scope")
            if b.form == "limit" and b.hard is not None and rq.parameters.get(b.param, 0) > b.hard:
                return Decision("DENY", "hard_limit", "above hard limit")
            if b.form == "limit" and b.auto is not None and rq.parameters.get(b.param, 0) > b.auto:
                raise Unavailable("PDP")   # a hold cannot be processed locally
        cap = self.bundle.values.degraded_caps.get("effects_per_pep", 10)
        if not counted_locally:
            self.local_counters["effects"] = self.local_counters.get("effects", 0) + 1
            if self.journal:
                self.journal.local_counters["effects"] = self.local_counters["effects"]
        if self.local_counters["effects"] > cap:
            return Decision("DENY", "degraded_cap", "degraded-mode cap reached")
        return Decision("ALLOW", "local_bundle", None, [], [], False, ["evidence_first"])

    def _decision_event(self, run: Run, node: Node, rq: DecisionRequest, d: Decision, reservation: str | None,
                        counters: dict[str, int], idem: str | None, approval_ref: str | None) -> str:
        ev = {"type": "decision", "node_id": node.id, "purpose": rq.purpose, "tool": rq.tool.tool_id, "version": rq.tool.version,
              "schema_hash": rq.tool.schema_hash, "parameters_ref": self._payload(rq.parameters), "parameters": rq.parameters,
              "parameter_roles": rq.tool.parameter_roles, "action_hash": rq.action_hash, "factors": sorted(rq.factors),
              "tier": node.tier, "decision": d.result, "rule_id": d.rule_id, "reason": d.reason, "obligations": d.obligations,
              "stop_list_seq": rq.stop_list_seq, "provenance": rq.provenance}
        if reservation:
            ev["reservation_id"] = reservation; ev["counters_snapshot"] = counters
            ev["reservation_keys"] = self._keys(run, rq.tool, rq.parameters)
        if idem:
            ev["idempotency_key"] = idem
        if approval_ref:
            ev["approval_ref"] = approval_ref
        eid = self._write(run, ev)
        self.last_decision_event[(run.run_id, node.id)] = eid
        return eid

    def _credential(self, run: Run, node: Node, m: ToolManifest, purpose: str, action_hash: str) -> dict[str, Any]:
        """A normal credential may be reused for the same audience within the same node (never on S4);
        compensation and replay credentials are per call."""
        key = (run.run_id, node.id, m.target_system)
        if purpose == "normal" and self.surface != "S4" and key in self.credential_cache:
            c = self.credential_cache[key]
            if c["payload"]["expires_at"] >= self.clock.now():
                return c
        release = {"agent_id": run.release.agent_id, "version": run.release.version, "surface": run.release.surface, "pep_form": run.release.pep_form}
        chain = run.principal_chain if run.service_identity is None else {"acting_user": run.acting_user, "agents": run.agents, "service": run.service_identity}
        cred = self.ids.issue_credential(self.workload, run.run_id, release, node.id, {"action_hash": action_hash}, chain, m.target_system, purpose)
        if purpose == "normal":
            self.credential_cache[key] = cred
        return cred

    def _apply_read_result(self, run: Run, node: Node, m: ToolManifest, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Taint and data class accounting, acknowledged at RUN before the result reaches the runtime."""
        us = self.registry.untrusted_source(m)
        tainted_items: list[str] = []
        exposed = False
        for i, it in enumerate(items):
            if us == "always":
                it["tainted"] = True
            elif us == "per_item" and "tainted" not in it:
                it["tainted"] = True   # untagged item from a per_item source
            elif us == "never":
                it["tainted"] = False
            if it.get("tainted"):
                exposed = True
                tainted_items.append(f"{m.tool_id}#{i}")
        delta = {"data_classes_touched": [m.reads_data_class], "tainted_reads": tainted_items, "exposed": exposed}
        self._update_state(run, delta)
        if exposed:
            self._write(run, {"type": "taint.applied", "source": m.tool_id, "items": tainted_items})
        return items

    def _update_state(self, run: Run, delta: dict[str, Any]) -> None:
        try:
            self.run.update_run_state(run, delta)
        except Unavailable:
            # under a RUN outage, in the journal, replayed to RUN before the run continues
            run.data_classes_touched |= set(delta.get("data_classes_touched", []))
            for t in delta.get("tainted_reads", []):
                run.tainted_reads.append(t)
            if delta.get("exposed"):
                run.exposed = True
            assert self.journal is not None
            self.journal.append({**run.header(), "type": "taint.applied", "source": "journaled-state", "items": list(delta.get("tainted_reads", []))})

    # ------------------------------------------------------------------ the call
    def call(self, run: Run, node: Node, tool_id: str, params: dict[str, Any], origin: str = "runtime") -> Any:
        """A runtime-originated call. Returns the result, raises Denied, Held, or NodeFailed."""
        if run.state != "RUNNING":
            raise Denied(f"run is {run.state}; a held or parked run makes no runtime-originated calls")
        if node.id not in run.entered and node.id not in self.local_entered.get(run.run_id, []):
            raise Denied("node_entered not confirmed")
        if node.id in run.in_doubt_cache:
            raise Denied("node in doubt")
        self.heartbeat(run)
        m = self.registry.get_tool_manifest(tool_id)
        # step cap for loop nodes
        c = self.step_counts.get((run.run_id, node.id), 0) + 1
        self.step_counts[(run.run_id, node.id)] = c
        if node.type == "loop" and ((node.step_cap is not None and c > node.step_cap) or (run.run_id, node.id) in self.capped_nodes):
            raise Denied("loop cap reached")
        if m.side_effect_class == "delivery":
            return self._deliver(run, node, m, params)
        if m.side_effect_class == "spawn":
            return self._spawn(run, node, m, params)
        if m.is_sanitizer:
            return self._sanitize(run, node, m, params)
        if m.side_effect_class in {"none", "internal_store"}:
            return self._read(run, node, m, params)
        return self._effect(run, node, m, params)

    def _read(self, run: Run, node: Node, m: ToolManifest, params: dict[str, Any]) -> Any:
        if m.reads_data_class == "restricted" and self._stopped(run, m.tool_id):
            raise Denied("restricted read refused under a stop")
        rq = self._request(run, node, m, params, "normal", {})
        d = self._decide(rq, run)
        self._decision_event(run, node, rq, d, None, {}, None, None)
        if d.result != "ALLOW":
            if node.type == "read":
                self._denied(run, node)
            raise Denied(d.reason or "read denied")
        system = self.systems[m.target_system]
        if m.side_effect_class == "internal_store":
            tag = "exposed" if run.exposed else "clean"
            return system.execute(m.tool_id, params, None, self.workload, tag=tag)
        items = system.read(m.tool_id, params)
        return self._apply_read_result(run, node, m, items)

    def _sanitize(self, run: Run, node: Node, m: ToolManifest, params: dict[str, Any]) -> dict[str, Any]:
        if node.type != "sanitize":
            raise Denied("only a sanitize node may call a sanitizer")
        s = self.registry.sanitizers[m.tool_id]
        rq = self._request(run, node, m, params, "normal", {})
        d = self._decide(rq, run)
        self._decision_event(run, node, rq, d, None, {}, None, None)
        if d.result != "ALLOW":
            raise Denied(d.reason or "sanitizer denied")
        accepted, rejected = s.fn(params)
        self._write(run, {"type": "sanitize.result", "node_id": node.id, "sanitizer": s.sanitizer_id, "version": s.version,
                          "accepted_ref": self._payload(accepted), "rejected_ref": self._payload(rejected)})
        if s.qualifies_for_sanitized_provenance:
            bucket = self.sanitized.setdefault(run.run_id, set())
            for v in accepted.values():
                bucket.add(digest(v))
        return accepted

    def _effect(self, run: Run, node: Node, m: ToolManifest, params: dict[str, Any], approval_ref: dict[str, Any] | None = None,
                grant: str | None = None) -> Any:
        if node.type != "effect":
            raise Denied("effects are made only by effect nodes")
        if self._stopped(run, m.tool_id):
            raise Denied("effect refused: stop in scope or stop list stale")
        keys = self._keys(run, m, params)
        counters: dict[str, int] = {}
        reservation: str | None = None
        counted_locally = False
        try:
            reservation, counters = self.run.reserve(keys, COUNTER_WINDOW)
        except Unavailable:
            if self.form == "proxy":
                raise
            # RUN down: PEP-E local counters with the degraded cap (6.1)
            counted_locally = True
            self.local_counters["effects"] = self.local_counters.get("effects", 0) + 1
            counters = {k: self.local_counters["effects"] for k in keys}
            if self.journal:
                self.journal.local_counters["effects"] = self.local_counters["effects"]
        rq = self._request(run, node, m, params, "normal", counters, approval_ref=approval_ref)
        if counted_locally and self.bundle and self.local_counters["effects"] > self.bundle.values.degraded_caps.get("effects_per_pep", 10):
            d = Decision("DENY", "degraded_cap", "degraded-mode cap reached")
        else:
            d = self._decide(rq, run, counted_locally)
        if d.result == "DENY":
            self._decision_event(run, node, rq, d, reservation, counters, None, approval_ref and approval_ref["payload"]["approval_ref"])
            if reservation:
                self.run.release(reservation)
            if approval_ref is not None:
                self.run.approved_action_used(run, node.id, "denied")
            self._denied(run, node)
            raise Denied(d.reason or "denied")
        if d.result == "HOLD":
            self._decision_event(run, node, rq, d, reservation, counters, None, approval_ref and approval_ref["payload"]["approval_ref"])
            if reservation:
                self.run.release(reservation)
            pending = {"tool": m.tool_id, "parameters": params, "factors": rq.factors, "counters": counters, "provenance": rq.provenance}
            self.pending[(run.run_id, node.id)] = PendingEffect(node.id, m, params, rq.provenance, rq.action_hash, rq.factors, keys)
            if approval_ref is not None:
                self.run.rehold(run, node, d, pending, rq.action_hash)
            else:
                self.run.hold(run, node, d, pending, rq.action_hash)
            raise Held(node.id)
        # ALLOW: evidence first, then credential, then execute
        idem = digest({"idem": rq.action_hash})
        eid = self._decision_event(run, node, rq, d, reservation, counters, idem, approval_ref and approval_ref["payload"]["approval_ref"])
        return self._execute(run, node, m, params, rq, d, reservation, idem, eid, approval_ref, grant)

    def _execute(self, run: Run, node: Node, m: ToolManifest, params: dict[str, Any], rq: DecisionRequest, d: Decision,
                 reservation: str | None, idem: str, decision_event: str, approval_ref: dict[str, Any] | None, grant: str | None) -> Any:
        system = self.systems[m.target_system]
        presentation = self.registry.systems[m.target_system].presentation
        # obligations before anything is sent
        if "dlp_check" in d.obligations and not self.dlp.check(params):
            self._write(run, {"type": "effect.failed", "node_id": node.id, "purpose": "normal", "credential_presentation": presentation,
                              "error": "dlp", "recorded_by": "pep", "action_hash": rq.action_hash})
            if reservation:
                self.run.release(reservation)
            self.run.approved_action_used(run, node.id, "failed")
            self._failed(run, node)
            raise NodeFailed("blocked by dlp_check")
        tag = "exposed" if ("apply_provenance_tag" in d.obligations and run.exposed) else None
        # credential
        try:
            if approval_ref is not None:
                cred = self._resume_credential(run, node, m, rq, approval_ref, grant)
            else:
                cred = self._credential(run, node, m, "normal", rq.action_hash)
        except Refused as e:
            if "revoked" in str(e) or (approval_ref is not None):
                return self._revoked_at_redemption(run, node, m, params, rq, reservation, presentation)
            # any other IDS refusal (identity lapsed, workload unbound, form mismatch): no credential, no call
            self._write(run, {"type": "effect.failed", "node_id": node.id, "purpose": "normal", "credential_presentation": presentation,
                              "error": "revoked", "detail": str(e), "recorded_by": "pep", "action_hash": rq.action_hash})
            if reservation:
                self.run.release(reservation)
            self.run.approved_action_used(run, node.id, "failed")
            self._failed(run, node)
            raise NodeFailed(f"credential refused: {e}")
        except Unavailable:
            if reservation:
                self.run.release(reservation)
            raise
        if cred is None:
            return self._revoked_at_redemption(run, node, m, params, rq, reservation, presentation)
        try:
            result = system.execute(m.tool_id, params, cred, self.workload, "normal", rq.action_hash, idem, tag)
        except SystemRefused as e:
            self._write(run, {"type": "effect.failed", "node_id": node.id, "purpose": "normal", "credential_presentation": presentation,
                              "error": "system_error", "recorded_by": "pep", "action_hash": rq.action_hash})
            if reservation:
                self.run.release(reservation)
            self.run.approved_action_used(run, node.id, "failed")
            self._failed(run, node)
            raise NodeFailed(str(e))
        except Indeterminate as e:
            self._write(run, {"type": "effect.indeterminate", "node_id": node.id, "purpose": "normal", "credential_presentation": presentation,
                              "last_known": str(e), "recorded_by": "pep", "action_hash": rq.action_hash})
            run.in_doubt_cache.add(node.id)
            raise
        self._write(run, {"type": "effect.executed", "node_id": node.id, "purpose": "normal", "credential_presentation": presentation,
                          "result_ref": self._payload(result), "idempotency_key": idem, "recorded_by": "pep", "action_hash": rq.action_hash})
        if reservation:
            self.run.confirm(reservation)
        mapping = m.compensation if isinstance(m.compensation, dict) else {}
        result_fields = {ref.split(".", 1)[1]: result.get(ref.split(".", 1)[1]) for ref in mapping.get("params", {}).values() if ref.startswith("result.")}
        self.run.effect_confirmed(run, EffectRecord(node.id, rq.action_hash, decision_event, params, result_fields, self._payload(result), [], m.tool_id))
        self.run.approved_action_used(run, node.id, "executed")
        self._update_state(run, {"data_classes_touched": [m.writes_data_class]})
        self.pending.pop((run.run_id, node.id), None)
        return result

    def _revoked_at_redemption(self, run: Run, node: Node, m: ToolManifest, params: dict[str, Any], rq: DecisionRequest,
                               reservation: str | None, presentation: str) -> Any:
        """IDS found the delegation revoked only at redemption: effect.failed (revoked), not in doubt, and a
        new hold with cause substitution_required where policy permits, else denial."""
        self._write(run, {"type": "effect.failed", "node_id": node.id, "purpose": "normal", "credential_presentation": presentation,
                          "error": "revoked", "recorded_by": "pep", "action_hash": rq.action_hash})
        if reservation:
            self.run.release(reservation)
        self.run.approved_action_used(run, node.id, "revoked")
        if self.bundle and self.bundle.values.substitution_permitted and not any(b.anchor == "acting_user" for b in node.bounds):
            pending = {"tool": m.tool_id, "parameters": params, "factors": rq.factors, "counters": {}, "provenance": rq.provenance}
            self.pending[(run.run_id, node.id)] = PendingEffect(node.id, m, params, rq.provenance, rq.action_hash, rq.factors, self._keys(run, m, params))
            self.run.substitution_hold(run, node, pending, rq.action_hash)
            raise Held(node.id)
        self._denied(run, node)
        raise Denied("delegation revoked and substitution not permitted")

    def _resume_credential(self, run: Run, node: Node, m: ToolManifest, rq: DecisionRequest, approval_ref: dict[str, Any], grant: str | None) -> dict[str, Any] | None:
        h = run.holds[node.id]
        assertion = self.run.status_assertion(run, h)
        if approval_ref["payload"]["kind"] == "grant" and grant:
            res = self.ids.redeem_resumption_grant(self.workload, grant, approval_ref, assertion)
            if res["status"] == "ok":
                self._write(run, {"type": "grant.redeemed", "grant_id": res["grant_id"], "action_hash": rq.action_hash, "presenter_workload": self.workload})
                return res["credential"]
            if res["status"] == "revoked":
                return None
            raise Refused(f"grant redemption failed: {res.get('reason')}")
        res = self.ids.credential_for_approved_action(self.workload, approval_ref, assertion)
        if res["status"] == "ok":
            self._write(run, {"type": "approved_action.used", "approval_ref": approval_ref["payload"]["approval_ref"], "action_hash": rq.action_hash, "presenter_workload": self.workload})
            return res["credential"]
        raise Refused(f"approved-action credential refused: {res.get('reason')}")

    def _denied(self, run: Run, node: Node) -> None:
        try:
            self.run._follow_branch(run, node.id, "denial")
        except Unavailable:
            run.next_node = node.denial_branch

    def _failed(self, run: Run, node: Node) -> None:
        try:
            self.run._follow_branch(run, node.id, "failure")
        except Unavailable:
            run.next_node = node.failure_branch or node.denial_branch

    # ------------------------------------------------------------------ deliveries and spawns
    def _deliver(self, run: Run, node: Node, m: ToolManifest, params: dict[str, Any]) -> Any:
        if node.type != "output":
            raise Denied("deliveries are made only by output nodes")
        if self._stopped(run, m.tool_id):
            raise Denied("delivery refused under a stop")
        rq = self._request(run, node, m, params, "delivery", {})
        d = self._decide(rq, run)
        self._decision_event(run, node, rq, d, None, {}, None, None)
        sink = params.get("sink") or params.get("recipient")
        if d.result != "ALLOW":
            self._write(run, {"type": "delivery.failed", "node_id": node.id, "sink": sink, "sanitizer_applied": False, "error": d.reason or "denied"})
            self._denied(run, node)
            raise Denied(d.reason or "delivery denied")
        content = params
        sanitized = False
        if "require_sanitizer" in d.obligations:
            s = next(x for x in self.registry.sanitizers.values() if x.rendering)
            acc, rej = s.fn({"content": params.get("content", "")})
            content = {**params, "content": acc["content"]}
            sanitized = True
            self._write(run, {"type": "sanitize.result", "node_id": node.id, "sanitizer": s.sanitizer_id, "version": s.version,
                              "accepted_ref": self._payload(acc), "rejected_ref": self._payload(rej)})
        tag = "exposed" if run.exposed else "clean"
        res = self.systems[m.target_system].execute(m.tool_id, content, None, self.workload, "delivery", tag=tag if "apply_provenance_tag" in d.obligations else None)
        self._write(run, {"type": "delivery.executed", "node_id": node.id, "sink": sink, "sanitizer_applied": sanitized, "result_ref": self._payload(res)})
        return res

    def _spawn(self, run: Run, node: Node, m: ToolManifest, params: dict[str, Any]) -> Any:
        if node.type not in {"handoff", "service"}:
            raise Denied("spawns are made only by handoff and service nodes")
        if self._stopped(run, m.tool_id):
            raise Denied("spawn refused under a stop")
        rq = self._request(run, node, m, params, "spawn", {})
        d = self._decide(rq, run)
        self._decision_event(run, node, rq, d, None, {}, None, None)
        if d.result != "ALLOW":
            self._denied(run, node)
            raise Denied(d.reason or "spawn denied")
        child = self.run.spawn(run, node, params)
        # synchronous: the child's final exposure comes back and the parent's PEP applies the taint
        if child.exposed:
            self._update_state(run, {"exposed": True, "tainted_reads": [f"child:{child.run_id}"]})
            self._write(run, {"type": "taint.applied", "source": f"child:{child.run_id}", "items": [node.id]})
        return {"child_run": child.run_id, "state": child.state, "outputs": child.outputs, "exposed": child.exposed}

    # ------------------------------------------------------------------ model calls
    def model_call(self, run: Run, node: Node, model: str, prompt: str, tokens: int = 100) -> str:
        if self.mgw is None:
            raise Denied("no model gateway")
        if (run.run_id, node.id) in self.capped_nodes:
            raise Denied("cap_reached: the PEP refuses the node's next model credential")
        release = {"agent_id": run.release.agent_id, "version": run.release.version, "surface": run.release.surface, "pep_form": run.release.pep_form}
        try:
            cred = self.ids.issue_credential(self.workload, run.run_id, release, node.id, {}, run.principal_chain, "MGW", "model")
        except Refused as e:
            self.cap_reached(run, node.id)      # no model credential: the node makes no further model calls
            raise Denied(f"model credential refused: {e}")
        text, cap = self.mgw.complete(cred, self.workload, run, node.id, model, prompt, tokens)
        if cap:
            self.cap_reached(run, node.id)
        return text

    def cap_reached(self, run: Run, node_id: str) -> None:
        self.capped_nodes.add((run.run_id, node_id))

    # ------------------------------------------------------------------ RUN-originated instructions
    def instruct(self, run: Run, node_id: str, purpose: str, **kw: Any) -> dict[str, Any]:
        """instruct(run, node, purpose ∈ {preview, compensation, replay, resume}, original_ref?, approval_ref?, grant?)."""
        self.instructions.append({"run": run.run_id, "node": node_id, "purpose": purpose})
        node = run.release.node(node_id)
        if purpose == "preview":
            return self._preview(run, node, kw["parameters"])
        if purpose == "resume":
            return self._resume(run, node, kw["approval_ref"], kw.get("grant"))
        if purpose == "compensation":
            return self._compensate(run, node, kw["original_node"])
        if purpose == "replay":
            return self._replay(run, node)
        raise Denied("unknown instruction")

    def cancel_pending(self, run: Run, node_id: str) -> None:
        """An effect not yet executed is cancelled by a stop; effect.failed (stopped), so it is not in doubt."""
        p = self.pending.pop((run.run_id, node_id), None)
        presentation = self.registry.systems[p.tool.target_system].presentation if p else "per_agent"
        self._write(run, {"type": "effect.failed", "node_id": node_id, "purpose": "normal", "credential_presentation": presentation,
                          "error": "stopped", "recorded_by": "pep", "action_hash": p.action_hash if p else ""})
        if p and p.reservation:
            self.run.release(p.reservation)

    def release_pending(self, run: Run, node_id: str) -> None:
        self.pending.pop((run.run_id, node_id), None)

    def _preview(self, run: Run, node: Node, params: dict[str, Any]) -> dict[str, Any]:
        m = self.registry.tools[node.tool]
        sysc = self.registry.systems[m.target_system]
        pt = self.registry.tools[sysc.preview_tool]
        rq = self._request(run, node, pt, params, "preview", {}, preview_instructed=True)
        d = self._decide(rq, run)
        self._decision_event(run, node, rq, d, None, {}, None, None)
        if d.result != "ALLOW":
            raise Denied(d.reason or "preview denied")
        res = self.systems[m.target_system].preview(params)
        self._apply_read_result(run, node, pt, [res])
        return {"result_ref": self._payload(res), "result": res}

    def _resume(self, run: Run, node: Node, approval_ref: dict[str, Any], grant: str | None) -> dict[str, Any]:
        """On resume the PEP re-reserves counters and resubmits the same action hash with approval_ref."""
        p = self.pending.get((run.run_id, node.id))
        if p is None:
            h = run.holds[node.id]
            p = PendingEffect(node.id, self.registry.tools[h.pending["tool"]], h.pending["parameters"], h.pending.get("provenance", {}),
                              h.action_hash, set(h.pending.get("factors", [])), {})
            self.pending[(run.run_id, node.id)] = p
        if run.state != "RUNNING":
            raise Denied("resume on a run that is not RUNNING")
        try:
            result = self._effect(run, node, p.tool, p.parameters, approval_ref=approval_ref, grant=grant)
        except Held:
            return {"status": "held_again"}
        except Denied as e:
            return {"status": "denied", "reason": str(e)}
        except NodeFailed as e:
            return {"status": "failed", "reason": str(e)}
        except Indeterminate:
            return {"status": "indeterminate"}
        run.outputs[node.id] = result
        self.exit_node(run, node, result)
        return {"status": "executed", "result": result}

    def _original_ref(self, run: Run, node_id: str) -> dict[str, Any] | None:
        """The recorded original: from EVS, from the journal, or from RUN's signed checkpoint copy."""
        evs = self._evidence(run)
        decisions = [e for e in evs if e["type"] == "decision" and e["node_id"] == node_id and e["purpose"] == "normal"]
        if decisions and self.evs.available:
            dec = decisions[-1]
            effects = [e for e in evs if e["type"].startswith("effect.") and e.get("action_hash") == dec["action_hash"]]
            holds = [e for e in evs if e["type"] == "hold.resolved" and e["node_id"] == node_id and e.get("timestamp", 0) > dec.get("timestamp", 0)]
            result = None
            for r in run.effects:
                if r.node_id == node_id:
                    result = r.result_fields
            return {"verified": self.evs.event_verifies(dec["event_id"]), "parameters": dec.get("parameters", {}), "result": result or {},
                    "decision": dec["decision"], "action_hash": dec["action_hash"], "idempotency_key": dec.get("idempotency_key"),
                    "effect_events": [e["type"] for e in effects], "later_hold_outcomes": [h["outcome"] for h in holds]}
        copy = self.run.signed_effect_copy(run, node_id)
        if copy and self.trust.verify(copy, role="run"):
            c = copy["payload"]
            return {"verified": True, "parameters": c["parameters"], "result": c["result"], "decision": "ALLOW",
                    "action_hash": c["action_hash"], "idempotency_key": digest({"idem": c["action_hash"]}), "effect_events": ["effect.executed"], "later_hold_outcomes": []}
        if self.journal:
            for e in self.journal.events():
                if e["type"] == "decision" and e["node_id"] == node_id and e.get("run_id") == run.run_id:
                    return {"verified": self.journal.entry_verifies(e["event_id"], self.trust), "parameters": e.get("parameters", {}), "result": {},
                            "decision": e["decision"], "action_hash": e["action_hash"], "idempotency_key": e.get("idempotency_key"),
                            "effect_events": [x["type"] for x in self.journal.events() if x["type"].startswith("effect.") and x.get("action_hash") == e["action_hash"]],
                            "later_hold_outcomes": []}
        return None

    def _compensate(self, run: Run, cnode: Node, original_node: str) -> dict[str, Any]:
        """A compensate node is a deterministic call with no runtime loop and no model: parameters from the
        manifest mapping over the recorded original call."""
        orig_tool = self.registry.tools[run.release.node(original_node).tool]
        rev = self.registry.tools[cnode.tool]
        mapping = orig_tool.compensation if isinstance(orig_tool.compensation, dict) else None
        original = self._original_ref(run, original_node)
        if mapping is None or original is None:
            return {"status": "failed", "reason": "no mapping or no record"}
        params = apply_mapping(mapping, original["parameters"], original["result"])
        rq = self._request(run, cnode, rev, params, "compensation", {}, original_ref=original)
        d = self._decide(rq, run)
        self._decision_event(run, cnode, rq, d, None, {}, None, None)
        if d.result != "ALLOW":
            return {"status": "denied", "reason": d.reason}
        presentation = self.registry.systems[rev.target_system].presentation
        try:
            cred = self._credential(run, cnode, rev, "compensation", original["action_hash"])
            res = self.systems[rev.target_system].execute(rev.tool_id, params, cred, self.workload, "compensation", original["action_hash"])
        except (SystemRefused, Refused, Unavailable) as e:
            self._write(run, {"type": "effect.failed", "node_id": cnode.id, "purpose": "compensation", "credential_presentation": presentation,
                              "error": "system_error", "recorded_by": "pep", "action_hash": original["action_hash"]})
            return {"status": "failed", "reason": str(e)}
        except Indeterminate as e:
            self._write(run, {"type": "effect.indeterminate", "node_id": cnode.id, "purpose": "compensation", "credential_presentation": presentation,
                              "last_known": str(e), "recorded_by": "pep", "action_hash": original["action_hash"]})
            return {"status": "indeterminate"}
        self._write(run, {"type": "effect.executed", "node_id": cnode.id, "purpose": "compensation", "credential_presentation": presentation,
                          "result_ref": self._payload(res), "recorded_by": "pep", "action_hash": original["action_hash"]})
        return {"status": "executed", "result": res}

    def _replay(self, run: Run, node: Node) -> dict[str, Any]:
        m = self.registry.tools[node.tool]
        original = self._original_ref(run, node.id)
        if original is None:
            return {"status": "denied", "reason": "no record"}
        params = dict(original["parameters"])
        rq = self._request(run, node, m, {**params, "__idempotency_key__": original["idempotency_key"]}, "replay", {}, original_ref=original)
        rq.action_hash = original["action_hash"]
        d = self._decide(rq, run)
        self._decision_event(run, node, rq, d, None, {}, original["idempotency_key"], None)
        if d.result != "ALLOW":
            return {"status": "denied", "reason": d.reason}
        presentation = self.registry.systems[m.target_system].presentation
        try:
            cred = self._credential(run, node, m, "replay", original["action_hash"])
            res = self.systems[m.target_system].execute(m.tool_id, params, cred, self.workload, "replay", original["action_hash"], original["idempotency_key"])
        except (SystemRefused, Refused, Unavailable) as e:
            self._write(run, {"type": "effect.failed", "node_id": node.id, "purpose": "replay", "credential_presentation": presentation,
                              "error": "system_error", "recorded_by": "pep", "action_hash": original["action_hash"]})
            return {"status": "failed", "reason": str(e)}
        except Indeterminate as e:
            self._write(run, {"type": "effect.indeterminate", "node_id": node.id, "purpose": "replay", "credential_presentation": presentation,
                              "last_known": str(e), "recorded_by": "pep", "action_hash": original["action_hash"]})
            return {"status": "indeterminate"}
        self._write(run, {"type": "effect.executed", "node_id": node.id, "purpose": "replay", "credential_presentation": presentation,
                          "result_ref": self._payload(res), "idempotency_key": original["idempotency_key"], "recorded_by": "pep", "action_hash": original["action_hash"]})
        mapping = m.compensation if isinstance(m.compensation, dict) else {}
        result_fields = {ref.split(".", 1)[1]: res.get(ref.split(".", 1)[1]) for ref in mapping.get("params", {}).values() if ref.startswith("result.")}
        self.run.effect_confirmed(run, EffectRecord(node.id, original["action_hash"], "", params, result_fields, self._payload(res), [], m.tool_id))
        self.run.reconcile_counters()
        return {"status": "executed", "outputs": res}
