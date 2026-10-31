"""PDP, the Policy Decision Point (spec A.3), the signed policy bundle, the stop list, and the PIP
protocol.

The PDP holds no run state. It evaluates a decision request in a fixed order against the signed
bundle and returns ALLOW, DENY(reason), or HOLD(hold_causes, approver_set, substitution_allowed), with
obligations. The first DENY is final; a HOLD is final only if no later rule denies."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .common import Unavailable, Availability, Clock, Denied, Record
from .crypto import Signer, TrustStore
from .registry import PolicyValues, Registry, ToolManifest
from .release import Node, Release, anchored_params

DATA_ORDER = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


class Tainted(Exception):
    """The PIP refuses to answer an anchor relation from a tainted field (4.3)."""


class PIP(Protocol):
    def relation(self, rel: str, value: Any) -> Any: ...
    def predicate(self, rel: str, value: Any) -> bool: ...
    def entitled(self, user: str, system: str, resource: Any) -> bool: ...


@dataclass
class PolicyBundle(Record):
    version: str
    values: PolicyValues
    entitlements: dict[str, dict[str, list[str]]]     # principal -> {tools: [...], systems: [...], agents: [...]}
    recipient_clearance: dict[str, str] = field(default_factory=dict)   # recipient role -> max data class
    default_approvers: list[str] = field(default_factory=lambda: ["approver-1"])
    second_approvers: list[str] = field(default_factory=lambda: ["approver-2"])
    exposed_velocity_factor: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "values": self.values.to_dict(), "entitlements": self.entitlements,
                "recipient_clearance": self.recipient_clearance}


@dataclass
class Stop(Record):
    stop_id: str
    scope_kind: str          # agent | tool | surface | fleet
    scope_value: str | None
    sequence: int


@dataclass
class StopList(Record):
    sequence: int
    issued_at: float
    validity: float
    stops: list[Stop]

    def in_scope(self, agent_id: str, tool_id: str | None, surface: str) -> Stop | None:
        for s in self.stops:
            if s.scope_kind == "fleet":
                return s
            if s.scope_kind == "agent" and s.scope_value == agent_id:
                return s
            if s.scope_kind == "tool" and tool_id is not None and s.scope_value == tool_id:
                return s
            if s.scope_kind == "surface" and s.scope_value == surface:
                return s
        return None


@dataclass
class DecisionRequest(Record):
    purpose: str                               # normal | compensation | replay | delivery | spawn | preview
    principal_chain: dict[str, Any]            # {acting_user, agents: [...]}
    agent: str
    release: Release
    run: str
    trace: str
    node: Node
    tool: ToolManifest
    parameters: dict[str, Any]
    provenance: dict[str, str]                 # parameter -> template | sanitized | model
    action_hash: str
    subject: str | None
    run_state: dict[str, Any]                  # data_classes_touched, exposed, tainted_reads, step_count, spend_to_date
    counters: dict[str, int]                   # post-reservation counts: agent, subject, destination
    factors: set[str]
    stop_list_seq: int
    anchor_version: int | None
    approval_ref: dict[str, Any] | None = None  # RUN-signed approval record with causes_discharged
    original_ref: dict[str, Any] | None = None  # for compensation / replay
    rehold_count: int = 0
    destination_outside: bool = False
    preview_instructed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"purpose": self.purpose, "agent": self.agent, "run": self.run, "node": self.node.id,
                "tool": self.tool.tool_id, "action_hash": self.action_hash, "factors": sorted(self.factors)}


@dataclass
class Decision(Record):
    result: str                                # ALLOW | DENY | HOLD
    rule_id: str
    reason: str | None = None
    hold_causes: list[str] = field(default_factory=list)
    approver_set: list[str] = field(default_factory=list)
    substitution_allowed: bool = False
    obligations: list[str] = field(default_factory=list)
    approvers_required: int = 1


class PolicyDecisionPoint(Availability):
    name = "PDP"

    def __init__(self, registry: Registry, clock: Clock, trust: TrustStore, authority: Signer) -> None:
        self.registry = registry
        self.clock = clock
        self.trust = trust
        self.authority = authority
        trust.trust(authority, "policy_authority")
        self.bundle: PolicyBundle | None = None
        self.signed_bundle: dict[str, Any] | None = None
        self.stop_list: StopList | None = None
        self.signed_stop_list: dict[str, Any] | None = None
        self.pip: PIP | None = None
        self.decisions: list[tuple[DecisionRequest, Decision]] = []

    # ------------------------------------------------------------------ bundle and stop list
    def publish_bundle(self, bundle: PolicyBundle) -> dict[str, Any]:
        self.bundle = bundle
        self.signed_bundle = self.authority.sign(bundle.to_dict())
        self.registry.on_bundle_published(bundle.values)
        return self.signed_bundle

    def distribute_stop_list(self, signed: dict[str, Any], stop_list: StopList) -> None:
        """OPS signs; the PDP distributes on the policy-bundle channel (A.9, 4.9)."""
        if not self.trust.verify(signed, role="ops"):
            raise Denied("stop list signature")
        self.stop_list = stop_list
        self.signed_stop_list = signed

    @property
    def values(self) -> PolicyValues:
        assert self.bundle is not None
        return self.bundle.values

    # ------------------------------------------------------------------ evaluation
    def decide(self, rq: DecisionRequest) -> Decision:
        self._check()
        d = self._decide(rq)
        self.decisions.append((rq, d))
        return d

    def _decide(self, rq: DecisionRequest) -> Decision:
        assert self.bundle is not None
        v = self.values
        node, m = rq.node, rq.tool
        holds: list[str] = []
        obligations = ["evidence_first"]
        discharged = set((rq.approval_ref or {}).get("payload", {}).get("causes_discharged", [])) if rq.approval_ref else set()

        def hold(cause: str) -> None:
            if cause not in discharged and cause not in holds:
                holds.append(cause)

        # 1. node declaration
        preview_tool = self.registry.systems.get(self.registry.tools[node.tool].target_system).preview_tool if node.tool in self.registry.tools and self.registry.tools[node.tool].target_system in self.registry.systems else None
        declared = node.declared_tools()
        if rq.purpose == "preview":
            if not (rq.preview_instructed and m.tool_id == preview_tool):
                return Decision("DENY", "node_declaration", "preview tool not instructed by RUN")
        elif rq.purpose == "compensation":
            if node.type != "compensate" or m.tool_id != node.tool:
                return Decision("DENY", "node_declaration", "compensation must run on the compensate node's mapped tool")
        elif m.tool_id not in declared:
            return Decision("DENY", "node_declaration", f"node {node.id} does not declare tool {m.tool_id}")
        # 2. tier guard
        if node.type == "effect" and node.tier == "A3" and rq.factors and rq.purpose == "normal":
            hold("factor_at_runtime")
        # 3. stop scope
        if rq.purpose not in {"compensation", "replay"}:
            stop = self._stop_in_scope(rq)
            is_effect = node.type == "effect" and rq.purpose == "normal"
            restricted_read = m.reads_data_class == "restricted" and rq.purpose in {"normal", "preview"} and node.type in {"read", "loop", "effect"}
            if stop and (is_effect or rq.purpose in {"delivery", "spawn"} or restricted_read):
                return Decision("DENY", "stop_scope", f"stop {stop.stop_id} in scope")
            if self._stop_list_stale() and (is_effect or rq.purpose in {"delivery", "spawn"} or restricted_read):
                return Decision("DENY", "stop_scope", "stop list stale")
        # 4. hard limits (normal effects)
        limit = next((b for b in node.bounds if b.form == "limit"), None)
        amount = rq.parameters.get(limit.param) if limit else None
        if rq.purpose == "normal" and node.type == "effect" and limit and limit.hard is not None and amount is not None and amount > limit.hard:
            return Decision("DENY", "hard_limit", f"{limit.param} above the hard limit")
        # 5. compensation: terminal
        if rq.purpose == "compensation":
            return self._decide_compensation(rq)
        # 6. replay: terminal
        if rq.purpose == "replay":
            return self._decide_replay(rq)
        # 7. anchor version, suspension, denied effects
        if rq.release.suspended:
            return Decision("DENY", "release_suspended", "release suspended by REG")
        if node.id in rq.release.denied_effects:
            return Decision("DENY", "no_resumption_path", "held effects of this node resolve by denial until republished")
        if rq.anchor_version is not None and not self.registry.anchors_still_capable(rq.release):
            return Decision("DENY", "anchor_version", "an anchor relation is no longer capable")
        # intersection (I2)
        reason = self._intersection(rq)
        if reason:
            return Decision("DENY", "intersection", reason)
        # bounds (never a hold cause)
        reason = self._bounds(rq)
        if reason:
            return Decision("DENY", "bounds", reason)
        # counters
        if node.type == "effect" and rq.purpose == "normal":
            for key, count in rq.counters.items():
                cfg = v.velocity.get(key)
                if not cfg:
                    continue
                lim = cfg.get("limit")
                if rq.run_state.get("exposed"):
                    lim = int(lim * self.bundle.exposed_velocity_factor) if lim else lim
                if cfg.get("hard_cap") is not None and count > cfg["hard_cap"]:
                    return Decision("DENY", "velocity_hard_cap", f"hard velocity cap for {key}")
                if lim is not None and count > lim:
                    hold(f"velocity:{key}")
        # limits band, tier A1
        if node.type == "effect" and rq.purpose == "normal":
            if limit and amount is not None and limit.auto is not None and amount > limit.auto:
                hold("limit_band")
            if node.tier == "A1":
                hold("tier_a1")
        # pack: exposure rule
        if rq.purpose == "normal" and node.type == "effect":
            if rq.destination_outside:
                obligations.append("dlp_check")
                if rq.run_state.get("exposed"):
                    anchored = anchored_params(node.bounds, rq.release.scope_names())
                    dp = m.destination_param()
                    dest_ok = (dp in anchored) if dp else True
                    content = [p for p in rq.parameters if p not in m.parameter_roles]
                    prov_ok = all(rq.provenance.get(p) in {"template", "sanitized"} for p in content)
                    if not (dest_ok and prov_ok):
                        hold("exposure")
            if rq.run_state.get("exposed") and self.registry.provenance_tag(m.target_system):
                obligations.append("apply_provenance_tag")
        if rq.purpose == "normal" and m.side_effect_class == "internal_store":
            obligations.append("apply_provenance_tag")
        # delivery
        if rq.purpose == "delivery":
            obligations.append("apply_provenance_tag")
            if rq.run_state.get("exposed"):
                obligations.append("require_sanitizer")
            target = self.registry.systems[m.target_system]
            if target.kind == "interface":
                recipient = rq.parameters.get("recipient")
                clearance = self.bundle.recipient_clearance.get(str(recipient), "internal")
                if recipient != rq.principal_chain.get("acting_user"):
                    for dc in rq.run_state.get("data_classes_touched", []):
                        if DATA_ORDER.get(dc, 0) > DATA_ORDER[clearance]:
                            return Decision("DENY", "delivery_recipient", f"recipient {recipient} not cleared for {dc}")
        # resume bookkeeping: re-hold maximum
        if holds:
            if rq.rehold_count >= v.rehold_maximum:
                return Decision("DENY", "rehold_maximum", "re-hold maximum reached")
            approvers, n = self._approver_set(rq, amount)
            obligations.append("redact_for_approver")
            return Decision("HOLD", "hold", None, holds, approvers, v.substitution_permitted, obligations, n)
        return Decision("ALLOW", "allow", None, [], [], False, obligations)

    # ------------------------------------------------------------------ rule helpers
    def _stop_in_scope(self, rq: DecisionRequest) -> Stop | None:
        if self.stop_list is None:
            return None
        return self.stop_list.in_scope(rq.agent, rq.tool.tool_id, rq.release.surface)

    def _stop_list_stale(self) -> bool:
        if self.stop_list is None:
            return False
        return self.clock.now() > self.stop_list.issued_at + self.stop_list.validity

    def _intersection(self, rq: DecisionRequest) -> str | None:
        """Once per principal in the chain; allow only if every evaluation allows. Agent entitlements
        come from the bundle; the acting user's resource entitlement comes from the PIP for per_agent
        presentation. The subject is not evaluated."""
        assert self.bundle is not None
        tool = rq.tool
        for agent in rq.principal_chain.get("agents", []):
            ent = self.bundle.entitlements.get(agent, {})
            if rq.purpose == "spawn":
                if tool.tool_id not in ent.get("agents", []):
                    return f"{agent} may not invoke {tool.tool_id}"
                continue
            if tool.tool_id not in ent.get("tools", []):
                return f"{agent} not entitled to tool {tool.tool_id}"
            if tool.target_system in self.registry.systems and tool.target_system not in ent.get("systems", []):
                return f"{agent} not entitled to system {tool.target_system}"
        acting = rq.principal_chain.get("acting_user")
        if acting and rq.purpose != "spawn":
            sysc = self.registry.systems.get(tool.target_system)
            rp = tool.resource_param()
            if sysc and sysc.presentation == "per_agent" and rp and rp in rq.parameters:
                if self.pip is None or not self.pip.entitled(acting, tool.target_system, rq.parameters[rp]):
                    return f"acting user {acting} not entitled to {rq.parameters[rp]}"
        return None

    def _anchor_value(self, rq: DecisionRequest, anchor: str) -> Any:
        if anchor == "subject":
            return rq.subject
        if anchor == "acting_user":
            return rq.principal_chain.get("acting_user")
        return rq.release.scopes.get(anchor)

    def _bounds(self, rq: DecisionRequest) -> str | None:
        p = rq.parameters
        for b in rq.node.bounds:
            # a bound on a parameter the called tool does not have does not apply to this call (read and
            # loop nodes declare several tools; the linter anchors each tool's resource role)
            if b.param and b.param not in rq.tool.schema and b.form != "pred":
                continue
            if b.form == "pred" and b.param not in rq.tool.schema:
                continue
            try:
                if b.form == "anchor_rel":
                    if b.param not in p:
                        return f"missing {b.param}"
                    if self._pip().relation(b.rel, p[b.param]) != self._anchor_value(rq, b.anchor):
                        return f"{b.rel}({b.param}) != {b.anchor}"
                elif b.form == "in_scope":
                    if p.get(b.param) not in (rq.release.scopes.get(b.scope) or []):
                        return f"{b.param} not in scope {b.scope}"
                elif b.form == "eq_rel_anchor":
                    if p.get(b.param) != self._pip().relation(b.rel, self._anchor_value(rq, b.anchor)):
                        return f"{b.param} != {b.rel}({b.anchor})"
                elif b.form == "eq_rel_param":
                    if p.get(b.param) != self._pip().relation(b.rel, p.get(b.q)):
                        return f"{b.param} != {b.rel}({b.q})"
                elif b.form == "pred":
                    if self._pip().predicate(b.rel, p.get(b.param)) != b.value:
                        return f"{b.rel}({b.param}) != {b.value}"
                elif b.form == "op":
                    if not _op(p.get(b.param), b.op, b.const):
                        return f"{b.param} {b.op} {b.const} failed"
            except Tainted:
                return f"{b.rel}: anchor relation answered from a tainted field"
        return None

    def _pip(self) -> PIP:
        if self.pip is None:
            raise Unavailable("PIP")
        return self.pip

    def _approver_set(self, rq: DecisionRequest, amount: Any) -> tuple[list[str], int]:
        assert self.bundle is not None
        base = list(rq.node.approver_set) or list(self.bundle.default_approvers)
        f = rq.factors
        if "irreversible" in f and "regulated" in f:
            if rq.tool.amount_param() is None or (amount is not None and amount > self.values.two_approver_threshold):
                return base + list(self.bundle.second_approvers), 2
        return base, 1

    def _decide_compensation(self, rq: DecisionRequest) -> Decision:
        """Allow if the parameters equal the manifest's mapping applied to the attached recorded original
        call and the record verifies; never held; terminal."""
        orig = rq.original_ref
        if not orig or not orig.get("verified"):
            return Decision("DENY", "compensation", "original record does not verify")
        # the mapping is declared on the reversed effect's manifest and names this reversing tool
        orig_node = rq.release.node(rq.node.reverses) if rq.node.reverses else None
        orig_tool = self.registry.tools.get(orig_node.tool or "") if orig_node else None
        mapping = orig_tool.compensation if orig_tool and isinstance(orig_tool.compensation, dict) else None
        if mapping is None:
            return Decision("DENY", "compensation", "no compensation mapping")
        if mapping.get("reversing_tool") != rq.tool.tool_id:
            return Decision("DENY", "compensation", "not the mapped reversing tool")
        expected = apply_mapping(mapping, orig["parameters"], orig.get("result") or {})
        if expected != rq.parameters:
            return Decision("DENY", "compensation", "parameters differ from the mapping over the recorded call")
        return Decision("ALLOW", "compensation", None, [], [], False, ["evidence_first"])

    def _decide_replay(self, rq: DecisionRequest) -> Decision:
        orig = rq.original_ref
        if not orig or not orig.get("verified"):
            return Decision("DENY", "replay", "original record does not verify")
        if orig.get("decision") != "ALLOW" or orig.get("action_hash") != rq.action_hash:
            return Decision("DENY", "replay", "no recorded ALLOW for this action hash")
        if orig.get("idempotency_key") != rq.parameters.get("__idempotency_key__"):
            return Decision("DENY", "replay", "idempotency key mismatch")
        if any(e != "effect.indeterminate" for e in orig.get("effect_events", [])):
            return Decision("DENY", "replay", "an effect event other than indeterminate exists")
        if any(o in {"denied", "revoked", "stopped"} for o in orig.get("later_hold_outcomes", [])):
            return Decision("DENY", "replay", "a later hold outcome forbids replay")
        return Decision("ALLOW", "replay", None, [], [], False, ["evidence_first"])


def apply_mapping(mapping: dict[str, Any], parameters: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """A compensation mapping is field references into the original call's recorded parameters and
    result (A.1): {"params": {"shipment_id": "result.shipment_id", ...}}."""
    out: dict[str, Any] = {}
    for k, ref in mapping.get("params", {}).items():
        src, _, fld = ref.partition(".")
        if src == "parameters":
            out[k] = parameters.get(fld)
        elif src == "result":
            out[k] = result.get(fld)
        else:
            raise ValueError(f"mapping may only reference parameters or result: {ref}")
    return out


def _op(a: Any, op: str, b: Any) -> bool:
    if a is None:
        return False
    return {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
