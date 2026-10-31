"""REG, the Registry (spec A.1).

The system of record for what exists and what it may touch: agents, releases, tool manifests, system
capability records, triggers, sanitizers, services, and the boundary definition. Trust properties are
derived here, never authored: `agent_writable`, `external_ingress` through `sources[]`,
`untrusted_source`, the derived side-effect classes, and anchor capability, which REG recomputes as
registrations change and stamps on each release."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .common import Availability, Record, Refused, digest
from .crypto import PublicKey
from .release import (DERIVED_CLASSES, EFFECT_CLASSES, MATRIX, NODE_TYPES, SIDE_EFFECT_CLASSES, Bound, Node,
                      Release, anchored_params)

SYSTEM_KINDS = {"system_of_record", "sink_store", "interface", "derived_store", "memory"}
DBS_KINDS = {"sink_store", "interface", "derived_store", "memory"}
DESTINATION_CLASSES = {"network_location", "payment_instrument", "email", "phone", "postal_address", "account_identifier"}
TIER_CAPS = {("S4", "sdk"): "A1", ("S4", "sidecar"): "A1", ("S2", "sdk"): "A2", ("S2", "sidecar"): "A3", ("S1", "proxy"): "A3"}
TIER_ORDER = {"A1": 1, "A2": 2, "A3": 3}


@dataclass
class Boundary(Record):
    """The boundary definition: which registered systems count as inside, and how a destination value
    of each class resolves inside or outside."""

    inside_systems: set[str] = field(default_factory=set)
    # per destination class: a predicate on the value → True when inside
    resolvers: dict[str, Callable[[Any], bool]] = field(default_factory=dict)
    # per class: whether a value of the class can resolve outside at all (for the static external factor)
    can_resolve_outside: dict[str, bool] = field(default_factory=dict)

    def is_inside_system(self, system_id: str) -> bool:
        return system_id in self.inside_systems

    def destination_inside(self, dest_class: str, value: Any) -> bool:
        fn = self.resolvers.get(dest_class)
        if fn is None:
            return False
        return bool(fn(value))

    def to_dict(self) -> dict[str, Any]:
        return {"inside_systems": sorted(self.inside_systems), "can_resolve_outside": self.can_resolve_outside}


@dataclass
class SystemCapability(Record):
    system_id: str
    kind: str
    owner_team: str = "owning-team"
    sources: list[str] = field(default_factory=list)
    external_ingress: bool = False            # authored; derived true for a system outside the boundary
    provenance_tag: bool = False               # authored; not registrable outside the boundary
    verified_fields: set[str] = field(default_factory=set)  # fields marked verified through an authenticated channel
    presentation: str = "per_agent"            # chained | per_agent
    recovery_accepted: bool = False
    preview_tool: str | None = None
    idempotency: bool = False
    pip_relations: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # rel -> backing (system, field)
    sync: str = "event"                        # derived stores: event | scheduled
    feed_reviews: dict[str, bool] = field(default_factory=dict)  # source -> passed
    approved_by: tuple[str, ...] = ("security", "compliance")


@dataclass
class ToolManifest(Record):
    tool_id: str
    version: str
    target_system: str
    schema: dict[str, str]                      # parameter -> type name
    description: str = ""
    side_effect_class: str = "none"            # authored for none and the effect classes; derived otherwise
    bulk: bool = False
    compliance_flag: bool = False
    reads_data_class: str = "internal"
    writes_data_class: str = "internal"
    writes_fields: list[tuple[str, str]] = field(default_factory=list)
    parameter_roles: dict[str, str] = field(default_factory=dict)  # param -> resource | destination | amount
    destination_class: str | None = None
    resource_none_justification: str | None = None
    compensation: Any = "irreversible"        # mapping {reversing_tool, params: {p: "parameters.x" | "result.y"}} or "irreversible"
    maintainer: str = "maintainer"
    is_sanitizer: bool = False
    schema_hash: str = ""

    def __post_init__(self) -> None:
        self.schema_hash = digest({"schema": self.schema, "description": self.description})

    @property
    def is_writing_tool(self) -> bool:
        return bool(self.writes_fields)

    def resource_param(self) -> str | None:
        for p, r in self.parameter_roles.items():
            if r == "resource":
                return p
        return None

    def destination_param(self) -> str | None:
        for p, r in self.parameter_roles.items():
            if r == "destination":
                return p
        return None

    def amount_param(self) -> str | None:
        for p, r in self.parameter_roles.items():
            if r == "amount":
                return p
        return None


@dataclass
class Trigger(Record):
    trigger_id: str
    source_system: str
    kind: str                                   # user_session | subject_claim | event
    signing_key: PublicKey | None = None
    subject_authentication: str | None = None   # how the source authenticates the subject before signing
    subject_schema: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"trigger_id": self.trigger_id, "source_system": self.source_system, "kind": self.kind,
                "subject_authentication": self.subject_authentication}


@dataclass
class Sanitizer(Record):
    sanitizer_id: str
    version: str
    fn: Callable[[dict[str, Any]], tuple[dict[str, Any], dict[str, Any]]]  # input -> (accepted, rejected)
    input_schema: dict[str, str]
    output_schema: dict[str, str]              # field -> int | number | bool | enum:<a,b> | identifier:<regex> | string
    rendering: bool = False

    @property
    def qualifies_for_sanitized_provenance(self) -> bool:
        """A.3: a sanitizer whose output schema has no string field at all, except enumerations and
        identifiers matching a registered pattern; the rendering sanitizer never qualifies."""
        if self.rendering:
            return False
        for t in self.output_schema.values():
            if t == "string" or t.startswith("string"):
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {"sanitizer_id": self.sanitizer_id, "version": self.version, "output_schema": self.output_schema}


@dataclass
class Agent(Record):
    agent_id: str
    owner: str
    builder: str
    surface: str
    launcher: Callable[..., Any] | None = None
    expiry: float | None = None
    agent_class: str = "governed"               # governed | A0
    input_roles_internal: set[str] = field(default_factory=set)
    is_service: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"agent_id": self.agent_id, "owner": self.owner, "surface": self.surface, "class": self.agent_class}


class Registry(Availability):
    name = "REG"

    def __init__(self, boundary: Boundary) -> None:
        self.boundary = boundary
        self.systems: dict[str, SystemCapability] = {}
        self.tools: dict[str, ToolManifest] = {}
        self.triggers: dict[str, Trigger] = {}
        self.sanitizers: dict[str, Sanitizer] = {}
        self.agents: dict[str, Agent] = {}
        self.releases: dict[str, Release] = {}
        self.anchor_version = 0
        self._capable: dict[str, bool] = {}     # relation -> capable now
        self.suspensions: list[tuple[str, str]] = []   # (release_id, reason)
        self.notifications: list[str] = []

    # ------------------------------------------------------------------ registration
    def register_system(self, cap: SystemCapability) -> SystemCapability:
        self._check()
        if cap.kind not in SYSTEM_KINDS:
            raise Refused(f"unknown kind {cap.kind}")
        inside = self.boundary.is_inside_system(cap.system_id)
        if cap.kind in DBS_KINDS and not inside:
            raise Refused(f"kind {cap.kind} is not registrable for a system outside the boundary definition")
        if cap.provenance_tag and not inside:
            raise Refused("provenance_tag is not registrable for a system outside the boundary definition")
        if cap.kind == "system_of_record":
            for s in cap.sources:
                if s in self.systems and self.systems[s].kind == "sink_store":
                    raise Refused("a sink_store may not appear in a system_of_record's sources[]")
        for s in cap.sources:
            if s in self.systems and self.systems[s].kind == "sink_store" and cap.kind == "system_of_record":
                raise Refused("a sink_store may not feed a system of record")
        if cap.system_id in self.systems:
            self._refuse_if_breaks_anchors(lambda: self._with_system(cap))
        self.systems[cap.system_id] = cap
        self._recompute_anchor_capability()
        return cap

    def register_feed_review(self, system_id: str, source: str, passed: bool) -> None:
        """A feed review result is a change REG cannot refuse: it suspends dependent releases (A.1)."""
        self._check()
        self.systems[system_id].feed_reviews[source] = passed
        self._recompute_anchor_capability(refusable=False)

    def register_tool(self, m: ToolManifest) -> ToolManifest:
        self._check()
        target = self.systems.get(m.target_system)
        if target is None and not m.is_sanitizer:
            raise Refused(f"unknown target system {m.target_system}")
        if m.side_effect_class not in SIDE_EFFECT_CLASSES:
            raise Refused(f"unknown side_effect_class {m.side_effect_class}")
        # derived classes cannot be authored (A.1)
        derived = self._derived_class(m, target)
        if derived is not None:
            if m.side_effect_class not in ("none", derived):
                raise Refused(f"class {derived} is derived for this tool and cannot be authored as {m.side_effect_class}")
            m.side_effect_class = derived
        elif m.side_effect_class in DERIVED_CLASSES:
            raise Refused(f"class {m.side_effect_class} cannot be authored")
        if m.side_effect_class == "none":
            if m.is_writing_tool and target is not None and target.kind in {"system_of_record", "derived_store"}:
                raise Refused("a writing tool whose target is a system_of_record or derived_store must carry an effect class")
            if target is not None and not self.boundary.is_inside_system(target.system_id):
                raise Refused("REG refuses none for a tool whose target_system is outside the boundary definition")
            dc = m.destination_class
            if m.destination_param() and dc and self.boundary.can_resolve_outside.get(dc, True):
                raise Refused("REG refuses none for a tool whose destination role can resolve outside the boundary definition")
        dp = m.destination_param()
        if dp and m.destination_class not in DESTINATION_CLASSES:
            raise Refused("a destination role must carry a registered destination class")
        if m.side_effect_class != "none" or m.reads_data_class in ("confidential", "restricted"):
            if m.resource_param() is None and m.resource_none_justification is None and not m.is_sanitizer:
                raise Refused("a tool with a side effect, or reading above internal, declares a resource or none with a security-approved justification")
        if m.tool_id in self.tools or m.is_writing_tool:
            self._refuse_if_breaks_anchors(lambda: self._with_tool(m))
        self.tools[m.tool_id] = m
        self._recompute_anchor_capability()
        return m

    def register_agent(self, agent: Agent) -> Agent:
        self._check()
        self.agents[agent.agent_id] = agent
        # the agent tool (A.1): class spawn by derivation
        self.tools[f"agent:{agent.agent_id}"] = ToolManifest(
            tool_id=f"agent:{agent.agent_id}", version="1", target_system="__agent__", schema={"inputs": "object"},
            side_effect_class="spawn", resource_none_justification="agent tool")
        return agent

    def register_trigger(self, t: Trigger) -> Trigger:
        self._check()
        if t.kind not in {"user_session", "subject_claim", "event"}:
            raise Refused("unknown trigger kind")
        if t.kind == "subject_claim" and not t.subject_authentication:
            raise Refused("a subject_claim trigger is registrable only if the source authenticates the subject before signing and records how")
        if t.source_system not in self.systems:
            raise Refused("trigger source must be a registered system")
        self.triggers[t.trigger_id] = t
        return t

    def register_sanitizer(self, s: Sanitizer) -> Sanitizer:
        self._check()
        self.sanitizers[s.sanitizer_id] = s
        self.tools[s.sanitizer_id] = ToolManifest(tool_id=s.sanitizer_id, version=s.version, target_system="__dbs__",
                                                  schema=s.input_schema, side_effect_class="none", is_sanitizer=True,
                                                  resource_none_justification="sanitizer")
        return s

    # ------------------------------------------------------------------ derivations
    def _derived_class(self, m: ToolManifest, target: SystemCapability | None) -> str | None:
        if target is None:
            return None
        if target.kind == "memory" and m.is_writing_tool:
            return "internal_store"
        if target.kind == "interface":
            return "delivery"
        if target.kind == "sink_store" and m.is_writing_tool:
            return "delivery"
        return None

    def external_ingress(self, system_id: str) -> bool:
        """Derived: true for the system or any source; true for any system outside the boundary."""
        cap = self.systems[system_id]
        if not self.boundary.is_inside_system(system_id):
            return True
        if cap.external_ingress:
            return True
        return any(s in self.systems and self.external_ingress(s) for s in cap.sources)

    def agent_writable(self, system_id: str) -> bool:
        """Derived: any registered writing tool targets the system, or any source is agent-writable.
        Memory and sink stores are agent_writable by definition."""
        cap = self.systems[system_id]
        if cap.kind in {"memory", "sink_store"}:
            return True
        if any(t.is_writing_tool and t.target_system == system_id for t in self.tools.values()):
            return True
        return any(s in self.systems and self.agent_writable(s) for s in cap.sources)

    def provenance_tag(self, system_id: str) -> bool:
        """Derived: the system and every source carry tags and every registered feed passed review."""
        cap = self.systems[system_id]
        if cap.kind in {"memory", "sink_store"}:
            return True
        if not cap.provenance_tag:
            return False
        for s in cap.sources:
            if s not in self.systems or not self.provenance_tag(s):
                return False
            if not cap.feed_reviews.get(s, False):
                return False
        return True

    def untrusted_source(self, m: ToolManifest) -> str:
        """per_item if provenance_tag; else always if external_ingress or agent_writable; else never."""
        if m.is_sanitizer or m.target_system in ("__agent__", "__dbs__"):
            return "never"
        sid = m.target_system
        if self.provenance_tag(sid):
            return "per_item"
        if self.external_ingress(sid) or self.agent_writable(sid):
            return "always"
        return "never"

    def payload_trust(self, trigger: Trigger) -> str:
        """Trigger payload trust is derived by the same rule as untrusted_source."""
        sid = trigger.source_system
        if self.provenance_tag(sid):
            return "per_item"
        if self.external_ingress(sid) or self.agent_writable(sid):
            return "untrusted"
        return "trusted"

    def writes_field(self, system: str, fld: str) -> bool:
        return any((system, fld) in t.writes_fields for t in self.tools.values())

    def relation_backing(self, rel: str) -> list[tuple[str, str]] | None:
        for cap in self.systems.values():
            if rel in cap.pip_relations:
                return cap.pip_relations[rel]
        return None

    def relation_capable(self, rel: str) -> bool:
        """Anchor capability (A.1)."""
        backing = self.relation_backing(rel)
        if backing is None:
            return False
        for system, fld in backing:
            cap = self.systems.get(system)
            if cap is None or cap.kind != "system_of_record":
                return False
            clean = not self.external_ingress(system) and not self.agent_writable(system)
            verified = self.provenance_tag(system) and fld in cap.verified_fields
            if not (clean or verified):
                return False
            if self.writes_field(system, fld):
                return False
        return True

    def all_relations(self) -> set[str]:
        out: set[str] = set()
        for cap in self.systems.values():
            out |= set(cap.pip_relations)
        return out

    def _capability_map(self) -> dict[str, bool]:
        return {r: self.relation_capable(r) for r in self.all_relations()}

    def _recompute_anchor_capability(self, refusable: bool = True) -> None:
        new = self._capability_map()
        if new != self._capable:
            self.anchor_version += 1
            lost = {r for r, ok in self._capable.items() if ok and not new.get(r, False)}
            self._capable = new
            if lost:
                for rel in self.releases.values():
                    if not rel.suspended and self._release_anchors(rel) & lost:
                        rel.suspended = True
                        self.suspensions.append((rel.release_id, f"anchor relation lost capability: {sorted(lost)}"))
                        self.notifications.append(f"owner of {rel.release_id}: release suspended, effects resolve by denial until republished")

    def anchors_still_capable(self, release: Release) -> bool:
        """What the PDP checks per call through `anchor_version`: every anchor relation the release
        uses is still capable at REG's current version."""
        return all(self._capable.get(r, False) for r in self._release_anchors(release))

    def _release_anchors(self, release: Release) -> set[str]:
        out: set[str] = set()
        for n in release.nodes:
            for b in n.bounds:
                if b.form in {"anchor_rel", "eq_rel_anchor", "eq_rel_param"} and b.rel:
                    out.add(b.rel)
        return out

    def _refuse_if_breaks_anchors(self, mutate_preview: Callable[[], dict[str, bool]]) -> None:
        """REG refuses a registration that would remove anchor capability from a relation any
        published release depends on, unless the owner republishes first."""
        would = mutate_preview()
        lost = {r for r, ok in self._capable.items() if ok and not would.get(r, False)}
        if not lost:
            return
        for rel in self.releases.values():
            if not rel.suspended and self._release_anchors(rel) & lost:
                raise Refused(f"registration would remove anchor capability of {sorted(lost)} from published release {rel.release_id}")

    def _with_tool(self, m: ToolManifest) -> dict[str, bool]:
        saved = dict(self.tools)
        self.tools[m.tool_id] = m
        try:
            return self._capability_map()
        finally:
            self.tools = saved

    def _with_system(self, cap: SystemCapability) -> dict[str, bool]:
        saved = dict(self.systems)
        self.systems[cap.system_id] = cap
        try:
            return self._capability_map()
        finally:
            self.systems = saved

    # ------------------------------------------------------------------ factors
    def static_factors(self, m: ToolManifest) -> set[str]:
        """Factors knowable from the manifest alone (the linter's view)."""
        f: set[str] = set()
        if m.compensation == "irreversible":
            f.add("irreversible")
        if m.side_effect_class in {"external", "financial_legal"}:
            f.add("external")
        dc = m.destination_class
        if m.destination_param() and dc and self.boundary.can_resolve_outside.get(dc, True):
            f.add("external")
        if m.target_system in self.systems and not self.boundary.is_inside_system(m.target_system):
            f.add("external")
        if m.side_effect_class == "financial_legal" or m.compliance_flag:
            f.add("regulated")
        if m.reads_data_class == "restricted" or m.writes_data_class == "restricted" or m.bulk:
            f.add("sensitive")
        return f

    def derive_factors(self, m: ToolManifest, params: dict[str, Any]) -> set[str]:
        """Factor derivation per call (A.1): irreversible, external, regulated, sensitive."""
        f: set[str] = set()
        if m.compensation == "irreversible":
            f.add("irreversible")
        if m.side_effect_class in {"external", "financial_legal"}:
            f.add("external")
        if self.destination_outside(m, params):
            f.add("external")
        if m.side_effect_class == "financial_legal" or m.compliance_flag:
            f.add("regulated")
        if m.reads_data_class == "restricted" or m.writes_data_class == "restricted" or m.bulk:
            f.add("sensitive")
        return f

    def destination_outside(self, m: ToolManifest, params: dict[str, Any]) -> bool:
        """Whether the call's destination resolves outside the trust boundary. A tool whose target is
        outside the boundary resolves outside, its registered target counting as the destination (A.1)."""
        if m.target_system in self.systems and not self.boundary.is_inside_system(m.target_system):
            return True
        dp = m.destination_param()
        if dp and dp in params and m.destination_class:
            return not self.boundary.destination_inside(m.destination_class, params[dp])
        return False

    # ------------------------------------------------------------------ releases and the linter
    def lint_release(self, rel: Release, policy: "PolicyValues", pep_allowlist: set[str]) -> list[str]:
        """The release linter (A.1). Returns the list of reasons a release is not publishable."""
        errs: list[str] = []
        agent = self.agents.get(rel.agent_id)
        if agent is None:
            return ["unknown agent"]
        ids = [n.id for n in rel.nodes]
        if len(ids) != len(set(ids)):
            errs.append("node ids must be unique")
        if rel.surface != agent.surface:
            errs.append("release surface must equal the agent's registered surface")
        cap = TIER_CAPS.get((rel.surface, rel.pep_form))
        if cap is None:
            errs.append(f"no tier cap for surface {rel.surface} with form {rel.pep_form}")
        if rel.pep_version not in pep_allowlist:
            errs.append("PEP version not on the allow-list")
        scope_names = rel.scope_names()
        for n in rel.nodes:
            if n.type not in NODE_TYPES:
                errs.append(f"{n.id}: unknown node type {n.type}")
                continue
            # node-type matrix
            for tid in n.declared_tools():
                m = self.tools.get(tid)
                if m is None:
                    errs.append(f"{n.id}: unregistered tool {tid}")
                    continue
                if m.is_sanitizer and n.type != "sanitize":
                    errs.append(f"{n.id}: only a sanitize node may call a sanitizer")
                if m.side_effect_class not in MATRIX[n.type]:
                    errs.append(f"{n.id}: node type {n.type} may not call a {m.side_effect_class} tool")
                if n.type == "effect" and m.side_effect_class == "none" and tid != self._preview_tool_for(n):
                    errs.append(f"{n.id}: an effect node calls exactly one effect-class tool plus its preview tool")
            if n.type == "effect":
                m = self.tools.get(n.tool or "")
                if m is None:
                    continue
                if n.tier not in {"A1", "A2", "A3"}:
                    errs.append(f"{n.id}: effect node must declare a tier")
                elif cap and TIER_ORDER[n.tier] > TIER_ORDER[cap]:
                    errs.append(f"{n.id}: tier {n.tier} exceeds the cap {cap} for {rel.surface}/{rel.pep_form}")
                sf = self.static_factors(m)
                if sf and n.tier == "A3":
                    errs.append(f"{n.id}: an effect node carrying a factor is never A3")
                if n.compensate is None:
                    errs.append(f"{n.id}: every effect node declares a compensate node or irreversible")
                elif n.compensate != "irreversible":
                    cn = next((x for x in rel.nodes if x.id == n.compensate), None)
                    if cn is None or cn.type != "compensate":
                        errs.append(f"{n.id}: compensate must name a compensate node")
                    elif m.compensation == "irreversible":
                        errs.append(f"{n.id}: manifest declares irreversible but the node declares a compensate node")
                if "irreversible" in sf and "regulated" in sf:
                    lim = next((b for b in n.bounds if b.form == "limit"), None)
                    if m.amount_param() is None:
                        if n.tier != "A1":
                            errs.append(f"{n.id}: irreversible and regulated with no amount role must be A1")
                    elif lim is None or lim.auto is None or lim.auto > policy.two_approver_threshold:
                        errs.append(f"{n.id}: auto limit must be at or below the two-approver threshold")
                # anchoring rule
                anchored = anchored_params(n.bounds, scope_names)
                for p in (m.resource_param(), m.destination_param()):
                    if p and p not in anchored:
                        errs.append(f"{n.id}: parameter {p} with role {m.parameter_roles[p]} is not anchored")
                # resumption path
                if n.tier in {"A1", "A2"} and not self._has_resumption_path(n, policy):
                    errs.append(f"{n.id}: no resumption path (grant or substitution) under the current policy bundle")
            if n.type in {"read", "loop"}:
                anchored = anchored_params(n.bounds, scope_names)
                for tid in n.declared_tools():
                    m = self.tools.get(tid)
                    if m and m.resource_param() and m.resource_param() not in anchored:
                        errs.append(f"{n.id}: read tool {tid} has a resource role that is not anchored")
            if n.type == "output":
                m = self.tools.get(n.tool or "")
                if m is None or m.side_effect_class != "delivery":
                    errs.append(f"{n.id}: an output node names exactly one delivery tool")
                else:
                    target = self.systems[m.target_system]
                    anchored = anchored_params(n.bounds, scope_names)
                    if target.kind == "interface" and "recipient" not in anchored:
                        errs.append(f"{n.id}: output to an interface must bound its recipient")
                    if target.kind == "sink_store" and "sink" not in anchored:
                        errs.append(f"{n.id}: output to a sink store must bound its sink")
            if n.type == "compensate":
                if n.reverses is None:
                    errs.append(f"{n.id}: compensate node must name the effect node it reverses")
            if n.type == "sanitize" and (n.sanitizer is None or n.sanitizer not in self.sanitizers):
                errs.append(f"{n.id}: sanitize node must name a registered sanitizer")
        for b_rel in self._release_anchors(rel):
            if not self.relation_capable(b_rel):
                errs.append(f"anchor relation {b_rel} is not anchor-capable")
        if rel.fast_path:
            if rel.effect_nodes():
                errs.append("fast path: graph has an effect node")
            if any(n.type in {"handoff", "service"} for n in rel.nodes):
                errs.append("fast path: graph has a handoff or service node")
            for n in rel.nodes:
                for tid in n.declared_tools():
                    m = self.tools.get(tid)
                    if m and m.reads_data_class in {"confidential", "restricted"}:
                        errs.append(f"fast path: tool {tid} reads above internal")
        return errs

    def _preview_tool_for(self, n: Node) -> str | None:
        m = self.tools.get(n.tool or "")
        if m is None:
            return None
        sysc = self.systems.get(m.target_system)
        return sysc.preview_tool if sysc else None

    def _has_resumption_path(self, n: Node, policy: "PolicyValues") -> bool:
        if policy.grants_permitted:
            return True
        if policy.substitution_permitted:
            # substitution counts only for a node with no bound anchored to acting_user (A.1)
            return not any(b.anchor == "acting_user" for b in n.bounds)
        return False

    def publish_release(self, rel: Release, policy: "PolicyValues", pep_allowlist: set[str]) -> Release:
        self._check()
        errs = self.lint_release(rel, policy, pep_allowlist)
        if errs:
            raise Refused("release not publishable: " + "; ".join(errs))
        self._recompute_anchor_capability()
        rel.anchor_version = self.anchor_version
        rel.suspended = False
        rel.denied_effects = set()
        self.releases[rel.release_id] = rel
        return rel

    def get_release(self, release_id: str) -> Release:
        self._check()
        return self.releases[release_id]

    def get_tool_manifest(self, tool_id: str) -> ToolManifest:
        self._check()
        return self.tools[tool_id]

    def on_bundle_published(self, policy: "PolicyValues") -> None:
        """When a new policy bundle is published, every release is re-linted; a release whose held
        effects lose their resumption path is flagged to its owner and those effects resolve by denial."""
        for rel in self.releases.values():
            lost = {n.id for n in rel.effect_nodes() if n.tier in {"A1", "A2"} and not self._has_resumption_path(n, policy)}
            if lost:
                rel.denied_effects = lost
                self.notifications.append(f"owner of {rel.release_id}: effects {sorted(lost)} lost their resumption path")

    def suspend(self, release_id: str, reason: str) -> None:
        self.releases[release_id].suspended = True
        self.suspensions.append((release_id, reason))


@dataclass
class PolicyValues(Record):
    """The policy values a bundle sets (section 0, Policy values)."""

    approval_timeout: float = 3600.0
    resume_window: float = 1800.0
    max_park: float = 7200.0
    rehold_maximum: int = 3
    staleness_limit: float = 300.0
    two_approver_threshold: float = 1000.0
    velocity: dict[str, dict[str, Any]] = field(default_factory=dict)   # key kind -> {window, limit, hard_cap}
    degraded_caps: dict[str, int] = field(default_factory=dict)
    heartbeat_deadline: float = 60.0
    wall_clock_budget: float = 86400.0
    consecutive_replays: int = 3
    credential_lifetime: float = 3600.0
    grants_permitted: bool = True
    substitution_permitted: bool = True
    token_budget_per_agent: int = 1_000_000
