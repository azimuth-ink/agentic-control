"""Releases, graphs, nodes and bounds (spec sections 0, 4.1 to 4.4, A.1).

A release is a pinned bundle: graph, tool versions, bounds, surface and PEP form, scope constants,
policy version, declared model route. Nodes are typed; bounds are a conjunction of predicate forms
from the bound grammar (4.3)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .common import Record

NODE_TYPES = {"read", "effect", "loop", "sanitize", "human", "handoff", "service", "compensate", "output"}
TIERS = {"A1", "A2", "A3"}
EFFECT_CLASSES = {"reversible_internal", "external", "financial_legal"}
DERIVED_CLASSES = {"internal_store", "delivery", "spawn"}
SIDE_EFFECT_CLASSES = {"none"} | DERIVED_CLASSES | EFFECT_CLASSES
DATA_CLASSES = ["public", "internal", "confidential", "restricted"]
ANCHORS = {"subject", "acting_user"}  # plus any registered scope constant name

# node-type matrix (A.1): which tool classes a node type may call
MATRIX: dict[str, set[str]] = {
    "read": {"none", "internal_store"},
    "loop": {"none"},
    "sanitize": {"none"},            # exactly one sanitizer
    "effect": EFFECT_CLASSES | {"none"},  # the `none` is only the system's preview tool, on RUN's instruction
    "compensate": EFFECT_CLASSES,    # the mapped reversing tool
    "output": {"delivery"},
    "handoff": {"spawn"},
    "service": {"spawn"},
    "human": set(),
}


@dataclass
class Bound(Record):
    """One predicate of a node's bounds. Forms (4.3):

    anchor_rel      PIP.rel(p) == A          rel, param, anchor
    in_scope        p ∈ scope                param, scope
    eq_rel_anchor   p == PIP.rel(A)          param, rel, anchor
    eq_rel_param    p == PIP.rel(q)          param, rel, q
    pred            PIP.pred(p) == value     rel, param, value
    op              p op constant            param, op, const
    limit           amount ≤ auto | hard     param, auto, hard
    """

    form: str
    param: str | None = None
    rel: str | None = None
    anchor: str | None = None
    scope: str | None = None
    q: str | None = None
    value: Any = None
    op: str | None = None
    const: Any = None
    auto: float | None = None
    hard: float | None = None

    @property
    def anchoring(self) -> bool:
        return self.form in {"anchor_rel", "in_scope", "eq_rel_anchor", "eq_rel_param"}


def anchored_params(bounds: list[Bound], scope_names: set[str]) -> set[str]:
    """The anchoring rule (4.3): a parameter is anchored by equality or membership to an anchor
    (`subject`, `acting_user`, a registered scope constant), or by equality to a relation of an
    already-anchored parameter. Other operators never anchor."""
    anchored: set[str] = set()
    for b in bounds:
        if b.form == "anchor_rel" and b.anchor in ANCHORS | scope_names:
            anchored.add(b.param)
        elif b.form == "in_scope" and b.scope in scope_names:
            anchored.add(b.param)
        elif b.form == "eq_rel_anchor" and b.anchor in ANCHORS | scope_names:
            anchored.add(b.param)
    changed = True
    while changed:
        changed = False
        for b in bounds:
            if b.form == "eq_rel_param" and b.q in anchored and b.param not in anchored:
                anchored.add(b.param)
                changed = True
    return anchored


def scope_only(bounds: list[Bound]) -> bool:
    """`Scope-anchored` (6.1): bounds that use only scope constants and predicates on constants."""
    return all(b.form in {"in_scope", "op", "limit"} for b in bounds)


@dataclass
class Node(Record):
    id: str
    type: str
    tool: str | None = None                 # tool id (effect/read/loop/output/compensate/handoff/service)
    tools: list[str] = field(default_factory=list)  # read/loop nodes may declare several none tools
    bounds: list[Bound] = field(default_factory=list)
    tier: str | None = None                 # effect nodes: A1 | A2 | A3
    compensate: str | None = None           # node id of the compensate node, or "irreversible"
    preview: bool = False
    step_cap: int | None = None
    token_cap: int | None = None
    approver_set: list[str] = field(default_factory=list)
    input_role: str | None = None           # human nodes: registered input role
    denial_branch: str | None = None        # node id to continue at on deny/timeout; None = end run on the branch
    failure_branch: str | None = None
    next: str | None = None                 # explicit successor; None = the next forward node in graph order
    target_agent: str | None = None         # handoff/service
    sanitizer: str | None = None            # sanitize nodes
    reverses: str | None = None             # compensate nodes: the effect node reversed
    template_param: str | None = None       # output/effect nodes: parameter carrying a template id

    def declared_tools(self) -> set[str]:
        out = set(self.tools)
        if self.tool:
            out.add(self.tool)
        return out


@dataclass
class Release(Record):
    agent_id: str
    version: str
    surface: str                            # S1 | S2 | S4
    pep_form: str                           # proxy | sidecar | sdk
    pep_version: str
    nodes: list[Node]
    tools: dict[str, str] = field(default_factory=dict)      # tool_id -> version
    scopes: dict[str, list[Any]] = field(default_factory=dict)  # scope constants: templates, recipients, sinks, ...
    policy_version: str = "1"
    model_route: list[str] = field(default_factory=list)
    retrieval_config: dict[str, Any] = field(default_factory=dict)
    anchor_version: int | None = None       # stamped by REG at publish
    fast_path: bool = False
    # runtime-maintained by REG
    suspended: bool = False
    denied_effects: set[str] = field(default_factory=set)   # node ids whose held effects lost a resumption path

    @property
    def release_id(self) -> str:
        return f"{self.agent_id}@{self.version}"

    def node(self, node_id: str) -> Node:
        for n in self.nodes:
            if n.id == node_id:
                return n
        raise KeyError(node_id)

    def effect_nodes(self) -> list[Node]:
        return [n for n in self.nodes if n.type == "effect"]

    def forward_nodes(self) -> list[Node]:
        return [n for n in self.nodes if n.type != "compensate"]

    def next_after(self, node_id: str) -> str | None:
        fwd = self.forward_nodes()
        for i, n in enumerate(fwd):
            if n.id == node_id:
                if n.next is not None:
                    return n.next
                return fwd[i + 1].id if i + 1 < len(fwd) else None
        return None

    def scope_names(self) -> set[str]:
        return set(self.scopes)
