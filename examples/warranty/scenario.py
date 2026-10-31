"""The worked flow (spec section 8) as a runnable scenario.

A device-support portal authenticates a customer and raises a fault ticket (a subject_claim trigger
from a system with external ingress). The agent looks up the customer's registered devices, reasons
about eligibility in a loop, sanitizes its proposal, ships a replacement (an effect with factor
external and a declared compensation), sends a templated reply, and logs the case."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentic_control.common import Clock
from agentic_control.crypto import Signer
from agentic_control.dbs import System, SinkStore, identifier_numeric_extractor, rendering_sanitizer
from agentic_control.enforcement import EnforcementPoint
from agentic_control.platform import Platform, build_platform
from agentic_control.policy import PolicyBundle, Tainted
from agentic_control.registry import Agent, Boundary, PolicyValues, Sanitizer, SystemCapability, ToolManifest, Trigger
from agentic_control.release import Bound, Node, Release
from agentic_control.runtime import Runtime

AGENT = "warranty-agent"
BUILD = "pep-e-build-1"


class DeviceRegistry(System):
    def apply(self, tool, params, tag):
        raise NotImplementedError("read-only")


class SupportPortal(System):
    def apply(self, tool, params, tag):
        raise NotImplementedError("read-only")


class Fulfilment(System):
    """System of record for shipments: tagging, idempotent, with a preview endpoint and a reversing tool."""

    def __init__(self, system_id: str, ids: Any) -> None:
        super().__init__(system_id, ids, tagging=True, idempotent=True)
        self.shipments: dict[str, dict[str, Any]] = {}
        self.dispatched: set[str] = set()
        self._n = 0

    def apply(self, tool: str, params: dict[str, Any], tag: str | None) -> dict[str, Any]:
        if tool == "ship_replacement":
            self._n += 1
            sid = f"ship-{self._n}"
            self.shipments[sid] = {**params, "status": "created"}
            self.records[params["device_id"]] = {**self.records.get(params["device_id"], {}), "replacement_issued": True}
            return {"shipment_id": sid, "status": "created"}
        if tool == "cancel_shipment":
            sid = params["shipment_id"]
            if sid not in self.shipments:
                from agentic_control.dbs import SystemRefused
                raise SystemRefused("unknown shipment")
            if sid in self.dispatched:
                from agentic_control.dbs import SystemRefused
                raise SystemRefused("already dispatched")
            self.shipments[sid]["status"] = "cancelled"
            return {"shipment_id": sid, "status": "cancelled"}
        raise NotImplementedError(tool)

    def preview(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"would_ship": params.get("part_sku"), "to": params.get("destination"), "value": params.get("amount"), "tainted": False}


class MailRelay(System):
    def __init__(self, system_id: str, ids: Any) -> None:
        super().__init__(system_id, ids)
        self.sent: list[dict[str, Any]] = []

    def apply(self, tool, params, tag):
        self.sent.append(dict(params))
        return {"message_id": f"msg-{len(self.sent)}"}


class WarrantyPIP:
    """PIP adapters over the fake systems. Refuses to answer an anchor relation from a tainted field."""

    def __init__(self, devices: DeviceRegistry, fulfilment: Fulfilment, identity_system: System) -> None:
        self.devices, self.fulfilment, self.identity_system = devices, fulfilment, identity_system
        self.queries: list[tuple[str, Any]] = []

    def relation(self, rel: str, value: Any) -> Any:
        self.queries.append((rel, value))
        if rel == "owner":
            return self.devices.records.get(value, {}).get("owner")
        if rel == "verified_ship_address":
            rec = self.fulfilment.records.get(value, {})
            if rec.get("_tags", {}).get("ship_address") in {"untrusted", "exposed"}:
                raise Tainted()
            return rec.get("ship_address")
        if rel == "address_on_file":
            return self.identity_system.records.get(value, {}).get("email")
        return None

    def predicate(self, rel: str, value: Any) -> bool:
        self.queries.append((rel, value))
        if rel == "replacement_issued":
            return bool(self.fulfilment.records.get(value, {}).get("replacement_issued"))
        return False

    def entitled(self, user: str, system: str, resource: Any) -> bool:
        return True


class WarrantyModel:
    """A deterministic stand-in for the model. `behaviour` switches the adversarial variants used by the
    conformance suite: inject_address, inject_sku, over_limit, wrong_device."""

    def __init__(self, device_id: str = "dev-1", part_sku: str = "PART-100", amount: float = 120.0, behaviour: str = "normal") -> None:
        self.device_id, self.part_sku, self.amount, self.behaviour = device_id, part_sku, amount, behaviour
        self.ticket_address: str | None = None

    def propose(self, run, node: Node, ctx: dict[str, Any]) -> dict[str, Any]:
        if node.id == "n1":
            return {"device_id": "dev-9" if self.behaviour == "wrong_device" else self.device_id}
        if node.id == "n2":
            it = ctx.get("iteration", 1)
            if it == 1:
                return {"call": "read_ticket", "params": {"ticket_id": "t-1"}}
            if it == 2:
                return {"call": "read_purchase", "params": {"device_id": self.device_id}}
            return {"done": True, "proposal": {"device_id": self.device_id, "part_sku": "P@RT 1" if self.behaviour == "inject_sku" else self.part_sku,
                                               "amount": 5000.0 if self.behaviour == "over_limit" else self.amount}}
        if node.id == "n3":
            return dict(ctx["outputs"].get("n2", {}))
        if node.id == "n4":
            s = ctx["outputs"].get("n3", {})
            dest = self.ticket_address if self.behaviour == "inject_address" and self.ticket_address else "12 Main St"
            return {"device_id": s.get("device_id"), "part_sku": s.get("part_sku"), "amount": s.get("amount"), "destination": dest}
        if node.id == "n5":
            return {"template_id": "tpl-shipped", "destination": self.ticket_address if self.behaviour == "inject_reply" else "cust@example.com"}
        if node.id == "n6":
            return {"sink": "case-log", "content": "Replacement issued. See https://evil.example/x?token=abc for details."}
        if node.id == "n0":
            return {"topic": "warranty" if self.behaviour != "bad_topic" else "finance", "text": "ticket received", "priority": 1}
        if node.id == "h1":
            return {"inputs": {"ticket": "t-1"}}
        raise KeyError(node.id)


@dataclass
class Scenario:
    platform: Platform
    release: Release
    pep: EnforcementPoint
    runtime: Runtime
    model: WarrantyModel
    systems: dict[str, System]
    pip: WarrantyPIP
    portal_signer: Signer
    bundle: PolicyBundle
    runs: list[Any] = field(default_factory=list)
    trigger_id: str = "fault-ticket"
    console_signer: Signer | None = None
    registry_signer: Signer | None = None
    child: dict[str, Any] = field(default_factory=dict)

    def start(self, customer: str = "cust-1", ticket_body: str = "My device is broken.", ticket_address: str | None = None,
              trigger: str | None = None, user: str | None = None):
        """Starts a run. Default: the subject_claim trigger from the portal (payload untrusted). `trigger`
        may name the clean subject_claim trigger (`clean-ticket`) or the user_session trigger (`console`)."""
        trigger = trigger or self.trigger_id
        self.systems["support_portal"].records["t-1"] = {"ticket_id": "t-1", "body": ticket_body, "address_in_body": ticket_address}
        self.model.ticket_address = ticket_address
        session = None
        if trigger == "console":
            session = self.platform.ids.create_session(user or "advisor-1")
            env = self.console_signer.sign({"trigger_id": "console", "kind": "user_session", "timestamp": self.platform.clock.now()})
        elif trigger == "clean-ticket":
            env = self.registry_signer.sign({"trigger_id": "clean-ticket", "kind": "subject_claim", "subject": customer, "timestamp": self.platform.clock.now()})
        else:
            env = self.portal_signer.sign({"trigger_id": "fault-ticket", "kind": "subject_claim", "subject": customer, "timestamp": self.platform.clock.now()})
        run = self.platform.run.start_run(self.release, trigger, env, {"body": ticket_body}, self.pep.workload, session_token=session)
        self.runs.append(run)
        return run

    def execute(self, run) -> str:
        return self.runtime.execute(run)

    def events(self, run) -> list[dict[str, Any]]:
        return self.platform.evs.read_unchecked(run.run_id)

    def types(self, run) -> list[str]:
        return [e["type"] for e in self.events(run)]


def policy_values(**over: Any) -> PolicyValues:
    v = PolicyValues(approval_timeout=3600, resume_window=1800, max_park=7200, rehold_maximum=3, staleness_limit=600,
                     two_approver_threshold=1000, heartbeat_deadline=60, wall_clock_budget=86400, consecutive_replays=2,
                     velocity={"agent": {"window": 3600, "limit": 50, "hard_cap": 200},
                               "subject": {"window": 3600, "limit": 6, "hard_cap": 10},
                               "destination": {"window": 3600, "limit": 4, "hard_cap": 6}},
                     degraded_caps={"effects_per_pep": 5})
    for k, val in over.items():
        setattr(v, k, val)
    return v


def build_scenario(behaviour: str = "normal", clock: Clock | None = None, policy: PolicyValues | None = None,
                   surface: str = "S2", form: str = "sidecar", tier_n4: str = "A2", ship_address_editable: bool = False,
                   internal_effect: bool = False, regulated_irreversible: bool = False, with_child: bool = False,
                   trigger: str = "fault-ticket", publish: bool = True) -> Scenario:
    """Variants: `internal_effect` prepends a no-factor, scope-anchored effect node (n0) for degradation
    tests; `regulated_irreversible` makes the shipment regulated and irreversible (two-approver path);
    `with_child` replaces the middle of the graph with a handoff to a triage agent; `trigger` selects the
    trigger the run starts from (fault-ticket, clean-ticket, console)."""
    clock = clock or Clock()
    if policy is None:
        policy = policy_values()
        if regulated_irreversible:
            policy.two_approver_threshold = 150.0
    boundary = Boundary(inside_systems={"support_portal", "device_registry", "fulfilment", "mail_relay", "identity_system", "case_log", "agent_memory", "notes", "console"},
                        resolvers={"postal_address": lambda v: False, "email": lambda v: str(v).endswith("@corp.internal")},
                        can_resolve_outside={"postal_address": True, "email": True})
    p = build_platform(boundary, policy, clock)
    reg = p.registry
    portal = SupportPortal("support_portal", p.ids)
    devices = DeviceRegistry("device_registry", p.ids)
    fulfilment = Fulfilment("fulfilment", p.ids)
    mail = MailRelay("mail_relay", p.ids)
    identity_system = System.__new__(System); System.__init__(identity_system, "identity_system", p.ids, tagging=True)
    case_log = SinkStore("case_log", p.ids)
    notes = NotesSystem("notes", p.ids)
    console = System.__new__(System); System.__init__(console, "console", p.ids)
    systems = {s.system_id: s for s in (portal, devices, fulfilment, mail, identity_system, case_log, notes, console)}
    p.systems.update(systems)
    # records
    devices.records["dev-1"] = {"device_id": "dev-1", "owner": "cust-1", "purchased": "2026-01-10"}
    devices.records["dev-9"] = {"device_id": "dev-9", "owner": "cust-2", "purchased": "2025-03-01"}
    fulfilment.records["dev-1"] = {"device_id": "dev-1", "ship_address": "12 Main St", "replacement_issued": False,
                                   "_tags": {"ship_address": "verified", "replacement_issued": "clean"}}
    identity_system.records["cust-1"] = {"customer_id": "cust-1", "email": "cust@example.com", "_tags": {"email": "verified"}}

    # capability records (A.1)
    reg.register_system(SystemCapability("support_portal", "system_of_record", external_ingress=True, presentation="per_agent"))
    reg.register_system(SystemCapability("device_registry", "system_of_record", presentation="per_agent",
                                         pip_relations={"owner": [("device_registry", "owner")]}))
    reg.register_system(SystemCapability("fulfilment", "system_of_record", provenance_tag=True, presentation="per_agent", preview_tool="preview_shipment",
                                         idempotency=True, verified_fields={"ship_address"},
                                         pip_relations={"verified_ship_address": [("fulfilment", "ship_address")], "replacement_issued": [("fulfilment", "replacement_issued")]}))
    reg.register_system(SystemCapability("mail_relay", "system_of_record", presentation="per_agent"))
    reg.register_system(SystemCapability("identity_system", "system_of_record", provenance_tag=True, presentation="per_agent", verified_fields={"email"},
                                         pip_relations={"address_on_file": [("identity_system", "email")]}))
    reg.register_system(SystemCapability("case_log", "sink_store"))
    reg.register_system(SystemCapability("notes", "system_of_record", presentation="per_agent"))
    reg.register_system(SystemCapability("console", "system_of_record", presentation="chained"))
    # tool manifests
    reg.register_tool(ToolManifest("lookup_devices", "1", "device_registry", {"device_id": "string"}, reads_data_class="confidential",
                                   parameter_roles={"device_id": "resource"}))
    reg.register_tool(ToolManifest("read_purchase", "1", "device_registry", {"device_id": "string"}, reads_data_class="confidential",
                                   parameter_roles={"device_id": "resource"}))
    reg.register_tool(ToolManifest("read_ticket", "1", "support_portal", {"ticket_id": "string"}, reads_data_class="internal"))
    reg.register_tool(ToolManifest("preview_shipment", "1", "fulfilment", {"device_id": "string", "part_sku": "string", "amount": "number", "destination": "string"},
                                   reads_data_class="internal", resource_none_justification="preview"))
    reg.register_tool(ToolManifest("ship_replacement", "1", "fulfilment", {"device_id": "string", "part_sku": "string", "amount": "number", "destination": "string"},
                                   side_effect_class="reversible_internal", writes_data_class="confidential",
                                   writes_fields=[("fulfilment", "replacement_issued")],
                                   parameter_roles={"device_id": "resource", "destination": "destination", "amount": "amount"},
                                   destination_class="postal_address", compliance_flag=regulated_irreversible,
                                   compensation="irreversible" if regulated_irreversible else {"reversing_tool": "cancel_shipment", "params": {"shipment_id": "result.shipment_id"}}))
    reg.register_tool(ToolManifest("add_note", "1", "notes", {"topic": "string", "text": "string", "priority": "number"}, side_effect_class="reversible_internal",
                                   writes_fields=[("notes", "text")], parameter_roles={"topic": "resource"},
                                   compensation={"reversing_tool": "delete_note", "params": {"note_id": "result.note_id"}}))
    reg.register_tool(ToolManifest("delete_note", "1", "notes", {"note_id": "string"}, side_effect_class="reversible_internal",
                                   writes_fields=[("notes", "deleted")], parameter_roles={"note_id": "resource"}, compensation="irreversible"))
    reg.register_tool(ToolManifest("cancel_shipment", "1", "fulfilment", {"shipment_id": "string"}, side_effect_class="reversible_internal",
                                   writes_fields=[("fulfilment", "shipment_status")], parameter_roles={"shipment_id": "resource"}, compensation="irreversible"))
    reg.register_tool(ToolManifest("send_reply", "1", "mail_relay", {"template_id": "string", "destination": "string"}, side_effect_class="external",
                                   parameter_roles={"destination": "destination"}, destination_class="email", resource_none_justification="templated reply acts on no record",
                                   compensation="irreversible"))
    reg.register_tool(ToolManifest("log_case", "1", "case_log", {"sink": "string", "content": "string"}, writes_fields=[("case_log", "content")],
                                   resource_none_justification="delivery"))
    reg.register_sanitizer(Sanitizer("proposal_extractor", "1", identifier_numeric_extractor(r"[A-Za-z]+-\d+", {"device_id": "identifier", "part_sku": "identifier", "amount": "number"}),
                                     {"device_id": "string", "part_sku": "string", "amount": "string"},
                                     {"device_id": "identifier:[A-Za-z]+-\\d+", "part_sku": "identifier:[A-Za-z]+-\\d+", "amount": "number"}))
    reg.register_sanitizer(Sanitizer("render", "1", rendering_sanitizer, {"content": "string"}, {"content": "string"}, rendering=True))
    if ship_address_editable:
        reg.register_tool(ToolManifest("update_ship_address", "1", "fulfilment", {"device_id": "string", "ship_address": "string"},
                                       side_effect_class="reversible_internal", writes_fields=[("fulfilment", "ship_address")],
                                       parameter_roles={"device_id": "resource"}, compensation="irreversible"))
    # agent, trigger, release
    reg.register_agent(Agent(AGENT, owner="owner-1", builder="builder-1", surface=surface))
    portal_signer = Signer("support-portal")
    reg.register_trigger(Trigger("fault-ticket", "support_portal", "subject_claim", signing_key=portal_signer.public(),
                                 subject_authentication="authenticated portal session", subject_schema={"subject": "customer_id"}))
    registry_signer = Signer("device-registry")
    reg.register_trigger(Trigger("clean-ticket", "device_registry", "subject_claim", signing_key=registry_signer.public(),
                                 subject_authentication="registry-side authenticated lookup"))
    console_signer = Signer("console")
    reg.register_trigger(Trigger("console", "console", "user_session", signing_key=console_signer.public()))
    A = "acting_user" if trigger == "console" else "subject"
    if trigger == "console":
        devices.records["dev-1"]["owner"] = "advisor-1"
        identity_system.records["advisor-1"] = {"customer_id": "advisor-1", "email": "cust@example.com", "_tags": {"email": "verified"}}
    nodes = [
        Node("n1", "read", tool="lookup_devices", bounds=[Bound("anchor_rel", param="device_id", rel="owner", anchor=A)]),
        Node("n2", "loop", tools=["read_ticket", "read_purchase"], step_cap=5, token_cap=200,
             bounds=[Bound("anchor_rel", param="device_id", rel="owner", anchor=A)]),
        Node("n3", "sanitize", sanitizer="proposal_extractor", tool="proposal_extractor"),
        Node("n4", "effect", tool="ship_replacement", tier=tier_n4, compensate="irreversible" if regulated_irreversible else "c1", preview=True, denial_branch="n5",
             bounds=[Bound("anchor_rel", param="device_id", rel="owner", anchor=A),
                     Bound("pred", rel="replacement_issued", param="device_id", value=False),
                     Bound("eq_rel_param", param="destination", rel="verified_ship_address", q="device_id"),
                     Bound("limit", param="amount", auto=100.0 if regulated_irreversible else 200.0, hard=1000.0)]),
        Node("n5", "effect", tool="send_reply", tier="A2", compensate="irreversible", template_param="template_id", denial_branch="n6",
             bounds=[Bound("in_scope", param="template_id", scope="templates"),
                     Bound("eq_rel_anchor", param="destination", rel="address_on_file", anchor=A)]),
        Node("n6", "output", tool="log_case", bounds=[Bound("in_scope", param="sink", scope="sinks")]),
        Node("c1", "compensate", tool="cancel_shipment", reverses="n4"),
    ]
    if regulated_irreversible:
        nodes = [n for n in nodes if n.id != "c1"]
    if internal_effect:
        nodes.insert(0, Node("n0", "effect", tool="add_note", tier="A2", compensate="c0", denial_branch="n1",
                             bounds=[Bound("in_scope", param="topic", scope="topics")]))
        nodes.append(Node("c0", "compensate", tool="delete_note", reverses="n0"))
    if with_child:
        child_agent = "triage-agent"
        reg.register_agent(Agent(child_agent, owner="owner-2", builder="builder-2", surface=surface))
        nodes = [Node("n1", "read", tool="lookup_devices", bounds=[Bound("anchor_rel", param="device_id", rel="owner", anchor="subject")]),
                 Node("h1", "handoff", tool=f"agent:{child_agent}", target_agent=child_agent),
                 Node("n6", "output", tool="log_case", bounds=[Bound("in_scope", param="sink", scope="sinks")])]
    release = Release(AGENT, "1.0", surface, form, "pep-1.0", nodes,
                      tools={n.tool: "1" for n in nodes if n.tool}, scopes={"templates": ["tpl-shipped", "tpl-denied"], "sinks": ["case-log"], "recipients": [], "topics": ["warranty"]},
                      model_route=["model-a"])
    entitlements = {AGENT: {"tools": [t for t in reg.tools], "systems": list(systems), "agents": [f"agent:triage-agent"]}}
    if with_child:
        entitlements["triage-agent"] = {"tools": ["read_ticket"], "systems": ["support_portal"], "agents": []}
    bundle = PolicyBundle("1", policy, entitlements=entitlements, recipient_clearance={"cust-1": "confidential"})
    p.publish_bundle(bundle)
    p.ids.allow_build(BUILD, form)
    p.ids.allow_build(BUILD + "-sdk", "sdk")
    p.ids.issue_agent_identity(AGENT)
    if publish:
        reg.publish_release(release, policy, {"pep-1.0"})
    pip = WarrantyPIP(devices, fulfilment, identity_system)
    p.set_pip(pip)
    pep = p.pep("wl-1", form, surface, BUILD, AGENT)
    p.ops.republish_stop_list()
    model = WarrantyModel(behaviour=behaviour)
    rt = Runtime(pep, p.run, model)
    sc = Scenario(p, release, pep, rt, model, systems, pip, portal_signer, bundle, trigger_id=trigger,
                  console_signer=console_signer, registry_signer=registry_signer)
    if with_child:
        _wire_child(sc, "triage-agent", surface, form, policy)
    return sc


class NotesSystem(System):
    def __init__(self, system_id: str, ids: Any) -> None:
        super().__init__(system_id, ids)
        self._n = 0

    def apply(self, tool: str, params: dict[str, Any], tag: str | None) -> dict[str, Any]:
        if tool == "add_note":
            self._n += 1
            nid = f"note-{self._n}"
            self.records[nid] = {"note_id": nid, **params}
            return {"note_id": nid}
        if tool == "delete_note":
            self.records.pop(params["note_id"], None)
            return {"deleted": params["note_id"]}
        raise NotImplementedError(tool)


class ChildModel:
    def propose(self, run, node: Node, ctx: dict[str, Any]) -> dict[str, Any]:
        return {"ticket_id": "t-1"}


def _wire_child(sc: Scenario, child_agent: str, surface: str, form: str, policy: PolicyValues) -> None:
    """The triage agent: one read of the support portal (external ingress), so the child returns exposed."""
    p = sc.platform
    child_release = Release(child_agent, "1.0", surface, form, "pep-1.0",
                            [Node("t1", "read", tool="read_ticket")], tools={"read_ticket": "1"}, model_route=["model-a"])
    p.ids.issue_agent_identity(child_agent)
    p.registry.publish_release(child_release, policy, {"pep-1.0"})
    child_pep = p.pep("wl-child", form, surface, BUILD, child_agent)
    child_rt = Runtime(child_pep, p.run, ChildModel())
    sc.child = {"release": child_release, "pep": child_pep, "runtime": child_rt, "runs": []}

    def launcher(parent, inputs, as_service, run):
        child = run.start_run(child_release, "child", {}, inputs, "wl-child", parent=parent, as_service=as_service)
        sc.child["runs"].append(child)
        child_rt.execute(child)
        return child

    p.registry.agents[child_agent].launcher = launcher
