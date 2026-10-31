"""MGW, the Model Gateway (spec A.8), and OPS, Operations Control (A.9)."""
from __future__ import annotations

from typing import Any, Callable

from .common import Availability, Denied, Refused, new_id
from .crypto import Signer, TrustStore
from .policy import Stop, StopList


class ModelGateway(Availability):
    name = "MGW"

    def __init__(self, ids: Any, run: Any, models: dict[str, Callable[[str], str]], region: str = "pinned-region") -> None:
        self.ids = ids
        self.run = run
        self.models = models
        self.region = region
        self.budgets: dict[str, int] = {}       # agent -> tokens used this period
        self.log: list[dict[str, Any]] = []

    def complete(self, credential: dict[str, Any], presenter: str, run_obj: Any, node_id: str, model: str,
                 prompt: str, tokens: int) -> tuple[str, bool]:
        """Routes only within the release's declared route; accepts only a per-node model credential
        presented by a PEP; attributes tokens to run and node; reports usage to RUN."""
        self._check()
        if not self.ids.verify_credential(credential, presenter, "MGW"):
            raise Denied("model credential rejected")
        c = credential["payload"]
        if c["purpose"] != "model" or c["run"] != run_obj.run_id or c["node"] != node_id:
            raise Denied("model credential is per node")
        if model not in run_obj.release.model_route:
            raise Denied(f"model {model} is outside the release's declared route")
        budget = self.run.policy.token_budget_per_agent
        used = self.budgets.get(run_obj.agent_id, 0)
        if used + tokens > budget:
            raise Denied("agent token budget exhausted")
        self.budgets[run_obj.agent_id] = used + tokens
        text = self.models[model](prompt)
        cap = self.run.record_usage(run_obj, node_id, tokens, model)
        self.log.append({"run": run_obj.run_id, "node": node_id, "model": model, "tokens": tokens, "region": self.region})
        return text, cap


class Operations:
    name = "OPS"

    def __init__(self, run: Any, pdp: Any, ids: Any, evs: Any, trust: TrustStore, clock: Any, validity: float = 600.0) -> None:
        self.run = run
        self.pdp = pdp
        self.ids = ids
        self.evs = evs
        self.clock = clock
        self.signer = Signer("OPS")
        trust.trust(self.signer, "ops")
        self.validity = validity
        self.sequence = 0
        self.stops: list[Stop] = []
        self.peps: list[Any] = []
        self.drills: list[dict[str, Any]] = []
        self.incidents: list[dict[str, Any]] = []

    def register_pep(self, pep: Any) -> None:
        self.peps.append(pep)

    def _publish_list(self) -> None:
        self.sequence += 1
        sl = StopList(self.sequence, self.clock.now(), self.validity, list(self.stops))
        signed = self.signer.sign(sl.to_dict())
        self.pdp.distribute_stop_list(signed, sl)
        for pep in self.peps:
            pep.update_stop_list(signed, sl)

    def republish_stop_list(self) -> None:
        """Re-signs the current list with a fresh validity period (the normal heartbeat of the channel)."""
        self._publish_list()

    def issue_stop(self, scope_kind: str, scope_value: str | None = None, issued_by: str = "ops-oncall") -> Stop:
        """Issues a stop into RUN's register and signs the stop list with a sequence number and validity."""
        if scope_kind not in {"agent", "tool", "surface", "fleet"}:
            raise Refused("stop scope is agent, tool, surface, or fleet")
        self.sequence += 1
        stop = Stop(new_id("stop"), scope_kind, scope_value, self.sequence)
        self.stops.append(stop)
        rec = {"stop_id": stop.stop_id, "scope_kind": scope_kind, "scope_value": scope_value, "sequence": stop.sequence}
        self.run.record_stop(rec)
        self.evs.append({"type": "stop", "scope": f"{scope_kind}:{scope_value}", "sequence": stop.sequence,
                         "issued_by": issued_by, "validity": self.validity})
        self._publish_list()

        def in_scope(r: Any) -> bool:
            return StopList(0, 0, 0, [stop]).in_scope(r.agent_id, None, r.surface) is not None or (
                scope_kind == "tool" and any(n.tool == scope_value for n in r.release.nodes))
        self.run.apply_stop(rec, in_scope)
        return stop

    def lift_stop(self, stop_id: str) -> None:
        self.stops = [s for s in self.stops if s.stop_id != stop_id]
        self.run.lift_stop(stop_id)
        self._publish_list()

    def approve(self, run_obj: Any, node_id: str, approver: str) -> dict[str, Any]:
        """The approver decides through OPS, authenticated by the identity provider."""
        assertion = self.ids.approver_assertion(approver)
        return self.run.approve(run_obj, node_id, approver, assertion)

    def deny(self, run_obj: Any, node_id: str, approver: str) -> dict[str, Any]:
        return self.run.deny(run_obj, node_id, approver)

    def recovery(self, identity: str, two_approvers: tuple[str, str], incident: str, actions: list[str]) -> dict[str, Any]:
        """Every recovery release opens an incident; actions are recorded as recovery.used."""
        cred = self.ids.release_recovery_identity(identity, two_approvers, incident)
        self.incidents.append({"incident": incident, "identity": identity, "actions": actions})
        self.evs.append({"type": "recovery.used", "scope": "recovery", "identity": identity, "releasers": sorted(two_approvers),
                         "incident_id": incident, "actions_ref": self.evs.payloads.put(actions)})
        return cred

    def drill(self, kind: str) -> None:
        self.drills.append({"kind": kind, "at": self.clock.now()})
