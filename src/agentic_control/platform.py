"""Wiring: one call builds the control plane with its nine components, a trust store, and a clock."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .common import Clock
from .coordinator import RunCoordinator
from .crypto import Signer, TrustStore
from .dbs import DLP, System
from .enforcement import EnforcementPoint
from .evidence import EvidenceStore
from .gateway import ModelGateway, Operations
from .identity import IdentityService
from .policy import PIP, PolicyBundle, PolicyDecisionPoint
from .registry import Boundary, PolicyValues, Registry


@dataclass
class Platform:
    clock: Clock
    trust: TrustStore
    boundary: Boundary
    registry: Registry
    evs: EvidenceStore
    ids: IdentityService
    pdp: PolicyDecisionPoint
    run: RunCoordinator
    mgw: ModelGateway
    ops: Operations
    dlp: DLP
    policy: PolicyValues
    systems: dict[str, System]
    peps: dict[str, EnforcementPoint]

    def pep(self, workload: str, form: str, surface: str, build_hash: str, agent_id: str) -> EnforcementPoint:
        """Creates a PEP for a hosting workload, attests it to IDS, loads the bundle and stop list."""
        p = EnforcementPoint(workload, form, surface, build_hash, self.registry, self.pdp, self.run, self.ids, self.evs,
                             self.clock, self.trust, self.systems, self.dlp, self.mgw)
        p.bind(agent_id)
        if self.pdp.signed_bundle and self.pdp.bundle:
            p.load_bundle(self.pdp.signed_bundle, self.pdp.bundle)
        if self.pdp.signed_stop_list and self.pdp.stop_list:
            p.update_stop_list(self.pdp.signed_stop_list, self.pdp.stop_list)
        self.ops.register_pep(p)
        self.peps[workload] = p
        return p

    def publish_bundle(self, bundle: PolicyBundle) -> None:
        signed = self.pdp.publish_bundle(bundle)
        for p in self.peps.values():
            p.load_bundle(signed, bundle)

    def set_pip(self, pip: PIP) -> None:
        self.pdp.pip = pip

    def outage(self, component: str, down: bool = True) -> None:
        """Degradation toggle for tests: component ∈ {EVS, PDP, RUN, IDS, REG, MGW, PIP}."""
        target = {"EVS": self.evs, "PDP": self.pdp, "RUN": self.run, "IDS": self.ids, "REG": self.registry, "MGW": self.mgw}.get(component)
        if component == "PIP":
            if down:
                self._pip_saved = self.pdp.pip
                self.pdp.pip = None
            else:
                self.pdp.pip = getattr(self, "_pip_saved", None)
            return
        assert target is not None, component
        if component == "RUN":
            if down:
                self.run.outage_window = [self.clock.now(), None]
            else:
                self.run.outage_window[1] = self.clock.now()
                target.available = True
                self.run.mark_outage_end()
                return
        target.available = not down


def build_platform(boundary: Boundary, policy: PolicyValues | None = None, clock: Clock | None = None,
                   models: dict[str, Callable[[str], str]] | None = None, stop_validity: float = 600.0) -> Platform:
    clock = clock or Clock()
    policy = policy or PolicyValues()
    trust = TrustStore()
    registry = Registry(boundary)
    evs = EvidenceStore(clock)
    ids = IdentityService(registry, clock, policy, trust)
    pdp = PolicyDecisionPoint(registry, clock, trust, Signer("policy-authority"))
    run = RunCoordinator(registry, ids, evs, clock, policy, trust)
    mgw = ModelGateway(ids, run, models or {"model-a": lambda prompt: f"[model-a] {prompt}"})
    ops = Operations(run, pdp, ids, evs, trust, clock, validity=stop_validity)
    dlp = DLP()
    return Platform(clock, trust, boundary, registry, evs, ids, pdp, run, mgw, ops, dlp, policy, {}, {})
