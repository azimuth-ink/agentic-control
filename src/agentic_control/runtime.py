"""A governed runtime for the embedded form (spec 4.1, 4.2, 4.6, A.5 hook contract).

Executes a release's forward nodes in topological order. The model fills parameters inside read,
loop, effect and output nodes and never decides whether an effect happens; every call goes through
the PEP. Holds stop the walk; the walk continues at the checkpointed next node after RUN resumes."""
from __future__ import annotations

from typing import Any, Callable, Protocol

from .common import Denied, Unavailable
from .coordinator import Run, RunCoordinator
from .dbs import Indeterminate
from .enforcement import EnforcementPoint, Held, NodeFailed
from .release import Node


class Model(Protocol):
    """What the runtime asks the model for. `propose` returns the parameters for a node's tool; for a loop
    node it returns {"call": tool_id, "params": {...}} per iteration or {"done": True, "proposal": {...}}."""

    def propose(self, run: Run, node: Node, context: dict[str, Any]) -> dict[str, Any]: ...


class Runtime:
    def __init__(self, pep: EnforcementPoint, run: RunCoordinator, model: Model, model_name: str = "model-a") -> None:
        self.pep = pep
        self.run = run
        self.model = model
        self.model_name = model_name
        self.trace: list[tuple[str, str]] = []

    def execute(self, run: Run) -> str:
        """Walks the graph from the checkpointed next node until the run leaves RUNNING."""
        while run.state == "RUNNING" and run.next_node is not None:
            node = run.release.node(run.next_node)
            try:
                self._step(run, node)
            except Held:
                self.trace.append((node.id, "held"))
                return run.state
            except NodeFailed:
                self.trace.append((node.id, "failed"))
                continue
            except Denied as e:
                self.trace.append((node.id, f"denied: {e}"))
                if run.state == "RUNNING" and run.next_node == node.id:   # the PEP could not move the checkpoint (RUN down)
                    run.next_node = node.denial_branch
                if run.state == "RUNNING" and run.next_node is None:
                    try:
                        self.run._complete(run)
                    except Unavailable:
                        pass
                continue
            except Indeterminate:
                self.trace.append((node.id, "indeterminate"))
                try:
                    self.run.resolve_in_doubt(run, node.id)
                except Unavailable:
                    pass
                if run.state == "RUNNING" and node.id in run.exited:
                    continue
                return run.state
            except Unavailable as e:
                self.trace.append((node.id, f"unavailable: {e.component}"))
                try:
                    self.run.park(run, f"{e.component} unavailable")
                except Unavailable:
                    run.state = "PARKED"
                    run.park = {"reason": f"{e.component} unavailable", "resolver": "oncall-resolver", "deadline": None, "recoverable": True, "from": "RUNNING"}
                return run.state
        return run.state

    def _step(self, run: Run, node: Node) -> None:
        ctx = {"outputs": run.outputs, "subject": run.subject}
        self.pep.enter_node(run, node, {"node": node.id})
        self.trace.append((node.id, "entered"))
        if node.type == "human":
            self.run.input_hold(run, node)
            raise Held(node.id)
        if node.type == "loop":
            result = self._loop(run, node, ctx)
        elif node.type == "sanitize":
            inp = self.model.propose(run, node, ctx)
            result = self.pep.call(run, node, node.sanitizer, inp)
        elif node.type in {"read", "effect", "output", "handoff", "service"}:
            params = self.model.propose(run, node, ctx)
            tool = params.pop("__tool__", node.tool)
            result = self.pep.call(run, node, tool, params)
        else:
            raise Denied(f"compensate nodes run only on RUN's instruction: {node.id}")
        self.pep.exit_node(run, node, result)
        self.trace.append((node.id, "exited"))

    def _loop(self, run: Run, node: Node, ctx: dict[str, Any]) -> Any:
        """Open-ended planning inside the loop: read-only tools under a step cap and a token cap; what the
        loop concludes is a parameter proposal for a later effect node."""
        iterations = 0
        while True:
            iterations += 1
            try:
                self.pep.model_call(run, node, self.model_name, f"iteration {iterations}", tokens=50)
            except Denied:
                break   # token cap reached: the PEP refused the node's next model credential
            step = self.model.propose(run, node, {**ctx, "iteration": iterations})
            if step.get("done"):
                return step.get("proposal", {})
            try:
                out = self.pep.call(run, node, step["call"], step.get("params", {}))
            except Denied as e:
                if "cap" in str(e):
                    break
                out = {"denied": str(e)}   # a denied read inside the loop is a failed call the model sees
            ctx.setdefault("loop_results", []).append(out)
        return ctx.get("last_proposal") or self.model.propose(run, node, {**ctx, "capped": True}).get("proposal", {})
