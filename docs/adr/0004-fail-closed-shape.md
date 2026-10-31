# ADR 0004 — How outages are expressed in the PEP

**Status:** accepted (0.1.0)

## Context

Section 6.1 fixes, per component outage, what continues. The PEP is where most of that is decided at call time, and the specification distinguishes PEP-E (which may continue on local checkpoints, local counters, and a journal) from PEP-P (which stops).

## Decision

The PEP calls each component through its contract and catches `Unavailable` at the point where the matrix says something different happens:

- **EVS down** — `_write` appends to the signed journal instead; `_evidence` reads EVS plus the journal; `reconcile` replays the journal in order with a `journal.reconciled` event.
- **PDP down** — `_decide` falls back to `_local_decide`, which allows only what 6.1 allows (scope-anchored, no-factor, not exposed, not delegated, cached bundle, list not stale, degraded cap) and raises `Unavailable("PDP")` for everything else so the run parks; compensation and replay evaluate the terminal rules locally.
- **RUN down** — PEP-E keeps a local checkpoint and local entered set (`enter_node`/`exit_node`), counts effects locally with the degraded cap (`_effect`), and journals state updates; PEP-P re-raises.
- **IDS down** — no credential: the PEP records `effect.failed` with `error = not_executed` (it knows nothing was sent) and re-raises, so the run parks and the node is not in doubt on recovery.
- **PIP down** — the PDP raises `Unavailable("PIP")`; the PEP does not try local evaluation of a PIP-anchored bound.

RUN, for its part, catches `Unavailable` from IDS at hold (park, timers suspended) and at resume after an approval (park with the approval recorded).

## Consequences

- The runtime never needs to know which component failed; it parks on `Unavailable` and resumes on `recover`.
- "Down" is binary. Partial degradation (slow, flapping) is not modelled.
- Local counters are per PEP process, as the specification says; a deployment with many PEP-E instances gets the cap per instance, which is why the degraded cap is tighter than the normal limits.
