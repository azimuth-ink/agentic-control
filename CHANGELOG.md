# Changelog

## 0.1.0 — first cut (unreleased)

Reference implementation of the Agentic Control Architecture v1.0 (internal specification 1.17).

### Added
- Nine components with the Appendix A contracts, in one process with injected time (ADR 0001, 0003).
- Ed25519 envelopes with a role-keyed trust store; Fernet-sealed resumption grants (ADR 0002).
- The evidence schema of Appendix D with required-field validation; a hash-chained evidence store with payload erasure and a witness hook; the PEP journal and in-order reconciliation.
- The release linter, derived trust fields, anchor capability with REG refusal and release suspension, factor derivation.
- The PDP evaluation order of A.3, including compensation and replay as terminal rules, the exposure rule, delivery recipient clearance, and the re-hold maximum.
- RUN: hooks and checkpoints, counters (reserve/release/confirm/reconcile), holds with grants and substitution, parks and recovery with timer suspension, effects in doubt with bounded replay and resolver outcomes, stops, escalation and the OPS close on the owner's deadline, child runs.
- The PEP's per-call duties and degraded modes (ADR 0004); deliveries with the rendering sanitizer; spawns; RUN-instructed previews, resumes, compensations and replays.
- The section-8 warranty flow as a runnable example with adversarial model behaviours and graph variants.
- Conformance suite F1–F9 (112 tests) with `@spec` markers; unit tests (20); `tools/conformance_report.py --check` in CI.

### Found by the conformance suite and fixed before this version
- A replacement PEP recomputed parameter provenance from a process-local set and so held an already-sanitized parameter for exposure; provenance is now rebuilt from the run's `sanitize.result` evidence.
- The host-lost timer kept running through a hold; it now restarts whenever a run returns to RUNNING.
- `RUN.approve` raised when IDS was unreachable; the approval is now recorded and the run parks with timers suspended, resuming on recovery.
- `hold()` and the IDS-at-hold path set `held_before_park` before `_park` cleared it; a recovered run returned to RUNNING instead of HELD.
- `substitution_only` was set on the hold after its `hold.created` event had been written.
- Effects under a RUN outage were counted twice against the degraded cap.
- RUN could not rebuild velocity windows after losing them; decision events now carry the reservation keys and `reconcile_counters` rebuilds from executed effects.
- The PDP looked up the compensation mapping on the reversing tool's manifest instead of the reversed effect's, so every compensation was denied.
- A run started under a current stop ran its reads and completed on denial branches; `start_run` now refuses, and a PEP-local stop refusal parks the run at that node (or cancels it if no effect node was entered). `lift_stop` now reaches RUN's register.
- An IDS refusal (lapsed identity, unbound workload, form mismatch) propagated out of the PEP as an exception; it is now `effect.failed` with `error = revoked` and the failure branch, and a refused model credential ends the loop.
- A PIP outage surfaced as a PDP denial and the run completed on the denial branch; it now parks.
- A credential unavailable before the call left the node in doubt on recovery; the PEP now records `effect.failed` with `error = not_executed`.
- `derive_factors` added `irreversible` to read-only tools from the manifest's default compensation value.
- An undeclared tool was refused structurally without a decision event; node declaration is now recorded as the first rule.

### Known gaps (deferred with the specification's v1.1 list, section 11)
- `approval_records[]` in the IDS contract and the two-approver substitution rule.
- The rendering sanitizer as a PEP-applied obligation rather than a tool.
- Per-agent token budget enforcement (`spend_to_date` is recorded, not capped).
- Park and escalation deadlines as policy values (constants on RUN here).
