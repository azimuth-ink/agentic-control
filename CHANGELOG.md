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
- Conformance suite F1–F9 plus review regressions (134 tests) with `@spec` markers; unit tests (20); `tools/conformance_report.py --check` in CI.

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

### Added after the first review
- REG row of 6.1: the PEP caches manifests with a time to live and continues on them during a REG outage; registrations and releases are refused.
- Live schema-hash check (A.1, I5): a tool server's advertised schema or description that differs from the manifest unregisters the tool, denies the call, and fails the dependent release's lint until re-registration.
- S1 proxy form: RUN writes `node.entered` and `node.exited` from the platform hooks; PEP-P writes call-level events only.
- `external.imported` for logs from ungoverned surfaces (section 7); the access review of A.1 (`Registry.access_review`).
- MGW outage and declared-route tests; the agent token budget test.

### Found by the first independent code review and fixed before this version
- Factored, exposed, or delegated effects executed during an EVS or RUN outage; the 6.1 gate (no factor, neither exposed nor delegated, scope-anchored under RUN) is now applied in the PEP before any reservation, and reads of `restricted` data stop under every outage.
- Local evaluation under a PDP outage skipped constant predicates (`op` bounds) and the bundle's entitlements.
- A substitution resubmitted the request with the revoked user as acting user; the chain now carries the approver with the original user as `requested_principal`.
- A replay whose credential was refused or unavailable wrote `effect.failed` for the original action hash and took the node out of doubt; nothing is written when nothing was sent, a replay the system refuses is recorded with `purpose = replay` and keeps the node in doubt, and `resolve_in_doubt` replays up to the count then parks (never resumes with the node unresolved).
- `not_executed` and `cancelled_effects` were never cleared, so a later recovery could re-execute a node; cleared when the hook accepts the re-entry.
- `deny` had none of `approve`'s guards; both now require an open hold and an approver in the set, and both are accepted while PARKED (recorded and applied on recovery, per A.2).
- Reads, previews, deliveries, and DBS stores presented no credential; every call through the PEP now carries one and the reference systems refuse one without (I1).
- `checkpoint` accepted a node that was never entered, so a `human` node could be skipped; RUN now opens the input hold on the hook and refuses checkpoints without it.
- Model calls bypassed the run-state, hook, and node-type checks.
- Parameters that did not fit the manifest schema reached the PDP's comparisons (a `TypeError` out of `decide`); a schema mismatch is now a recorded denial before reservation, and a decision that raises releases its reservation.
- Suspended time before an approval was credited against the resume window (RUN and IDS).
- The PDP honoured `causes_discharged` from an unverified approval record; the record must verify under RUN's key for the same action hash.
- A missing rendering sanitizer raised `StopIteration`; a stop cancelled input holds with an `effect.failed`; a preview failing on an outage broke the hold.

### Known gaps (deferred with the specification's v1.1 list, section 11)
- `approval_records[]` in the IDS contract and the two-approver substitution rule.
- The rendering sanitizer as a PEP-applied obligation rather than a tool.
- The per-agent token budget is applied at MGW without a period rotation (the specification says "per period"; the period is policy content).
- Park and escalation deadlines as policy values (constants on RUN here).
