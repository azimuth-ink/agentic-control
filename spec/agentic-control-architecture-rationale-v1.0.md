# [Title]: Design Rationale

**v1.0, companion to the specification at internal version 1.17. CC0 1.0 Universal.**

Records the six core decisions as taken, the implementation decisions made while writing and repairing the specification, how each severe finding of the earlier review that motivated the architecture is addressed, the sixteen-round verification record, and what remains weak. Section references are to the specification's v1.0 numbering (body sections 0 to 11, appendices A to D).

Naming: **Dn** is a core decision (specification section 1), **ADR-n** an implementation decision recorded here, **R-n** a declared residual in the specification's section 9.

---

## Part A: Core decisions as taken

All six were settled on 9 October 2026 from a decision document that set out the problem, the invariants, and the options for each. D2 and D5 were the author's choices against the document's recommendation set; D1, D3, D4, and D6 proceeded on its recommendation.

| | Decision | Where it lands in the spec |
|---|---|---|
| D1 | Hybrid enforcement by surface | Two PEP forms with one contract (A.4); surface table (7); S3, S5, and S4 without PEP-E declared ungoverned |
| D2 | Graph with bounded loop nodes | Node types (4.2); effect nodes and bounds (4.3); loops hold the model's freedom and effects hold the decision (4.6); checkpoints make holds resumable (A.5) |
| D3 | Per-agent downstream credentials, chained where supported | Presentation table (A.2); PIP entitlement check for `per_agent` systems (A.3); credential binding (A.4) |
| D4 | Resumption grant, approver fallback | Grant lifecycle (A.2); substitution at approval or via a new hold (A.2) |
| D5 | Tiered fail-closed | Degradation matrix (6.1); what never degrades (6.2); recovery identities as the declared exception to I1 and I3 (6.3) |
| D6 | Taint follows data, sanitizers clear it | Sources, propagation, sanitizers, policy effect (5); derived trust fields (A.1) |

---

## Part B: Implementation decisions

### ADR-1. Split enforcement into a decision point and enforcement points

PDP evaluates; PEPs enforce; policy bundles and stop lists are signed and distributable. **Rejected:** a monolithic gateway. **Why:** hybrid-by-surface needs more than one enforcement form; one decision engine keeps them consistent; distributable bundles make the PDP-down row possible. **Tradeoff:** two PEP forms needing a conformance suite. **Forecloses:** policies that depend on state only a central proxy could see.

### ADR-2. A central Run Coordinator distinct from the agent runtime

RUN owns lifecycle state, checkpoints, holds, parks, counters, the stop register, and approved-action records; runtimes execute nodes and integrate through a hook contract. **Rejected:** run state inside each runtime; a platform hosting its own RUN. **Why:** three of the five severe findings were about state nobody owned, and a platform-hosted RUN would hold every grant. **Tradeoff:** a new critical service; platforms must implement hooks. **Forecloses:** A1 and A2 on any runtime that cannot checkpoint. Added in the publication rounds: RUN rejects an out-of-order `node_entered` hook; a `handoff` or `service` node with a live child is never re-spawned on restart; OPS closes an escalated run on the owner's deadline with a recorded disposition, so no run waits forever on one person (rounds fourteen to sixteen).

### ADR-3. Factors derived from tool manifests, never declared by the builder

**Rejected:** builder self-declaration at intake. **Why:** classification once per tool by qualified people. **Tradeoff:** every tool needs a manifest; schema-hash drift unregisters it. During verification this was extended: `untrusted_source`, `agent_writable`, `delivery`, `internal_store`, and `spawn` are all derived, so no owner can register a risky thing as safe.

### ADR-4. Bounds anchor to the subject, the acting user, or a registered scope

**Rejected:** runtime-supplied identifiers from content. **Why:** the difference between a bound and a suggestion. **Tradeoff:** triggers must authenticate and sign a subject; agents started by unauthenticated triggers have no subject-scoped bounds. Verification added the bound grammar, the equality-or-membership rule, anchor backing, and continuous anchor capability (ADR-20).

### ADR-5. Velocity counters as policy inputs, reserved before the decision

**Rejected:** per-action limits with sampling only; snapshot-then-reserve. **Why:** in-bounds abuse at scale; concurrent decisions must see each other. **Tradeoff:** stale under degradation, so factored effects stop. Counters are never bounds; a breach holds.

### ADR-6. Compensation is deterministic, declared at release, executed by the PEP on RUN's instruction

**Rejected:** compensation as agent tool calls (blocked by stops); human runbook only; per-action approval; RUN presenting credentials. **Why:** approved at release; the model is removed from recovery; only a PEP presents credentials. **Tradeoff:** builders write the reverse of every effect; `irreversible` carries a factor.

### ADR-7. Workload binding, with the platform trusted to assert the agent and node

**Tradeoff:** a compromised multi-tenant platform exposes every agent it hosts (residual R-1). PEP-E builds are attested and allow-listed with their form; IDS refuses a credential when a release's declared form or surface disagrees with the attestation.

### ADR-8. Resumption grants held by RUN, redeemed after the decision is written

**Rejected:** long-lived refresh tokens; re-prompting the user; substitution as the only mechanism. Verification added: no clock inside the grant (IDS computes expiry from RUN-signed timer state); suspension while parked up to `max_park`; approved-action records in RUN; replacement instances resume before the decision or go to in-doubt after it.

### ADR-9. Every call passes through the PEP, including reads, retrieval, memory, sanitizers, previews, deliveries, spawns, and model calls

**Rejected:** gating writes only; runtime self-reporting of run state. **Why:** exposure and data-class state must be derived by something on the path. **Tradeoff:** the PEP is on every read's latency path; run-state updates are acknowledged at RUN before results are released, which closes a crash window at the cost of a round trip per call.

### ADR-10. Taint carried as a field-level provenance tag, with derived trust for systems that cannot carry one

**Rejected:** run-scoped taint. **Why:** the laundering finding. **Tradeoff:** heavy over-marking on untagged systems. Verification extended it to triggers (envelope trusted, payload derived), derived stores (lineage through `sources[]` with feed review), sink stores and memory (writable and tagged by definition), platform-native stores, and child returns.

### ADR-11. Evidence per event, witnessed externally, verified independently

**Rejected:** one record per run; operator-verified chains. **Tradeoff:** witnessing cost; the PEP as writer can still omit, mitigated by RUN's own hook records and reconciliation.

### ADR-12. Recovery identities as the declared exception to I1 and I3

**Rejected:** pretending nothing bypasses the enforcement point. **Tradeoff:** systems must recognize a second credential class; the recovery identity is the one worth attacking.

### ADR-13. A0 defined structurally, enforced by the linter and the runtime matrix

A0 is a graph with no effect nodes; the fast path additionally requires nothing above `internal`, no spawn nodes; the rendering sanitizer is imposed on every delivery of an exposed run.

### ADR-14. Surfaces S3, S5, and S4 without PEP-E declared outside the architecture

An honest gap with an owner beats a claimed control that does not exist.

### ADR-15. Subject is not a principal

A `subject_claim` trigger carries whom the run is *about* in a signed envelope; the run acts under the agents' authority alone. An acting user exists only for `user_session` triggers and for one action on substitution. **Rejected:** the customer in the principal chain, which made a strict intersection deny every action on the subject's own records. **Forecloses:** treating a subject's own entitlements as a check; the subject's protection comes from anchored bounds instead.

### ADR-16. Hold causes are explicit and cumulative

A hold names every cause; an approval discharges exactly those; a re-hold carries only new causes and keeps the discharged set; a policy maximum on re-holds bounds every loop. **Rejected:** an approval discharging only the limit band (livelocked A1 and velocity holds); invalidating the whole record on re-hold (alternating causes livelocked).

### ADR-17. In doubt is defined over the latest decision for the effect's own action hash

A node is in doubt when its latest `purpose = normal` decision is `ALLOW` and there is no `effect.*` event or the latest one is `effect.indeterminate`. Replay and compensation decisions carry the same hash and are excluded from the test (round fourteen); the latest-event wording stops a successfully replayed node from re-parking (round fifteen); consecutive indeterminate replays are bounded by policy. The PEP writes `effect.failed` only on a definitive negative and `effect.indeterminate` otherwise. A node with no decision in reconciled evidence may be re-entered (I3). Replay accepts an indeterminate. **Rejected:** "any decision" (a resumed node was never in doubt); binary executed-or-failed (a timeout took a node out of doubt and allowed double execution).

### ADR-18. RUN's checkpoint is an admitted source for compensation

The PEP supplies each effect's recorded parameters and result to RUN with `confirm`; RUN signs the copy; the PDP verifies against it when EVS is unreachable. **Tradeoff:** an unconfirmed in-doubt effect from a dead instance still waits on journal recovery.

### ADR-19. Reversal and replay authority belongs to the agent and the release

Compensation and replay credentials carry the original chain as a record, not as live delegation, so an action a user authorised can be undone or completed after their session ends. **Tradeoff:** a replay after a revocation that the PEP never recorded (a narrow race) proceeds on that authority.

### ADR-20. Anchor capability is a continuously maintained REG property

Every PIP relation is registered with its backing fields; capability follows `sources[]` lineage and manifests' `writes_fields[]`; REG refuses registrations that would break a published release's anchors and suspends releases on changes it cannot refuse; the PDP checks the release's anchor version at decision time. **Rejected:** a one-time linter join. **Why:** an agent-written field could become an anchor after publication.

### ADR-21. Node-type matrix enforced at lint and at runtime

Each tool class may be called only from named node types; the PDP denies any call to a tool the node does not declare. **Why:** a sink or agent tool callable from a read node evaded delivery and spawn decisions.

### ADR-22. Stop list signed by OPS, distributed by PDP, held by every PEP, with staleness as a stop

**Rejected:** stop state in a stateless PDP; RUN as the signer (its outage would have stopped the fleet). Compensation and replay are outside stop scope (residual R-16).

### ADR-23. Tiered degradation by factor, exposure, delegation, and anchor type

No-factor effects on non-exposed, non-delegated runs with scope-only anchors continue under most outages; everything else stops. Compensation and replay degrade open against EVS, PDP, and PIP but not RUN or IDS (R-5).

### ADR-24. A declared residual register inside the specification

Nineteen residuals in v1.0, each with where it is declared and what bounds it. **Why:** reviewers kept re-finding risks the author had accepted silently; writing them down stops the cycle and makes acceptance a decision with an owner.

### ADR-25. A tool that sends its parameters outside the trust boundary is an effect

REG refuses `side_effect_class = none` for a tool whose target system is outside the boundary definition or whose `parameter_roles` declare a `destination` that can resolve outside; such a tool carries an effect class, derives the `external` factor, and for every destination-keyed rule its registered target counts as the anchored destination. **Rejected:** treating external lookups as reads governed only by the taint on their returns. **Why:** round thirteen showed an exposed run could carry confidential data out in a read tool's query; round fourteen showed the same one hop further through an internal fetch proxy; the definition of effect already said that sending data outside is an effect, and nothing enforced it. **Tradeoff:** a read of a system outside the trust boundary is an effect node, never a `read` or `loop` node; it defaults to A1, is `irreversible` unless a reversing tool exists, and a system outside the boundary has no preview tool. Open-ended research against external sources therefore cannot happen inside a loop node. **Deferred to v1.1:** a compensation value for tools whose only side effect is the egress of their parameters, so that cancelling a run that performed an external read does not need an owner close.

### ADR-26. DBS-managed stores, interfaces, and recipient roles are confined inside the trust boundary

REG refuses `kind = interface`, `sink_store`, `memory`, or `derived_store` for a system outside the boundary definition; `provenance_tag` is not registrable for a system outside it; a recipient role resolves only to principals inside it. **Why:** deliveries and decided non-effect writes are not effects, so they carry no `external` factor and no `dlp_check`; the only way to keep that true is to keep their targets inside (rounds fifteen and sixteen). **Tradeoff:** a messaging surface hosted outside the boundary cannot be a delivery target; reaching it is an effect.
---

## Part C: Traceability to the earlier review's severe findings

The architecture was written in response to an adversarial review of a predecessor guide, conducted from the viewpoints of fifteen enterprise functions. The fifteen severe findings of that review, and where each lands:

| Finding | Addressed by | Residual |
|---|---|---|
| 1. Injection launderable through service requests and system-of-record writes | Taint follows data (5); derived trust (ADR-3, ADR-10); children and returns (4.7); anchor capability (ADR-20); external targets as effects (ADR-25) | R-6, R-7, R-17 |
| 2. Exposure gate adds nothing; in-bounds abuse at scale | Counters reserved before decisions (ADR-5); content provenance on exposed external effects (5.4) | R-10 |
| 3. Gateway credential as shared service account | Only a PEP presents (A.2); `per_agent` with PIP check (A.3) | R-1, R-2, R-3 |
| 4. Held actions outlive credentials; no runtime resumes | Grants and approved actions (ADR-8); hook contract (ADR-2); hold causes (ADR-16) | Long parks exhaust the re-hold maximum |
| 5. Fail-closed blocks recovery | Degradation matrix (ADR-23); compensation by PEP (ADR-6); in-doubt and indeterminate (ADR-17); checkpoint source (ADR-18); recovery identities (ADR-12) | R-5, R-16 |
| 6. Bypass rule conflicts with agent classes; browser agents absent | Surface table (7); credential binding scoped to governed agents (A.4); S3, S5 declared (ADR-14) | R-15 |
| 7. A0 fast path inconsistent | Structural A0, linted and matrix-enforced (ADR-13, ADR-21) | |
| 8. Diagram contradicts text on retrieval | Everything through the PEP (ADR-9) | |
| 9. Managed model service residency overclaim | Region-pinned routes only (A.8, Appendix C) | |
| 10. Control catalogue incomplete | Patterns built on the core, deferred with the extension points (v1.1) | Open |
| 11. Regulatory layer misframes the operator's role | Out of scope for the core; regulatory determinations are pattern content | Open |
| 12. Explainability mapping overclaims | Decisions are reasoned from deterministic components; the model's own account is recorded and labelled as such (Appendix D, `model_account_ref`) | Pattern content |
| 13. Evaluation standard not defensible | Deferred with the extension points (v1.1) | Open |
| 14. Derived data stores ungoverned | Derived-store registry with lineage (A.1, A.7) | R-14 |
| 15. No basis for an investment decision | Out of scope for the core | Open |

---

## Part D: Verification record

Each version was checked by a separate AI verifier that had not seen the previous versions, the rationale, or the review that produced the fixes. The verifier read only the specification, was asked to reproduce nine findings with concrete sequences, to tag severity (unsafe, blocking, minor, none), to list contradictions and anything unimplementable, and to give a verdict. From round thirteen the verifier also checked the body text against the normative appendices and the worked example against the rules it invokes. Findings closed and reopened across rounds because each repair added text with new interactions. Severity labels are the verifiers' own.

| Version | Findings closed (of 9) | Verdict | What the round found |
|---|:-:|---|---|
| 1 | 0 | Not sound | Credential binding broken by the architecture's own preview, resume, and compensation paths; stop had no propagation; taint gaps through service returns and triggers |
| 1.1 | 0 | Not sound | Factor counting contradicted the worked example; exposure gating held everything for any agent reading email; minimum version could not produce its own evidence record; stop blocked its own recovery |
| 1.2 | 3 | Not sound | Worked example exploitable inside its bounds (bounds keyed on ticket text); holds outlived credentials; three different answers on who approves bounds |
| 1.3 | 2 | Not sound | Counters exempted the effects they were meant to count; compensation had no way to run under a stop; output nodes bypassed the PEP; the customer was in the principal chain |
| 1.4 | 5 | Not sound | Bound grammar admitted `!=` as an anchor; substitution-only holds had no credential path; S1 lacked a graph; a dead host's journaled effect could reach FAILED |
| 1.5 | 5 | Not sound | Resume rule only discharged a limit-band hold, so A1 and velocity holds could never be approved; compensation source under EVS outage; handoff and service had no decision shape |
| 1.6 | 5 | Not sound | Alternating hold causes livelocked; sinks delivered from read nodes; RUN-down node entry; minor residual citations |
| 1.7 | 2 | Not sound | Sanitize node missing from the matrix; revoked-then-replay; a node with no decision parked forever; anchors backed by writable fields |
| 1.8 | 5 | Not yet, 2 blocking | Per-call heartbeat parked a parent whose child was held; anchor-backing check lacked field-level data |
| 1.9 | 5 | Not yet, 4 unsafe/blocking | Indeterminate outcome took a node out of doubt; declared surface not bound to the registered one; S1 taint crash window; substitution invalidated its own record |
| 1.10 | 6 | Not yet, 3 unsafe | Anchor capability ignored registered lineage and was checked once; content provenance conditioned on private data; never-A3 unenforced at runtime |
| 1.11 | 5 | Not yet, 1 unsafe, 1 blocking; "with those fixed, remaining items are minor and the core can be frozen" (round twelve) | Capability-record change de-anchored live releases; replay rule denied the indeterminate case it existed for |
| 1.12 | not re-verified | Provisionally frozen | Applies the two fixes and the carried minor items |
| 1.13 | 5 | Not yet, nothing unsafe or blocking; 9 required one-clause items (round thirteen) | First publication-shape text: body, mechanisms, appendices, renamed terms, warranty example. Effect definition contradicted the derived-store rule; stop-scope rule broader in the PDP than the PEP; no recovered-resume edge; a residual bounded by a deferred section; checkpoint lacked mapped result fields; no path when IDS is unreachable at hold; resolver `not_executed` outcome unstated; a read tool with an external target could carry data out. A separate sentence-level comparison with 1.12 found no normative loss from the restructure |
| 1.14 | 6 | Not yet, nothing unsafe or blocking; 5 required (round fourteen) | Owner-deadline close contradicted "only the owner may close" (inherited from 1.12); external-target rule one hop short (internal fetch proxy); `external_ingress` authorable for an outside system; `dlp_check` rejection left a node in doubt; version label |
| 1.15 | 8 | Not yet, nothing unsafe or blocking; 2 required (round fifteen) | Read-row wording broader than the 6.1 rows; in-doubt clause re-parked a successfully replayed node. Twenty-five recommended items, twenty-two applied |
| 1.16 | 7 | Not yet, nothing unsafe or blocking; 2 required; "with those applied the text can be deposited" (round sixteen) | Wall-clock park listed as auto-resuming (introduced in 1.16); external-target rule not wired to destination-keyed rules for tools with no `destination` role. Sixteen recommended, two applied, fourteen listed for v1.1 |
| 1.17 | not re-verified | Deposited as v1.0 | Applies round sixteen's two required clauses and two registry refusals |

**What this record shows.** Sixteen rounds against the same nine findings moved the verdict from "three structural conflicts" to "two one-clause wording defects." Repairs generated new defects at a declining rate: structural in rounds 1 to 3, mechanical in 4 to 7, bookkeeping and wording from 8 on; from round fourteen nothing unsafe or blocking was found, and from round fifteen every required item was one the previous round's fixes had introduced. The required count over the four publication rounds was nine, five, two, two. That pattern will not reach zero by editing, which is why the register exists and why v1.0 is deposited on the sixteenth verifier's statement that the text could be deposited with its two clauses applied, rather than on a clean pass.

**What the record does not show.** Each verifier was a single generalist reader. Reviews from specialist seats, as patterns are written on the core, will find things a generalist did not. The verifiers' severity tags are their own judgment. Nothing has been built.

---

## Part E: Known weaknesses

- **Not piloted.** The degradation matrix, the hold and resume protocol, and the anchor-capability recomputation are designs with no running instance. The first implementation will find contradictions sixteen reviews did not.
- **Version 1.17 is unverified.** The four clauses added after round sixteen were applied by the author and checked by nobody else. The fourteen recommended items that round listed are deferred to v1.1 and are named in the specification's changelog.
- **External reads are effect nodes (ADR-25).** Correct under the definition of effect, and heavy: no loop node can consult an external source, and a cancelled run that performed an external read needs an owner close. v1.1 should decide whether an egress-only compensation value is the right relief.
- **Size.** The specification is about 21,900 words in publication form: about 13,700 in the body (of which 2,700 are terms, 1,600 the mechanisms summary, and 2,600 the verification record, citation, and changelog) and about 8,200 in the appendices, after a restructure meant to reach 6,000 in the body. Each verification round added clauses. v1.1 should cut.
- **Latency.** Every call now carries a decision, an acknowledged run-state update at RUN, and for effects a durable evidence write before execution. No numbers exist.
- **The platform trust (R-1)** remains the largest single residual.
- **The SDK form (R-3, R-18)** is weaker than the sidecar form in ways that network policy cannot fix; the A2 cap is the only bound.
- **Operational load.** Resolvers, feed reviews, anchor-capability suspensions, and re-hold maxima are all human work the architecture creates and does not staff.
- **Registered-lineage completeness (R-6)** is the quiet assumption under the taint model: a feed nobody registered is a feed the architecture cannot see.
- **Manifest honesty (R-19)** is the second: every factor is derived from a manifest the owning system team wrote, and the schema-hash check catches drift, not misdeclaration.
