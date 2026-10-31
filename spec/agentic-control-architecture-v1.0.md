---
title: "[Title]"
short_name: "[Short name]"
version: v1.0
specification_version: "1.17 (internal)"
date: "[YYYY-MM-DD]"
deposited: "[deposit timestamp]"
license: CC0 1.0 Universal
status: "architecture, pre-implementation; sixteen adversarial verification rounds on internal versions 1 through 1.16, the last two on this publication text; the deposited text (internal 1.17) applies round sixteen's two required clauses and is not itself re-verified; nineteen residuals declared"
provenance: "[see section 10]"
companion: "Design rationale, same version [deposited with v1.0 | withheld]"
supersedes: none
---

# [Title]

*[Short name], v1.0. Internal specification version 1.17.*

## Abstract

Enterprises are beginning to let agents act on systems of record under authority delegated from people, while those agents read content the enterprise does not control. The models inside them cannot reliably tell instructions from data, and their behaviour shifts when a provider changes the model. This paper specifies a control architecture whose guarantees are meant to hold when the model is wrong, confused, or manipulated. Its position is that controls sit outside the model, as a deterministic decision on every call; that they do not depend on the tool that built the agent; that evidence is produced by construction, written durably before each effect executes; and that autonomy is granted per action, from properties derived from the tool rather than declared by the builder. It contributes nine component contracts; a graph run model with bounded loop nodes; a bound grammar in which a model-chosen value is constrained only by equality or membership with the run's subject, acting user, or a registered scope; taint that follows data through registered lineage; a hold-and-resume protocol that lets a held action outlive its original credentials; tiered fail-closed degradation; an evidence schema; and a register of the risks it accepts. Nothing has been built.

## What this is and is not

A reference architecture is usually distilled from systems that have been built and run. Its contracts describe interfaces that exist, and its failure modes have been observed. This paper is the other kind: it is published ahead of any implementation. Nothing described in it has been built, piloted, or measured. There are no latency figures, no availability data, and no operating experience of the hold-and-resume protocol, the degradation matrix, or anchor-capability recomputation. The design also creates human work that nobody has yet staffed: resolvers, feed reviews, suspended releases, and re-hold limits.

The verification record (section 10) is adversarial review of text, not testing of a running system. It shows the text becoming more consistent, from structural conflicts in the early rounds to one-clause defects at the end. It does not show that the architecture works, that it is complete, or that a system built to it would be secure.

**What the paper is.** A specification of components and their contracts; a run model; a taint model; failure and recovery behaviour; deployment rules per surface; an evidence schema; and the risks the architecture accepts. It is written to be implemented and cited. The body (sections 0 to 9) states the position and every mechanism; the appendices carry the full component contracts, the run-state machine, the hosting requirements, and the evidence schema. Sections 1, 4 to 7, and 9 and the appendices are normative; sections 0 and 3 restate them and yield to them where they differ; sections 2 and 8 are informative.

**What it is not.** Policy content, cost, staffing, regulatory determinations, product selection, or contract language. The identity-flow sequences, availability targets, drill cadence, and the list of extension points that patterns plug into are deferred to v1.1 (section 11).

**What it claims nothing for.** The surfaces it declares ungoverned: agents embedded in purchased software, browser and desktop control, and developer tools without PEP-E. Its requirements for them are that they be registered with their class, the controls applied, and the owner who accepted the gap, and that a stop reaches them as a runbook step (section 7).

---

## 0. Terms

Definitions are collected here and used unchanged throughout. The component contracts in Appendix A are normative; where a definition here is shorter than the appendix, the appendix governs.

**Components.** Nine components, each a role with a contract (section 2, Appendix A). Several may be one product; one existing product may fill one role.

| Term | Meaning |
|---|---|
| **REG**, Registry | The system of record for agents, releases, tool manifests, system capabilities, triggers, sanitizers, services, and the boundary definition (A.1). |
| **IDS**, Identity Service | Issues agent identities and every credential a PEP presents downstream; holds workload bindings, delegation state, and recovery identities (A.2). |
| **PDP**, Policy Decision Point | Evaluates each decision request against the signed policy bundle; returns `ALLOW`, `DENY`, or `HOLD` with obligations; holds no run state (A.3). |
| **PIP**, Policy Information Point | A registered adapter the PDP queries at decision time for entitlement, ownership, and status relations about one system's resources (A.1, A.3). |
| **PEP**, Policy Enforcement Point | The point every call of a governed agent passes through. Two forms, one contract: **PEP-P**, a network proxy; **PEP-E**, a signed SDK or sidecar embedded in a code runtime (A.4). |
| **RUN**, Run Coordinator | Owns the lifecycle of every governed run: checkpoints, holds, parks, counters, heartbeats, the stop register. Always central (A.5). |
| **EVS**, Evidence Store | Append-only, hash-chained record of every decision and transition, written before any effect executes (A.6). |
| **DBS**, Data Boundary Service | Retrieval, memory, derived stores, sanitizers, delivery tools, and outbound checks, all reached through the PEP as tools (A.7). |
| **MGW**, Model Gateway | Routes a model call only within the release's declared route and attributes tokens to run and node (A.8). |
| **OPS**, Operations Control | Issues stops and signs the stop list; runs the park queue, resolvers, the recovery path, and drills (A.9). |

**Surfaces.** The class of environment an agent is built and executed on (section 7).

| Surface | Environment |
|---|---|
| **S1** | A low-code or managed agent platform. Governed through PEP-P and the hook contract. |
| **S2** | Engineered code: agents and pipelines in a server-side runtime. Governed through PEP-E. |
| **S3** | Agents embedded in purchased software. Ungoverned. |
| **S4** | Developer tools on a workstation. Governed only when the host embeds PEP-E ("S4 with PEP-E"), and then capped at A1. |
| **S5** | Agents that drive a user interface by browser or desktop control. Ungoverned. |

**Agents, releases, runs.**

| Term | Meaning |
|---|---|
| **Agent** | A registered unit of automation with an owner, an identity, and one or more releases. |
| **Governed agent** | An agent whose every call passes through a PEP, whose runtime reports to RUN through the hook contract, and whose release has a graph with node identity: surfaces S1, S2, and S4 with PEP-E. The invariants bind governed agents only. |
| **Owner** | The person accountable for an agent: approves its bounds, accepts its residuals, decides parked runs beyond a resolver's authority. |
| **Release** | A pinned, versioned bundle: graph, instructions, tool list with versions, bounds, model version or declared route, policy version, retrieval configuration, PEP-E version, runtime and platform version. Nothing changes in production outside one (I6). |
| **Graph** | A release's directed acyclic graph of typed nodes, executed in topological order (4.1). Each node has a stable id. |
| **Node** | One step of the graph. Types: `read`, `effect`, `loop`, `sanitize`, `human`, `handoff`, `service`, `compensate`, `output` (4.2). |
| **Run** | One execution of a release's graph. Has a run id, a trace id shared with child runs, and a parent run id if spawned. |
| **Child run** | A run started by a `handoff` or `service` node of another run (4.7). |
| **Hook contract** | The calls every governed runtime makes to RUN (`start_run`, `node_entered`, `checkpoint`, `heartbeat`, `rendered_description`, the `hold` and `resume` callbacks) and the signed `(run_id, node_id)` header on every runtime-originated call to the PEP (A.5). |
| **Trigger** | A registered event that starts a run, signed by its source's workload key. Kinds: `user_session` (a person is present and the runtime holds their token), `subject_claim` (the source asserts whom the run is about), `event` (neither). |
| **Signed envelope**, **payload** | The signed part of a trigger (trigger id, kind, subject claim, timestamp) and the content it carries, whose trust is derived from the source. The subject claim is never in the payload (A.1). |

**Tools, systems, and effects.**

| Term | Meaning |
|---|---|
| **Tool manifest** | The registered description of one tool version: identity, target system, side-effect class, data classes, parameter roles, compensation mapping, maintainer. Authored by the owning system team, consumed by builders (A.1). |
| **System kinds** | A registered system is of one kind: `system_of_record`; `derived_store` (index, embedding store, cache); `memory`; `sink_store` (append-only, provenance-tagged); `interface` (the enterprise delivery surface, which stores nothing). Every DBS-managed store and every interface is inside the trust boundary (A.1). Derived stores, memory, and sink stores are DBS-managed. |
| **Trust boundary** | The set of address spaces, domains, and systems that count as inside the enterprise. Recorded in REG as the **boundary definition**, against which the PEP resolves whether a `destination` is outside. |
| **Effect** | A tool call whose manifest has a side effect: it changes state in a system of record or a derived store, or sends data outside the trust boundary. Only `effect` nodes make effects in the forward graph; a `compensate` node makes the effect that reverses one. Writes to memory and sink stores are decided calls, not effects; a write to a derived store is an effect (A.1). Model calls are PEP-mediated and MGW-governed, not PDP-decided. |
| **Delivery**, **delivery tool** | An `output` node's call to a registered delivery tool, whose target is of kind `interface` (delivering to the acting user or a recipient role) or `sink_store`. Decided like any call, with `purpose = delivery`; not an effect. |
| **Side-effect class** | The manifest's `side_effect_class`: `none`, `internal_store`, `delivery`, `spawn`, `reversible_internal`, `external`, `financial_legal`. `internal_store`, `delivery`, and `spawn` are derived from the target; `none` and the effect classes are authored and approved, with the two refusals of `none` in A.1. |
| **Factor** | A property of an effect derived per call from the manifest and the parameters: *irreversible*, *external*, *regulated*, *sensitive* (A.1, 4.4). |
| **Tier** | The autonomy level of an effect node. **A1**: every call held. **A2**: allowed within the auto limit, held up to the hard limit, denied beyond. **A3**: allowed within policy. **A0** is an agent class, not a tier: an agent whose graph has no effect nodes (4.4). |
| **Bounds** | The conjunction of predicates an effect, read, loop, or output node declares over its parameters, in the bound grammar (4.3). |
| **Auto limit**, **hard limit** | The two limits on an `amount`: at or below the auto limit an A2 call is allowed; between them it is held; above the hard limit it is denied, and no approval widens it. |
| **Anchor** | What a bound may tie a parameter to by equality or membership: the run's subject, its acting user, or a registered **scope constant** (a set fixed in the release, such as `release.templates`). "Anchor" is used in this sense only. |
| **Anchor-capable** | A PIP relation that may serve as an anchor: every field it is answered from sits in a system of record that no agent can write by any registered path and no external party feeds, or is tagged and marked verified; and no registered tool writes the field. Maintained continuously by REG (A.1). |
| **Scope-anchored** | Of bounds: using only scope constants and predicates on constants, so no PIP relation is needed at decision time (6.1). |
| **Parameter roles** | The manifest's `parameter_roles`: which parameters are the **`resource`** (the record the call acts on), the **`destination`** (where it sends, carrying a destination class), and the **`amount`**. A parameter with no role is **content-bearing**. |
| **Two-approver threshold** | The policy value on the `amount` role above which an `irreversible` and `regulated` effect needs two approvers, or a person performs the action (4.4). |
| **Action hash** | Hash of (tool, version, canonical parameters, run id, node id). Grants, approvals, idempotency keys, and resumes key on it. |
| **Provenance** (of a parameter) | A flag the PEP sets on each value in a decision request: `template` (a template id in the release), `sanitized` (the value's canonical hash matches an accepted output of a qualifying sanitizer in this run), or `model` (anything else) (A.3). |
| **Preview tool** | A system's registered read tool that calls its preview endpoint, a dry run that changes nothing; used within a held node to show the approver what would change (A.1, 4.5). |

**Principals and approvals.**

| Term | Meaning |
|---|---|
| **Acting user** | A person whose authority the run acts under: the person whose authenticated session started the run, or, for one held action only, the approver who substituted. Heads the principal chain while present; a run is *delegated* for any call made while it has one. |
| **Subject** | The person or account the run acts *about*, carried in the trigger's signed envelope. Not a principal; bounds anchor to it and velocity counters key on it. Distinct from the `resource` role, which names the record a call acts on. |
| **Principal chain** | The acting user, if any, then each agent from the root run to the current one. Authority is the intersection over the chain (I2). |
| **Approver**, **approver set** | The people policy names to decide a hold. Independent of the builder whenever any factor is present (4.5). |
| **Approval record** | RUN's signed record of an approver's decision on a hold, carrying the approver's identity-provider assertion and marked `grant` or `substitution`. |
| **Approved-action record** | RUN's record, beside the hold, that an action hash has been approved and may be executed until the resume window ends; invalidated by execution, failure, a later hold or denial of the same hash, or a stop. |
| **Resumption grant** | A single-use token IDS mints at hold where policy permits one, bound to the action hash, that a PEP of the same workload redeems for a credential after the resubmitted decision is allowed (A.2). |
| **Substitution** | The approver becoming the acting user for one held action when the original user's delegation is revoked or no grant was minted (A.2). |
| **Resolver** | The standing on-call role that resumes, cancels, escalates to the owner, or records a hand-verified outcome for a parked run; cannot widen bounds or approve a held factored effect (B.2). |

**Holds, stops, and failure.**

| Term | Meaning |
|---|---|
| **Hold** | An effect awaiting a human decision, or a `human` node awaiting input. A hold names every rule that caused it (its **hold causes**), and an approval discharges the causes it covers (A.3). |
| **Park** | A run suspended by a stop, a failure, a degradation, host loss, the wall-clock budget, an unreconciled journal, or an unreachable IDS at hold, with a named resolver and a deadline. |
| **Stop**, **stop scope** | An instruction from OPS that halts new effect, delivery, and spawn decisions and reads of `restricted` data, and cuts `loop` nodes, within a scope: an agent, a tool, a surface, or the fleet (4.9). |
| **Stop list** | The signed, sequenced list of current stops that OPS publishes, the PDP distributes, and every PEP holds; a list older than the staleness limit acts as a stop. |
| **In doubt** | Of an effect node: RUN has its entry hook and no exit checkpoint, the latest `purpose = normal` decision for the effect's own action hash is `ALLOW`, and there is no `effect.*` event or the latest one is `effect.indeterminate` (A.5). |
| **Indeterminate** | The outcome the PEP records when it cannot tell whether an effect happened (a timeout, a lost response). Distinct from `effect.failed`, which is written only on a definitive negative. |
| **Compensation**, **replay** | Compensation reverses an executed effect through the manifest's declared mapping; replay re-presents an effect in doubt with its recorded idempotency key. Both are PEP-executed on RUN's instruction, decided under their own `purpose`, never held, and outside stop scope (A.3, A.4). |
| **Degraded mode**, **signed local journal** | The PEP's behaviour while a control-plane component is unreachable (section 6): what may continue does so against the cached bundle, with decisions and effects written to an append-only journal signed with the workload key and reconciled into EVS on recovery. |
| **Policy bundle**, **policy pack** | A bundle is the signed, versioned, distributable artefact the PDP evaluates and every PEP caches; a pack is a named set of rules within it (the baseline pack is in 5.4). |
| **Obligation** | An instruction the PDP attaches to a decision that the PEP must carry out: `evidence_first`, `redact_for_approver[]`, `apply_provenance_tag`, `require_sanitizer`, `dlp_check`. |
| **Recovery path**, **recovery identity** | The declared exception to I1 and I3 for what the degradation tiers do not cover: vaulted recovery identities, released by two named people (a **recovery release**), accepted directly by systems that opt in, every use an incident (6.3). |
| **Residual**, **R-n** | A risk the architecture accepts in writing, numbered in the register (section 9), with an owner who records acceptance. |
| **Denial branch**, **failure branch** | The graph edges a release declares for a node whose call is denied or times out (denial branch) and for one whose effect ends in `effect.failed` on a system error or an outbound-check rejection (failure branch); a node with no failure branch takes its denial branch. A node cancelled by a stop is re-entered instead (4.9). |
| **Policy values** | Values a policy bundle sets that the text names: the approval timeout, the resume window, `max_park`, the re-hold maximum, the staleness limit, the two-approver threshold, velocity windows and caps, degraded-mode caps, the heartbeat deadline, model token budgets, the consecutive-replay count, and the wall-clock budget per run. |
| **Risk owner** | The function that approves the bounds of a factored effect alongside the agent's owner (4.4). |
| **Access-review cycle** | The cadence on which human access is reviewed; agent identities, trigger registrations, `sources[]` entries, and feed reviews are reviewed on the same cycle (A.1). |
| **Drill** | A scheduled exercise, in a test environment, of a stop, a recovery release, a journal reconciliation, or a restart from checkpoint; the set and cadence are deferred to v1.1. |

**Data and taint.**

| Term | Meaning |
|---|---|
| **Data class** | One of `public`, `internal`, `confidential`, `restricted`. "Private data" in policy means `confidential` or `restricted`. |
| **Taint** | The mark carried by content that entered from outside the trust boundary, from a system that agents or external parties can write, from an exposed child run, or from a human input role not registered as internal, and has not been cleared by a `sanitize` node. Applies to content. |
| **Exposed** | Of a run: it has touched tainted content, from its first tainted input to its end. Policy uses this flag (5.2). |
| **Provenance tag** | A per-field mark a system stores and returns, recording that the field arrived through external ingress or was written during an exposed run. Distinct from parameter provenance above. |
| **Sanitizer**, **`sanitize` node** | A registered, versioned, deterministic function with declared input and output schemas that clears taint from its output only; callable only from a `sanitize` node. A model is never a sanitizer (5.3). |
| **Rendering sanitizer** | The sanitizer imposed on every delivery of an exposed run: removes links, media references, data URIs, query strings, and long runs of encoded data (5.3). |
| **`untrusted_source`** | A tool manifest field derived from its target: `never` (a trusted system), `always` (every return is tainted), or `per_item` (the target tags fields and each item is tainted or not by its tag) (A.1). |

---

## 1. Position and invariants

The position: controls sit outside the model, as a deterministic decision on every call; they do not depend on the tool that built the agent; evidence is produced by construction, written before the effect; and autonomy is granted per action, from properties derived from the tool rather than declared by the builder. The invariants state that position as obligations.

For governed agents. Surfaces S3, S5, and S4 without PEP-E are registered and controlled by other means; the invariants make no claim for them.

| | Invariant |
|---|---|
| I1 | No side effect without a deterministic decision made outside the model. |
| I2 | No authority broader than the principal chain; the identity presented downstream is the agent's own, never shared with another agent. |
| I3 | Evidence of the decision is durably written, to EVS or in degraded mode to the signed local journal, before the effect executes. |
| I4 | Taint persists across every hop until an evidenced `sanitize` node clears it. |
| I5 | No unregistered agent holds enterprise authority. |
| I6 | Nothing changes in production outside a versioned release. |
| I7 | Every governed run can be stopped; every stopped run ends in a declared state. |
| I8 | Administration of REG, IDS, PDP, PEP (its builds, bundles, and stop lists), RUN, EVS, MGW routing, and OPS (stop issuance and recovery release) is separated from building agents. |

The recovery path (6.3) is the one declared exception to I1 and I3: its decision is made by two named people instead of the PDP, and its evidence is written by hand when EVS is unavailable.

**Core decisions.** Six decisions fix the shape of the architecture. The alternatives rejected for each, and the tradeoffs accepted, are in the design rationale.

| | Decision |
|---|---|
| D1 | Enforcement is hybrid by surface: a proxy where nothing can be embedded, an embedded enforcement point in code runtimes, and declared ungoverned surfaces (section 7). |
| D2 | A run is a graph with bounded loop nodes; open-ended planning happens inside a loop node and ends in a parameter proposal, never in a decision (section 4). |
| D3 | Downstream credentials are the agent's own, per agent, chained with the acting user where the system supports it (A.2). |
| D4 | A held action resumes by a resumption grant bound to the exact call, with approver substitution as the fallback (A.2). |
| D5 | The control plane fails closed, in tiers: what an attacker would gain by taking it down never degrades open (section 6). |
| D6 | Taint follows data through registered lineage and is cleared only by a `sanitize` node (section 5). |

---

## 2. Components

Nine components. Each is a role with a contract; several may be one product, or one existing product may fill one role. Under I8, the team that builds agents administers none of REG, IDS, PDP, PEP, RUN, EVS, MGW routing, or OPS stop issuance and recovery release.

```
 trigger (signed by its source) ──► RUN  Run Coordinator
                                     │ run state · checkpoints · holds · parks
                                     │ counters · stop register
                                     ▼
                              Agent runtime (per surface)
                                                   │
                                                   │ every call: tools, reads, retrieval,
                                                   ▼ memory, sanitizers, previews, deliveries,
                                                 PEP   model calls, child-run spawns
                                                  │ ──► PDP ──► PIP   (tool, delivery, spawn decisions)
                                                  ├──► MGW ──► models (model calls: credential and budget, no PDP decision)
                        ┌─────────────────────────┼─────────────────────┐
                        ▼                         ▼                     ▼
                 systems of record        DBS retrieval, memory,   sanitizers,
                                          derived stores           delivery targets

 EVS  ◄── every decision, written before every effect; every transition
 IDS  ── agent identities, delegation, grants, recovery identities
 REG  ── agents, releases, tools, triggers, systems, sanitizers, services
 OPS  ── stop (signs the stop list), park queue, recovery, drills
```

In one line each; the contracts are in Appendix A.

- **REG** records what exists and what it may touch, derives trust properties from registered lineage rather than accepting an owner's declaration, and keeps anchor capability true as registrations change (A.1).
- **IDS** issues one identity per agent, credentials only to attested PEP workloads, and the grants and approved-action credentials that let a held action resume after its original credentials are gone (A.2).
- **PDP** decides every call in a fixed rule order against a signed bundle, returning allow, deny, or hold with named causes and obligations (A.3).
- **PEP** is the one path from a governed agent to anything: it derives factors, reserves counters, writes evidence first, presents credentials, applies obligations, and keeps a signed journal for degraded mode (A.4).
- **RUN** checkpoints every node boundary, holds and parks runs, resolves effects in doubt, keeps counters and the stop register, and instructs the PEP for previews, resumes, compensations, and replays (A.5).
- **EVS** keeps the hash-chained record, externally witnessed, with erasable payloads referenced by keyed hash (A.6).
- **DBS** places retrieval, memory, derived stores, sanitizers, delivery tools, and outbound checks behind the PEP as tools (A.7).
- **MGW** keeps model calls inside the declared route and attributes tokens to run and node (A.8).
- **OPS** signs the stop list, runs the park queue and resolvers, and holds the recovery path (A.9).

---

## 3. Mechanisms

The mechanisms the architecture rests on, each stated once at the level needed to recognise it, with a pointer to where it is specified. Where a statement here and the section or appendix it points to differ, the latter is normative.

1. **Equality-or-membership anchoring, with anchor capability maintained continuously** (4.3; A.1, `pip_adapter`; A.3, `anchor_version`). A node's bounds are a conjunction of predicates over the call's parameters. A parameter is anchored only when an equality or membership form ties it to the run's signed subject, its acting user, or a registered scope constant, or to a relation of a parameter already anchored. Every `resource` and `destination` parameter must be anchored; other predicates never anchor. A relation may anchor only if every field it is answered from sits in a system of record that is neither externally fed nor agent-writable through any registered path, or is tagged and marked verified, and no registered tool writes it. REG recomputes that property as registrations change, stamps an anchor-capability version on each release, and the PDP denies a call whose anchors are no longer capable.

2. **Parameter provenance with schema-qualified sanitizers** (A.3, decision request; 5.3; 5.4). The PEP marks each parameter value in a decision request `template`, `sanitized`, or `model`. A value is `sanitized` only if its canonical hash matches an accepted output, in this run, of a sanitizer whose output schema has no string field except enumerations and identifiers matching a registered pattern. On an exposed run, an effect whose destination resolves outside the trust boundary is allowed only if the destination is anchored and every content-bearing parameter is `template` or `sanitized`; otherwise it is held with cause `exposure`. A model is never a sanitizer, and sanitizing clears taint without making a value authoritative.

3. **Subject distinct from acting user** (section 0; A.1, trigger registration; A.2, acting user). A trigger's signed envelope carries the subject claim separately from the payload, and a `subject_claim` trigger is registrable only if the source authenticates the subject before signing and records how. The subject is whom the run acts about: a bound anchor and a velocity key, inherited by child runs, never a principal. An acting user exists only for a `user_session` trigger or for one held action when an approver substitutes.

4. **Taint through derived trust fields and registered lineage** (A.1; section 5; A.4). `external_ingress` and `agent_writable` are true for a system if true for it or for any system in its registered `sources[]`; `provenance_tag` holds only if the system and every source tag their fields and the feed passed a review repeated on the access-review cycle. A tool's `untrusted_source` and a trigger's payload trust follow from these and cannot be authored. A run is exposed from its first tainted input to its end; writes during an exposed run carry a provenance-tag obligation; untagged items from `per_item` sources count as tainted; child runs receive the full run state and return their exposure. A runtime's claim of per-item provenance is recorded as its claim and narrows nothing.

5. **Resumption grants with approved-action records and substitution** (A.2). At hold, where policy permits a grant, IDS mints a single-use grant bound to the action hash, audience IDS, encrypted under a hardware-backed key, stored by RUN. The grant carries no clock: at redemption IDS computes expiry from RUN-signed timer state, including suspension while the run is parked, up to `max_park`. It is redeemed only after the resubmitted decision is allowed and durably written; RUN then keeps an approved-action record until the resume window ends. If the user's delegation is revoked, the approver can, where policy permits substitution, become the acting user for that one action, by substitution at approval or, when the revocation is found only at redemption, through a new hold with cause `substitution_required`; the credential records the original user as the requested principal.

6. **Cumulative hold causes with bounded re-holds** (A.3; 4.5). A hold names every rule that held it, and an approval adds those causes to a discharged set kept per action hash. On resume the call re-reserves counters and is evaluated in full: a discharged cause does not hold again until the action executes, is denied or stopped, or the resume window expires; a new cause opens an approval for itself only; a policy maximum on re-holds ends in denial. Hard limits, hard velocity caps, bounds, and the intersection are deny-only and never discharged.

7. **Reversal and replay authority as a record claim** (A.2). Compensation and replay credentials are issued on the authority of the agent and the release, carrying the original action hash and principal chain as a record claim, not as live delegation, and systems of record accept them only to reverse or re-present an action already recorded under that hash. An action a user authorised can be undone or completed after the user's delegation ends.

8. **Node-type matrix, enforced per call** (A.1, `side_effect_class`; A.3, evaluation order; 4.2). Each node type may call only named tool classes, and the PDP's first rule denies any call to a tool the node does not declare. The `delivery` and `internal_store` classes are derived from the target's kind, `spawn` from the tool being an agent tool, and none of the three can be authored, so a delivery target or an agent cannot be reached from a node that would skip its decision.

9. **Factors derived from tool manifests** (A.1; 4.4). Each tool version has a manifest authored by the owning system team and approved by security and compliance; builders consume it, and a live mismatch of its schema hash unregisters the tool. The PEP derives the four factors per call from the manifest and the resolved parameters, and the default tier follows the factors: none, A2; any, A1, never A3; irreversible and regulated above the two-approver threshold, two approvers or a person performs the action.

10. **Deterministic compensation verified against the recorded call** (A.1, `compensation`; A.3; A.4; A.5). Each effect node declares a `compensate` node or `irreversible`. The manifest's compensation is a parameter mapping expressed only as field references into the original call's recorded parameters and result. On RUN's instruction the PEP executes it with no model, attaching the recorded original from EVS, its own signed journal, or RUN's signed checkpoint copy, and the PDP allows it only if the parameters equal the mapping applied to that record and the record verifies. A compensation is never held, and stops do not reach it.

11. **In doubt, defined over the latest decision, with an indeterminate outcome** (A.4; A.5; 4.8). The PEP writes `effect.failed` only on a definitive negative and `effect.indeterminate` when the outcome is unknown. An effect node is in doubt when RUN holds its entry hook and no exit checkpoint, the latest `purpose = normal` decision for the effect's own action hash is `ALLOW`, and there is no effect event or the latest one is indeterminate. A node in doubt is never re-entered: it is resolved by replay with the recorded idempotency key, or by a resolver who records a hand-verified outcome. A run with an unreconciled journal parks, and `FAILED` and `CANCELLED` are reachable only when RUN's own hooks show that no effect node was ever entered.

12. **Tiered fail-closed, with compensation and replay outside stop scope** (section 6; 4.9). For each control-plane component, a matrix fixes what continues during its outage. Effects continue only if they have no factor and the run is neither exposed nor delegated, and, when the PDP or PIP is unreachable, only if the bounds are scope-anchored and the cached bundle decides, and during a RUN outage only on PEP-E surfaces, on local checkpoints and counters; what an attacker would gain by taking the control plane down never degrades open. Compensation and replay are outside every stop's scope, are never held, and continue through EVS, PDP, and PIP outages, but not through RUN or IDS outages. Beyond the matrix, recovery identities released by two named people are the single declared exception to I1 and I3, and every use is an incident.

13. **Enforcement-build attestation tied to tier caps** (A.2; A.4; section 7). IDS issues credentials only to workloads whose attestation includes a PEP build hash on an allow-list that records each build's form, and refuses a credential when the release declares a form or surface other than the attested one, so caps tied to form and surface cannot be evaded by declaration. Credentials are sender-constrained to the PEP's workload and bound to an audience; only a PEP presents downstream.

14. **Stop list signed by operations, with staleness as a stop** (A.9; 4.9; A.4). OPS issues stops by scope and signs the stop list with a sequence number and validity period; the PDP distributes it; every PEP holds and enforces it locally, even when the PDP is unreachable. A list older than the staleness limit acts as a stop. An unexecuted effect cancelled by a stop is written `effect.failed` with `error = stopped`, so it is not in doubt, and stops never compensate on their own.

15. **Velocity counters reserved before the decision** (A.5; A.4). Before an effect decision the PEP atomically reserves counters keyed on the agent, the subject (else the acting user, else the agent alone), and the resolved destination, and the post-reservation counts go into the request. The PEP is the sole releaser of its reservations; RUN reconciles unconfirmed ones against executed-effect events by action hash. A velocity breach holds, a hard cap denies, and counters are never bounds.

16. **Declared residual register as part of the specification** (section 9). A numbered register of the risks the architecture accepts, each with the section that declares it, what bounds it, and an owner who records acceptance. Surfaces the architecture cannot govern are registered with the owner who accepted the gap, and the invariants make no claim for them.

---

## 4. Run model (D2)

### 4.1 A run is a graph

A release contains a directed acyclic graph. The runtime executes the forward nodes in topological order; `compensate` nodes are outside the forward order and run only when RUN instructs the PEP. RUN checkpoints at each boundary. An effect is decided when its node submits the call, after the model has filled the parameters and before that call executes; taint and data-class accounting is recorded per call before the result reaches the runtime (A.4) and settled in `node.exited`.

### 4.2 Node types

| Type | May call | Declares | Decision |
|---|---|---|---|
| `read` | Tools with `side_effect_class = none` or `internal_store` (memory) | Expected data classes; read bounds | Allow or deny; reads of `restricted` data are refused under a stop, a stale stop list, or a control-plane outage whose row in 6.1 marks them as stopped (4.9, 6.1); memory writes carry `apply_provenance_tag` |
| `effect` | One tool with a side effect, plus its system's `preview_tool` when RUN instructs a preview | Bounds with auto and hard limits, tier, compensation, preview use | Allow, hold, or deny |
| `loop` | `none` tools only, inside a bounded inner loop | Step cap, token cap, allowed tools, read bounds | As `read`, per iteration; a cap ends the node |
| `sanitize` | One registered sanitizer | Input and output schema | Deterministic; writes `sanitize.result` |
| `human` | Nothing | Approver set, or input schema | Holds as `HELD(input)`; no grant, since no effect is pending |
| `handoff` | The target agent's agent tool (`purpose = spawn`) | Target agent, inputs | Decided through the PEP; on allow, a child run under the extended chain |
| `service` | The service's agent tool (`purpose = spawn`) | Service id, inputs | Decided through the PEP; on allow, a child run presenting the service's identity; chain and caller recorded |
| `compensate` | The reversing tool named by the manifest mapping of the effect it reverses | The effect node it reverses | Allowed only when the parameters equal the mapping over the recorded call (A.3); never held; has no bounds or tier; executed only on RUN's instruction |
| `output` | One `delivery` tool | Output schema, delivery tool, recipient or store bound | A delivery decision through the PEP: the PDP checks the delivery tool's recipient against the data classes touched and, when the run is exposed, imposes `require_sanitizer` with the rendering sanitizer. Sending output outside the trust boundary, or writing to a system of record, is an `effect` node. |

A model may run inside `read`, `loop`, `effect` (to fill parameters), and `output` nodes. It never decides whether an effect happens.

### 4.3 Effect nodes, bounds, and anchoring

An effect node declares the tool and version; **bounds**; the **tier**; its **`compensate` node** or `irreversible`; whether to use preview.

**Bound grammar.** A node's bounds are a conjunction of predicates of these forms, where `p`, `q` are parameters, `A` is an anchor (`subject`, `acting_user`, or a registered scope constant), and `PIP.rel(x)` is a registered relation:

```
anchoring forms:      PIP.rel(p) == A        p ∈ scope        p == PIP.rel(A)        p == PIP.rel(q)
predicate forms:      p op constant          PIP.pred(p) == true|false
limits:               amount ≤ auto_limit | hard_limit
```

**Anchoring rule**, evaluated per node over the conjunction. A parameter is *anchored* if an anchoring form relates it by equality or membership to an anchor (`PIP.rel(p) == A`, `p ∈ scope`, `p == PIP.rel(A)`), or if it equals a relation of an anchored parameter (`p == PIP.rel(q)` with `q` anchored). Only equality and membership anchor; `!=`, `<`, and other operators are predicates, never anchors. The node passes if every `resource` and `destination` parameter is anchored. Predicates such as `PIP.replacement_issued(p) == false` are permitted and do not count as anchors. Read-node and loop-node bounds are linted the same way, and a read tool with a `resource` role must have that parameter anchored, so reads of private data about a subject are bounded to that subject. Velocity counters are never bounds; they live in the policy pack, where a breach holds.

**Anchor backing.** A relation may anchor only if REG holds it as anchor-capable (A.1): every backing field is in a system of record that no agent can write by any registered path and no external party feeds, or that carries tags and marks the field verified; and REG keeps that property true by refusing later registrations that would break it. Where the backing system carries tags, the PIP also refuses to answer an anchor relation from a tainted field, which denies the call. Fields that agents or external parties may write (a contact address, a note, a form field) can be read and used as parameters, never as anchors. A bound that uses only scope anchors needs no PIP at decision time; one that uses a PIP relation does.

This is what makes a model-chosen value safe: the model may choose any value, and the bound checks that what it chose belongs to the subject or user the run is acting for.

**Limits.** Inside the auto limit, A2 allows; beyond the hard limit, the PDP denies and no approval widens it; between, the call is held.

### 4.4 Tiers and factors

| Factors present on the effect | Default tier |
|---|---|
| None | A2, with bounds approved by the owner. A3 after a production record at A2, independent review, and owner agreement. |
| One or more | A1. A2 only with written bounds approved by the owner and the risk owner; security also approves effects whose `destination` resolves outside the trust boundary or that write credentials or keys. Never A3. |
| `irreversible` and `regulated` together, above the two-approver threshold set in policy on the `amount` role | Held calls need two approvers, each recorded as an approval record on the one hold and both attached at redemption; or the node is replaced by a `human` node and a person performs the action. Policy requires such a node's auto limit to be at or below the two-approver threshold, so no call above it executes unheld. A node with both factors and no `amount` role is A1 and every hold on it takes two approvers. |

Tier is per effect node. A held A2 call is A2 behaviour, not a tier change. Compensation nodes have no tier; they were approved with the release and are allowed when their parameters match the mapping (A.3). The owner's function samples A2 and A3 effects after the fact at a rate set by tier; an independent governance function checks that the sampling happens, and the rate is a published measure.

**A0 and the fast path.** A0 is an agent class, not a tier: an agent is A0 if its graph has no effect nodes. It takes the fast path (registration and builder self-check) when it reads nothing above `internal` and has no `handoff` or `service` node. Its `output` nodes are decisions like any other, and the rendering sanitizer is imposed whenever the run is exposed, fast path or not.

### 4.5 Holds and approval

Every effect hold, whatever caused it, follows the same rules. An input hold (`human` node) shows the input schema and the run's tainted reads, and a timeout follows the graph's denial branch.

- The approver is independent of the builder whenever any factor is present.
- The approver view contains: tool and typed parameters; the preview result, or a statement that none exists; the subject; the factors, bounds, and which limit was crossed; the counters the call would consume; what will change; the run's tainted reads. Where the runtime claims per-item provenance, the view marks which reads it claims shaped the parameters, labelled as the runtime's claim; otherwise it lists every tainted read since exposure. Policy never uses the claim; it uses the run-level flag.
- Timeout denies. A denied or timed-out hold ends the node and the denial branch follows. Denial never compensates, because nothing executed.
- On approval, RUN signs the approval record and instructs the PEP to resubmit the decision with `approval_ref`; only on `ALLOW` does the PEP obtain the credential, by grant or by substitution (A.2), and execute.
- Approval rate and median decision time per approver set are published measures.

### 4.6 Loops and emergent behaviour

Open-ended planning lives inside `loop` nodes, with read-only tools and caps. What a loop concludes becomes a parameter proposal for a later `effect` node, where the decision is made.

### 4.7 Child runs

`handoff` extends the principal chain; the child's effective authority is the intersection (I2). `service` keeps the acting user and the caller chain in the principal chain for evaluation but presents the service agent's identity downstream; the PDP checks the caller's authority to invoke the service and evaluates each of the service's calls against the service's bounds and every principal. In both, the full run state (`exposed`, `tainted_reads`, `data_classes_touched`) passes to the child, the trace id is shared, and anything a child returns carries the child's exposure.

### 4.8 Run states

A run is `CREATED`, then `RUNNING`, and ends in one of five terminal states: `COMPLETED`, `COMPENSATED`, `CANCELLED`, `FAILED`, `CLOSED_WITH_EXCEPTION`. Between, it may be `HELD`, `PARKED`, `ESCALATED`, `STOPPING`, or `COMPENSATING`. The state machine is in B.1.

`FAILED` and `CANCELLED` are reachable only from a run in which no effect node was ever entered, which RUN knows from its own `node_entered` hooks, not from evidence it may be unable to see. `CLOSED_WITH_EXCEPTION` is the terminal state for a run that cannot be completed or fully compensated, or that OPS closed on the owner's deadline: an irreversible effect stands, a compensation failed, a recovery action (6.3) was taken outside the graph, or the owner did not decide in time. Only the owner may close a run this way, with a recorded disposition (loss accepted, manual remediation reference, or incident reference), except that when the owner's deadline passes OPS runs the declared compensations and closes the run with disposition `owner_deadline_passed`, and the owner is notified. Every transition writes a `run.*` event (Appendix D). `PARKED` and `ESCALATED` always carry a resolver and a deadline (I7). A run parked by degradation, host loss, an unreconciled journal, or an unreachable IDS at hold resumes without a resolver once the cause has cleared or the runtime has been restarted and any effect in doubt is resolved (A.5); a run parked by a stop, the wall-clock budget, a failed compensation, or an irreversible effect needs a resolver or the owner.

### 4.9 Stop semantics and propagation

**Register and list.** OPS issues a stop into RUN's register with a stop scope (agent, tool, surface, fleet) and signs the stop list with a sequence number and validity period; PDP distributes it on the policy-bundle channel; every PEP holds it. A PEP whose list is older than the staleness limit behaves as under a fleet-scope stop (A.4), so a broken channel becomes a stop rather than a gap. Propagation latency is a published measure.

**Effect of a stop.**

1. The PDP denies new effect, delivery, and spawn decisions in scope; PEPs enforce from their own list even if the PDP is unreachable.
2. A node in flight: a `read` node finishes; a `loop` node in scope is cut at once; reads of `restricted` data in scope are refused; an `effect` not yet executed is cancelled, and the PEP writes `effect.failed` with `error = stopped` so the node is not in doubt; an effect in doubt is resolved by replay, which is outside the stop's scope, or by parking (A.5).
3. The run moves to `CANCELLED` if no effect node was ever entered in it, else to `PARKED` with the on-call resolver. Stops never compensate on their own; a resolver or owner decides between resuming after the stop lifts and cancelling, which compensates every executed effect in reverse order.
4. Compensation and replay requests are outside the stop's scope and are never held. A compensation that fails, or an effect declared `irreversible`, parks the run.
5. When a parked run resumes after a stop lifts, a node whose effect was cancelled by the stop is re-entered for a fresh decision; a node whose effect ended in `effect.failed` on a definitive system error follows the graph's failure branch, or the denial branch if none is declared.

**Reach.** Stops reach S1, S2, and S4 with PEP-E through the list. For S3, S5, and S4 without PEP-E, a stop is a runbook step recorded against the registry entry.

---

## 5. Taint model (D6)

### 5.1 Sources

Taint is applied when:

- a trigger whose derived payload trust is untrusted starts a run, or a provenance-tagged field in its payload is tainted (applied by RUN at `run.created`);
- a tool with `untrusted_source = always` returns (applied by the PEP);
- a `per_item` tool returns an item flagged tainted (memory, provenance-tagged systems);
- a child run returns while exposed;
- a `human` node receives input from a role not registered as internal (A.5).

Because `untrusted_source` and `agent_writable` are derived, a system with external ingress or with agent writes cannot be registered as trusted by its owner, and a provenance-tagged system cannot be read through a tool that ignores the tags. A system with `external_ingress = false` and no registered write tool is trusted on read at its own classification. The `apply_provenance_tag` obligation is honoured where the target supports tags; where it does not, the target is already `always` tainted on read, so the obligation has nothing to add.

### 5.2 Propagation

- **Run.** The run is `exposed` from the first tainted input to the end of the run. Policy uses this flag. A runtime may additionally claim per-item provenance; the claim is recorded as the runtime's and narrows nothing in policy.
- **Child runs and returns.** The full run state passes to `handoff` and `service` children; a child's return carries the child's exposure.
- **Memory.** Anything written during an exposed run is stored tainted and returned flagged.
- **Systems of record and sink stores.** A write during an exposed run carries the obligation `apply_provenance_tag`. Systems that support the tag store it per field, and reads of those fields return tainted through `per_item` tools. Systems that do not support it are `agent_writable` without `provenance_tag`, so every agent read from them is `always` tainted (5.1).

### 5.3 `sanitize` nodes and sanitizers

A sanitizer is a registered, versioned, deterministic function with a declared input and output schema: a structured parser, a schema validator with an allow-list, a numeric or enumerated extractor, the rendering sanitizer. It clears taint from its *output* only; the input remains tainted. The PEP executes it and writes `sanitize.result` with what was accepted and rejected; only a `sanitize` node may call a sanitizer, and only its result mints `sanitized` provenance. A model is never a sanitizer.

Clearing taint does not make a value authoritative. A sanitized `(device_id, part_sku, amount)` is still a model-chosen value; the anchored bound on the effect node decides whether it may be acted on (4.3).

**Rendering sanitizer.** Removes hyperlinks, image and media references, data URIs, query strings, and runs of encoded data above a registered length; passes plain text and declared structured fields. Imposed on every `output` node of an exposed run.

### 5.4 Policy effect

The PDP receives `exposed`, `tainted_reads`, and `data_classes_touched`. The baseline policy pack ships these rules:

- Exposed: effects whose `destination` resolves outside the trust boundary are allowed only where the destination is anchored by the node's bounds and every content-bearing parameter carries provenance `template` or `sanitized` (A.3); otherwise held with cause `exposure`. Exposed and has touched private data: in addition, state changes only within the node's bounds (a call outside them is denied, as always), and any other call that the pack does not allow is held.
- Every effect counts against per-agent, per-subject, and per-destination velocity limits; on exposed runs the limits are tighter.
- Approver views flag tainted reads.
- Bounds anchor to the subject, the acting user, or a registered scope (4.3); a tainted or model-chosen value cannot serve as an anchor.
- `require_sanitizer` on every `output` node of an exposed run.
- `apply_provenance_tag` on every `delivery` and `internal_store` call, and on every effect of an exposed run whose target supports tags.

---

## 6. Failure and recovery (D5)

### 6.1 Tiers of degradation

"No-factor" means an effect with no factor on a run that is neither exposed nor delegated (no acting user). "Other" is everything else. Compensation requests follow the compensation column.

"Scope-anchored" means a no-factor effect whose bounds use only scope anchors and predicates on constants, so no PIP relation is needed. Deliveries follow the no-factor column, with the rendering sanitizer applied locally.

| Component down | No-factor effects | Other effects | Compensation and replay | Reads of `restricted` | Other reads | Runs in flight |
|---|---|---|---|---|---|---|
| **EVS** | Continue; `decision` and `effect.*` to the signed journal; central counters (RUN is up) | Stop; hold → park | Continue, journaled | Stop | Continue, journaled | Park at next other effect |
| **PDP** | Scope-anchored ones continue by PEP-local evaluation of the cached bundle, central counters, until the stop list is stale; PIP-anchored ones stop | Stop | Continue (mapping and key checks are local to the bundle), even with a stale list | Stop | Scope-anchored reads continue on the bundle until the stop list is stale; reads with PIP-anchored bounds, and reads over `per_agent` sources on delegated runs, stop | Park at the next PIP-anchored or other effect, or when the list is stale |
| **RUN** | PEP-E surfaces: scope-anchored ones continue on local checkpoints, local hook records, local counters, journaled; S1: stop | Stop (no holds, no central counters) | Stop (nothing instructs) | Stop | PEP-E: continue; S1: stop (no hook confirmation) | PEP-E: continue through scope-anchored no-factor nodes on local checkpoints, park at the first node that needs RUN; S1: park at once |
| **IDS** | Continue only for further calls in the same node to an audience holding a live credential (none on S4) | Stop | Stop (needs a fresh credential) | Stop | Continue only with a live credential, same node | Park when a new credential is needed |
| **PIP** | Scope-anchored ones continue; PIP-anchored ones stop | Stop | Continue | Stop | Scope-anchored reads continue; reads with PIP-anchored bounds, and reads over `per_agent` sources on delegated runs, stop | Park at next PIP-anchored node |
| **Stop-list channel** | Continue until the list is stale, then stop | Stop | Continue | Stop once stale | Continue | Park when the list is stale |
| **REG** | Continue on the signed, cached release and manifests; no new releases, no re-registration | As left | Continue | As left | Continue | Unaffected until a cached manifest expires |
| **MGW** | Continue for nodes needing no model call | As left | Continue | Continue | Continue | Park at the next model call |

Parking under degradation is itself journaled, so no run is silently half-done (I7). On recovery, journals reconcile into EVS in order with a `journal.reconciled` event naming the gap, and any local counters merge into RUN's.

### 6.2 What never degrades open

Factored effects, effects on exposed or delegated runs, reads of `restricted` data, new credentials, PIP-anchored bounds without the PIP, and any effect other than compensation or replay once the stop list is stale. These are what an attacker gains by taking the control plane down, so they do not degrade. Compensation and replay degrade open against EVS, PDP, and PIP outages because they only re-perform or reverse what was already decided; they still need RUN to instruct and IDS to issue. For that reason RUN, PDP, EVS, IDS, and each PEP-P carry an availability objective at least equal to the most critical system they front, and a latency budget per decision that includes the evidence acknowledgement path; the objective and budget values are deployment content.

### 6.3 Recovery path

For what the degradation tiers do not cover: the enforcement path is unavailable or compromised, a compensation is undeclared or fails, or a parked run needs an action outside its graph.

- **Recovery identities** are provisioned in advance, vaulted, released by two named people, and accepted directly by systems with `recovery_accepted`. This is the declared exception to I1 and I3 (section 1).
- Every release opens an incident. Every action under it is recorded by hand if EVS is down and reconciled afterwards as `recovery.used`.
- Recovery actions are taken by operations staff, never by an agent runtime, and never by the person who built the affected agent.
- Use outside drills is a published measure with a target of zero.

---

## 7. Deployment patterns per surface (D1)

| Surface | Example | PEP | RUN | Identity binding | Governed | Tiers | Compensating controls |
|---|---|---|---|---|---|---|---|
| **S1 Platform** | Low-code or managed agent platform | PEP-P | Central; platform implements the hook contract, including the graph and signed node headers | Platform is the attested workload; asserts agent and node per call | Yes | A0 agents; A1–A3 | Platform treated as a critical supplier; platform version in the release; tool egress pinned to PEP-P; native memory registered as a `memory` store, native retrieval as a `derived_store`, and native models routed through PEP-P to MGW, or each disabled |
| **S2 Code** | Engineered agents, pipelines | PEP-E (sidecar for A3; SDK permitted to A2) | Central via the PEP-E client | Workload attestation including the PEP-E build hash | Yes | A0 agents; A1–A3 | SDLC; release bundling in CI; orchestrator integrity controls (signed images, admission control, runtime attestation); workload egress pinned to PEP-E and MGW by orchestrator network policy |
| **S3 Embedded** | Agents inside purchased software | None of ours | Vendor's | Vendor's grants in the identity provider, restricted and reviewed | No | Not applicable | Grant restriction; vendor logs imported as `external.imported`; contract terms |
| **S4 Developer tools, with PEP-E** | Coding agents whose host embeds PEP-E | PEP-E | Central via the PEP-E client | Workstation attestation including the PEP-E build hash; session-scoped delegation | Yes | A0 agents; A1 | Device policy; repository and pipeline controls |
| **S4 Developer tools, without PEP-E** | Other workstation agents | None | None | Short-lived scoped tokens per session | No | Not applicable | Device policy; repository and pipeline controls; registered as ungoverned |
| **S5 Browser and desktop control** | Agents driving a user interface | None | None | A dedicated restricted account per agent, never the user's own | No | Not applicable | Session recording; account restriction; device policy; registered as ungoverned |

Rules that follow:

- A surface is governed only with both a PEP and the hook contract; a surface without RUN integration is ungoverned, and a governed surface's behaviour during a RUN outage is the degradation row in 6.1. A platform that cannot implement the contract, or cannot disable or register its native memory, retrieval, and models, is ungoverned.
- A governed runtime holds no state across runs outside a registered `memory` store; on S1 that includes platform conversation or thread state, which is registered as `memory` or disabled. On S2 this is a build rule checked in review, not enforced at runtime, and is residual R-13.
- One system is registered once, under one `kind`; REG refuses a second registration of the same endpoint, and the owning team attests at registration that no other endpoint reaches the same data.
- Every run carries a wall-clock budget from policy; a `RUNNING` run that exceeds it is parked for the resolver even if heartbeats continue.
- Ungoverned surfaces are recorded with their class, the controls applied, and the owner who accepted the gap. The invariants make no claim for them. Writes by ungoverned agents pass through no registered tool and so do not set `agent_writable` (R-7).
- Fleet stop reaches governed surfaces through the list; for ungoverned surfaces it is a runbook step.

---

## 8. Worked flow: a warranty replacement agent

A device-support portal authenticates a customer and raises a fault ticket. The ticket is a registered `subject_claim` trigger from a system with `external_ingress = true`, so the ticket payload is untrusted; `subject = customer_id` travels in the signed envelope, outside the payload, and is trusted because the portal authenticated the customer before signing and its registration records how. There is no acting user: the customer is the subject, not a principal. The principal chain is the agent alone.

1. `run.created`: subject recorded; `exposed_at_start = true`. Taint applied to the ticket body.
2. `read` node: look up the customer's registered devices. The device tool reads `confidential` data and declares `device_id` as its `resource` parameter, so the anchoring rule (4.3) requires an anchor: `PIP.owner(parameters.device_id) == subject`. The model may name any device id; the read is allowed only if that device is registered to the customer who raised the ticket. The data class enters run state.
3. `loop` node: the model reasons about warranty eligibility from the fault description, the purchase date, and prior claims, with read tools only, under a step cap and a token cap. It concludes a proposed `(device_id, part_sku, amount)`, where `amount` is the replacement's declared value from the parts catalogue.
4. `sanitize` node: an identifier-and-numeric extractor turns the proposal into typed values; `device_id` and `part_sku` must match their registered identifier patterns and `amount` must be numeric; `sanitize.result` is written. The sanitizer's output schema has no free string field, so its accepted values carry `sanitized` provenance (A.3). They are untainted content and still model-chosen.
5. `effect` node, replacement shipment through the fulfilment system. Factors from the manifest: `external`, because the `destination` parameter is of class postal address and resolves outside the trust boundary; `regulated` only if compliance has set `compliance_flag` on the tool, which in this example it has not; not `irreversible`, because the manifest declares a compensation, `cancel_shipment`, mapped from the `shipment_id` in the original call's result. Bounds: `PIP.owner(parameters.device_id) == subject` (anchors `device_id`); `PIP.replacement_issued(parameters.device_id) == false` (a predicate, never an anchor); `parameters.destination == PIP.verified_ship_address(parameters.device_id)` (anchors `destination` through the anchored `device_id`, the form `p == PIP.rel(q)`); `amount ≤ auto_limit` to allow, `≤ hard_limit` to hold, beyond it deny. The policy pack's per-subject and per-destination velocity limits apply on top, as holds; the per-destination limit is what catches many replacements to one address under different customer ids. The verified ship address can anchor because the fulfilment system tags the field and marks it verified through an authenticated channel: the customer confirmed it inside the authenticated portal session. An address typed into the ticket body is payload, tainted, and fails the bound. Had the address been a plain field that any registered tool could write, the relation would not be anchor-capable and could not anchor anything (A.1). The `resource` and `destination` parameters are anchored, so the node passes the anchoring rule. Being `external`, the node defaults to A1; it is A2 with bounds approved by the owner and the risk owner, and by security because the destination resolves outside. The intersection evaluates the agent's own entitlement to the shipment tool. The run is exposed and has touched private data, so the baseline pack applies: the destination is anchored and the one content-bearing parameter, `part_sku`, carries `sanitized` provenance, so the exposure rule permits the call. Counters are reserved first, then the decision. Under the auto limit: allow, with the obligations `dlp_check` (the destination resolves outside) and `apply_provenance_tag` (an exposed run writing to a system that tags fields); `decision` written and acknowledged; a `per_agent` credential to the fulfilment system; execute; `effect.executed`; counters confirmed. Between the limits: hold with cause `limit_band`; reservation released; grant minted; approver view with the ticket excerpt flagged and the counters the call would consume; on approval the PEP re-reserves counters, resubmits with `approval_ref`, and on `ALLOW` writes the `decision`, waits for its acknowledgement, redeems the grant, and executes. Beyond the hard limit: deny; the denial branch routes the ticket to a person. Had compliance flagged the tool, the node would also be `regulated`, but with a compensation declared it is still not `irreversible`, and the two-approver rule (4.4) needs both. If the run is later cancelled by a resolver, RUN instructs the PEP to execute the `compensate` node: `cancel_shipment(shipment_id)` with the parameter taken from the recorded result, decided with `purpose = compensation` and allowed only because the parameters equal the mapping over the recorded call. The cancellation succeeds before dispatch and fails after; a failed compensation parks the run for the resolver (4.9), and the owner may close it with a recorded disposition (4.8).
6. `effect` node, reply. Roles: `destination` is the address parameter (class: email address), anchored to `address_on_file`, a field the identity system marks verified through an authenticated channel; `resource` is `none`, approved by security because a templated reply acts on no record. Factors: `external`, and `irreversible`, since a sent message has no reversing tool and the manifest declares `compensation = irreversible`. Bounds: `template_id ∈ release.templates`; `parameters.destination == PIP.address_on_file(subject)`, the form `p == PIP.rel(A)`. The node is A2 with bounds approved by the owner, the risk owner, and security. A destination taken from the ticket fails the bound. The message body is a template, so every content-bearing parameter carries `template` provenance and the exposure rule permits the call.
7. `output` node to the case-log delivery tool, whose target is an internal provenance-tagged sink store: the run is exposed, so `require_sanitizer` applies; `apply_provenance_tag` marks the entry tainted; `delivery.executed` is written. `run.completed` carries `exposed = true` and the data classes touched.

What this does not prevent: a real customer whose device is not faulty talking the agent into an under-limit replacement. The eligibility loop, the auto limit, the velocity holds, and post-hoc sampling bound that loss. They do not remove it (R-10).

---

## 9. Declared residual register

Risks the architecture accepts in writing. Each has an owner who records acceptance in the registry.

| # | Residual | Where declared | Bound by |
|---|---|---|---|
| R-1 | A multi-tenant platform (S1) asserts which agent and node a call belongs to; a compromised platform can obtain any hosted agent's credentials | A.2 | Platform as critical supplier; platform version in every release; egress pinning |
| R-2 | On S4 the credential binding is to a device, weaker than server attestation | A.2 | Per-call credentials; A1 cap |
| R-3 | In the SDK form of PEP-E, builder code shares the process and could extract a credential | A.4 | SDK form limited to A2; sidecar form for A3 |
| R-4 | A host with root can tamper with a running PEP process | A.4 | Attestation; S4 cap; orchestrator integrity controls on S2 |
| R-5 | Compensation and replay need RUN and IDS; during their outage recovery falls to the recovery path | 6.2 | Availability objectives (6.2); recovery identities (6.3) |
| R-6 | A system of record fed by an integration that is not registered in `sources[]` inherits no taint | A.1, 5.1 | Feed registration and feed review (A.1); access reviews (A.1) include `sources[]` |
| R-7 | Content written by ungoverned agents (S3, S5, S4 without PEP-E) does not set `agent_writable` | 7 | Vendor-side controls; owner acceptance |
| R-8 | A registered source that mis-declares how it authenticates its subject makes an attacker-chosen subject a trusted anchor | A.1 | The registration condition in A.1; review of trigger registrations on the access-review cycle |
| R-9 | A tool registered with `resource = none` is unanchored | A.1 | Security approval per tool |
| R-10 | A real customer whose device is not faulty can obtain an under-limit replacement | 8 | Eligibility loop; auto limit; velocity holds; sampling |
| R-11 | `spend_to_date` is stale within a node | A.8 | Token cap enforced by RUN via `cap_reached` |
| R-12 | Erased payloads make a run not fully reconstructable | A.6 | `erasure.applied` event |
| R-13 | A governed runtime on S2 could keep tainted state in process memory across runs | 7 | Build rule checked in review |
| R-14 | Retrieval over a derived store uses entitlements as fresh as its last sync | A.7 | Registered cadence; event-driven sync required for `restricted` |
| R-15 | On S4, device egress cannot be fully pinned to the PEP, so builder code could call out directly | Appendix C | Device policy; A1 cap; repository controls |
| R-16 | An effect in doubt is resolved by replay even under a stop whose intent was to prevent that tool acting | 4.9 | Replay only re-presents an already-decided action with its recorded key |
| R-17 | A person in an internal input role can paste external content that enters untainted | A.5 | Role registration; the same trust as a `user_session` prompt |
| R-18 | In the SDK form, and in a sidecar sharing a pod's network identity, egress pinning cannot separate builder code from the PEP | Appendix C | SDK form capped at A2; declared with R-3 |
| R-19 | Factor derivation rests on the manifest: a manifest that mis-declares a side-effect class, a data class, a compensation, or a parameter role, or omits a `destination` role, derives the wrong factors | A.1 | Manifests authored by the owning system team and approved by security and compliance; schema-hash check against the live tool; manifests reviewed on the access-review cycle |

---

## 10. Verification record and provenance

**Provenance.** Developed by [the author] in collaboration with an AI system. A decision document set out the problem, the invariants, and the options for six core decisions, which the author decided or accepted; [how drafting was divided, in the author's words]. Each version of the specification through internal 1.11 was then reviewed by a separate AI verifier that had not seen earlier versions, the rationale, or the fixes; the record is in the design rationale. Internal 1.12 applied the twelfth verifier's two fixes without re-verification. Internal 1.13 restructured 1.12 for publication, renamed terms, and replaced the worked example, and was verified in round thirteen; internal 1.14 applied that round's findings and was verified in round fourteen; internal 1.15 applied round fourteen's findings and was verified in round fifteen; internal 1.16 applied round fifteen's findings and was verified in round sixteen; internal 1.17, the text deposited here, applies the two clauses round sixteen required and is recorded below. Nothing has been built.

**Independent** means, throughout, that the verifier had not seen earlier versions, the design rationale, or the fixes made in response to the previous round. It does not mean a separate organisation or a separate model family.

**What each round did.** Each verifier read only the specification and was asked to reproduce nine known findings with concrete call sequences, to tag each as unsafe, blocking, minor, or absent, to list contradictions and anything unimplementable, and to give a verdict. The verdicts moved from structural conflicts (versions 1 to 1.5) through one-clause defects (1.6 to 1.11) to the twelfth verifier's statement that, with its two fixes applied, the remaining items were minor and the core could be frozen. Severity labels are the verifiers' own. The full table is in the rationale, Part D.

**Round thirteen, on internal 1.13.** The verifier found nothing unsafe or blocking: no sequence violated an invariant and every run reached a declared state. It returned NOT YET with nine required one-clause changes and eleven recommended ones, and stated that the text could be frozen once the nine were applied. The nine: a definition of effect that contradicted the registry rule for derived-store writes; a stop-scope rule in the decision point broader than the enforcement point's; a missing recovered-resume edge in the state machine; a residual bounded by a deferred section; a checkpoint that did not carry the result fields a compensation mapping needs; a hold with no path when the identity service is unreachable and substitution is not permitted; an unstated outcome for a node a resolver records as not executed; a read tool with an external target that could carry run data out in its parameters, which the definition of effect covered but no rule enforced; and the normative status of sections 4 to 7. A separate check compared 1.13 with 1.12 sentence by sentence and found no normative loss from the restructure. Internal 1.14 applies all twenty items and the loss check's notes. The one change of mechanism is the eighth: a tool whose target is outside the trust boundary cannot carry `side_effect_class = none` (A.1).

**Round fourteen, on internal 1.14.** Nothing unsafe. NOT YET, with five required one-clause changes and fourteen recommended: one contradiction inherited from 1.12 (the state machine closed an escalated run on the owner's deadline while the text allowed only the owner to close one, and the closing event required a disposition nobody supplied); the external-target rule from round thirteen extended one hop, to a tool with an internal target that forwards an outward-resolving `destination`; a system outside the trust boundary whose owner could author `external_ingress = false`; a `dlp_check` rejection that left an effect node in doubt; and a version label. Internal 1.15 applies all nineteen items.

**Round fifteen, on internal 1.15.** All nine findings closed except one minor partial (a delivery target registered outside the trust boundary). NOT YET, with two required one-clause changes, both wording whose literal reading changed behaviour (a read-node rule broader than the degradation matrix; an in-doubt clause that would re-park a successfully replayed node), and twenty-five recommended. Internal 1.16 applies both and twenty-two of the recommended items; it adds residual R-19 (manifest honesty) and states the consequence of the external-target rule: a read of a system outside the trust boundary is an effect node, never a `read` or `loop` node.

**Round sixteen, on internal 1.16.** Seven of nine findings closed, two partial and minor. Nothing unsafe and nothing blocking. NOT YET, with two required one-clause changes, both introduced by the previous round's fixes: the wall-clock-budget park had been placed in the list of parks that resume without a resolver, which contradicted section 7 and admitted a restart loop; and the external-target rule declared that such a tool's calls fall under rules keyed on a `destination` resolving outside, without saying how a tool with no `destination` role resolves. The verifier stated that with those two applied the text could be deposited, and listed sixteen recommended items, none touching an invariant or a core decision. Internal 1.17 applies the two required clauses and two of the recommended ones that are pure registry refusals (memory and derived stores confined inside the trust boundary; recipient roles resolving only to principals inside it); the remaining fourteen are listed in the changelog for v1.1. 1.17 has not been re-verified; the four clauses it adds are refusals and a list correction, none of which opens a path.

**Summary.** Sixteen rounds on internal versions 1 through 1.16. The required items per round over the publication rounds were nine, five, two, and two; from round fourteen on, every required item was a one-clause wording defect, and from round fifteen on, every required item was one the previous round's fixes had introduced.

---

## 11. How to cite, revision policy, and changelog

```
[Author]. "[Title]" ([Short name]), v1.0. azimuth.ink, [YYYY-MM-DD].
Deposited [timestamp]. CC0 1.0 Universal. [URL]
```

Cite the version and the section. Section 4.3 of v1.0 may not be section 4.3 of v1.2.

**Revision policy.** This paper is a living document. Each revision receives a new version number (v1.1, v1.2) and is re-deposited with its own timestamp. Earlier deposits remain available unchanged, and each remains the prior-art record for what it contains. The changelog below records, for each version, what changed and in which sections, maps any renumbered section to its predecessor, states the internal specification version the text corresponds to, and states whether that text was itself verified. The residual register is updated as residuals close or are added: a closed residual keeps its number and is marked closed, with the version and the mechanism that closed it, and is never deleted; a new residual takes the next number. Each change to the core is recorded in the design rationale with the alternative rejected and the tradeoff accepted. A pattern built on this architecture supplies tool manifests and capability records, policy packs, PIP adapters, trigger registrations, sanitizers, store registrations, PEP builds and runtime hooks, hosting records, evidence consumers, evaluation thresholds and sampling rates, runbooks, supplier controls, and builder aids; anything else it needs is a change to the core. Clarifications, added mechanisms, and residual updates are minor versions; a change to an invariant or to a core decision is a major version.

**Changelog.**

*v1.0, internal specification 1.17.* First deposit. Relative to internal 1.12, the text was restructured for publication (internal 1.13; no mechanism was changed by the restructure) and then corrected on the thirteenth verification round (internal 1.14). Corrections in 1.14 to 1.17 by section: 0 (effect definition; new rows for `untrusted_source`, denial and failure branches, policy values, risk owner, access-review cycle, drill); 1 (I2 wording, "never shared with another agent"); 3 (items 5, 8, 12 aligned with the appendices); 4.1 (taint accounting per call); 4.4 (two approvers for a node with both factors and no `amount` role); 4.8 and B.1 (recovered resume from `PARKED`); 5.1 (human input as a taint source); 6.2 (availability objective and latency budget restored from 1.12 section 6.3); 7 (ungoverned writes and `agent_writable`); 8 (identifier patterns, obligations, decision written before redemption); 9 (R-5 bound); A.1 (no `none` class for a tool with an external target, which is the one mechanism change; email as a destination class; cycle naming); A.2 (substitution only where permitted; `acting_user` anchors under substitution); A.3 (stop-scope rule narrowed to effects, deliveries, spawns, and restricted reads; replay rule wording; entitlement wording); A.5 (run-start identity check; checkpoint carries mapped result fields; preview data classes; hold when IDS is unreachable; re-entry after a resolver's `not_executed`); A.8 (`spend_to_date` freshness; budgets as policy content); Appendix C (R-18 pointer). In 1.15: 4.8, B.1, and Appendix D (OPS closes an escalated run on the owner's deadline with disposition `owner_deadline_passed`); A.1 (`none` refused also for a tool with an outward-resolving `destination` role; `external_ingress` derived for systems outside the boundary; substitution as a resumption path only without `acting_user` anchors); A.4 and Appendix D (`dlp_check` rejection is a definitive negative, `error = dlp`, failure branch); A.5 (in-doubt keyed on `purpose = normal` decisions; a bounded count of indeterminate replays; `handoff` and `service` nodes with a live child are not re-entered; out-of-order `node_entered` hooks rejected); 4.9, A.4, and 0 (deliveries and spawns named under a stop); 4.2 (`restricted` read rule stated); 7 (A0 as agent class in the tiers column); Appendix D (`resolver` and `deadline` required on parks and escalations). In 1.16: 4.2 (restricted-read refusal tied to the 6.1 rows); 4.4 (two approval records on one hold; "write credentials or keys"); 4.8 and B.1 (OPS close unconditional and in the state's definition; auto-resume list; new PARKED edges); 4.9 (stale list behaves as a fleet stop); 7 ("one system"); 9 (R-9 covers every tool; R-16 pointer; new R-19); A.1 (interfaces and sink stores inside the boundary; `provenance_tag` not registrable outside; sanitizer only from a `sanitize` node in the linter; consequences of the external-target rule stated; `launcher` labelled per agent; manifests in the access review); A.2 (unseen replay key is a first execution); A.3 (hold history attached to `original_ref`); A.4 (obligation order); A.5 (in-doubt keyed on the latest `effect.*` event; continuation after replay or resolver; `record_outcome` carries result fields; `not_executed` error; child of a cancelled parent; PEP-E next-node rule during a RUN outage; `acting_user`-anchored holds wait for IDS); Appendix D (`approvers[]`, `not_executed`); 0 and 3 aligned. In 1.17: 4.8 (wall-clock park needs a resolver); A.1 (a tool with an external target resolves outside for every destination-keyed rule; memory and derived stores confined inside the boundary); A.7 (recipient roles resolve inside the boundary). Recommended by round sixteen and deferred to v1.1: `approval_records[]` in the IDS contract and the two-approver substitution rule; the rendering sanitizer as a PEP-applied obligation rather than a tool; a cross-reference from 4.9 to the OPS close; "park at that effect" in the 6.1 stop-list row; delivery behaviour on exposed and delegated runs in 6.1; the channel on which `anchor_version` reaches the PDP; a replay that returns `effect.failed`; resolver outcomes for nodes whose evidence cannot be recovered; A2 on a node with no `amount` role; the park and escalation deadline as a policy value; parks rather than cancellations under a stale list; the `launcher` row's placement; and wording in 0, 2, 3, and B.1. Not adopted from round fifteen: a compensation value for tools whose only side effect is parameter egress (deferred to v1.1 with the rest of the external-read consequences), the registration of recipient roles, and the event sequence for a recovered return to `HELD`. Identifiers `sink` (the `delivery.*` event field and the `release.sinks` bound) and the `scope` field of events outside a run keep their 1.12 names.

| Internal 1.12 section | v1.0 |
|---|---|
| Header table | Front matter; "What this is and is not"; section 10 |
| 0 Terms | 0, expanded |
| 1 Invariants | 1, with the six core decisions listed |
| 2 Components, intro | 2 |
| 2.1 to 2.9 | A.1 to A.9 |
| (new) | 3 Mechanisms |
| 3.1 to 3.7 | 4.1 to 4.7 |
| 3.8 Run states | 4.8 (terminal-state rules); B.1 (state machine) |
| 3.9 Stops | 4.9 |
| 3.10 Resolvers | B.2 |
| 4.1 to 4.3, 4.5 Identity flows | Deferred to v1.1 as sequence restatements of A.2 to A.5; the `per_agent` entitlement check of 4.5 is folded into A.3 |
| 4.4 Handoff and service | Credential details into A.2; the remainder is 4.7 |
| 4.6 Rotation and review | A.1 |
| 5 Taint | 5 |
| 6.1, 6.2 | 6.1, 6.2 |
| 6.3 Availability targets | The objective and budget requirement is in 6.2; published measures deferred to v1.1 |
| 6.4 Recovery path | 6.3 |
| 6.5 Drills | Deferred to v1.1 |
| 7 Surfaces | 7 |
| 7.1 Hosting | Appendix C |
| 8 Evidence schema | Appendix D |
| 9 Extension points | Deferred to v1.1; its one rule is in the revision policy above |
| 10 Worked flow | 8, with the domain changed from a refund to a warranty replacement, and a `compensate` node added |
| 11 Residual register | 9 |

Renamed in v1.0: the parameter role `subject_resource` is `resource`; "sink tool" and "output sink" are "delivery tool"; "sanitization node" and "sanitization step" are "`sanitize` node"; "evaluated route" is "declared route"; "materiality threshold" is "two-approver threshold"; "the risk function" is "the risk owner"; the evidence chain is "witnessed", reserving "anchor" for bounds; "Enforcement Point" is "Policy Enforcement Point". Notation: `purpose = x` for both requests and credentials; "S4 with PEP-E" throughout.

---

## Appendix A. Component contracts (normative)

Each component's holdings, rules, and contract. Section 2 orients; this appendix governs.

### A.1 REG, Registry

The system of record for what exists and what it may touch.

**Holds:** agents (owner, builder, surface, class, controls applied, tiers per effect node, expiry); releases; the tool catalog, including an **agent tool** per agent and per registered service (`tool_id = agent:<id>`, class `spawn` by derivation) through which `handoff` and `service` nodes are decided; system capabilities; the sanitizer catalog; triggers; services; the **boundary definition** (the address spaces, domains, and systems that count as inside), against which the PEP resolves whether a `destination` is outside.

**System capabilities**, one record per system of record, authored by the owning team, approved by security and compliance:

| Field | Purpose |
|---|---|
| `kind` | `system_of_record`; `sink_store` (append-only, provenance-tagged, never the target of a side-effect tool); `interface` (the enterprise delivery surface, stores nothing); `derived_store` (index, embedding store, cache); `memory`. Derived stores, memory, and sink stores are DBS-managed. A `sink_store` may not appear in any `system_of_record`'s `sources[]`. REG refuses `kind = interface`, `sink_store`, `memory`, or `derived_store` for a system outside the boundary definition, so neither a delivery nor a decided non-effect write ever leaves the trust boundary; sending content outside is an effect (4.2). |
| `sources[]` | The systems whose content feeds this one by any path outside agent tool calls (sync pipelines, integrations, replication). Registrable for any kind, required for a `derived_store`. `external_ingress` and `agent_writable` are **derived** as true if true for the system itself or any source; `provenance_tag` is derived as true only if the system and every source carry tags and the registered feed has passed a **feed review**: a recorded test, repeated on the access-review cycle (A.1, Rotation and review), that tags survive the feed. A `memory` store and a `sink_store` are `agent_writable` and `provenance_tag` by definition. |
| `launcher` | A per-agent field, held on the agent record rather than the system record: the orchestrator RUN calls to start that agent's runtime for a child run |
| `presentation` | `chained` or `per_agent` (A.2) |
| `recovery_accepted` | Accepts recovery identities directly |
| `agent_writable` | **Derived**: true if any registered writing tool targets this system; an `interface` stores nothing and is never writable or readable |
| `external_ingress` | Content from outside the trust boundary enters it (mail, tickets, forms, web). **Derived** true for any system outside the boundary definition; authored otherwise |
| `provenance_tag` | Stores and returns a per-field provenance tag, and tags fields that arrived through external ingress as untrusted. Not registrable for a system outside the boundary definition, whose tools are therefore `always` |
| `preview_tool`, `idempotency` | The registered read tool (`side_effect_class = none`, with its own `reads_data_class`) that calls the system's preview endpoint (a dry run that changes nothing), if one exists; its `untrusted_source` is derived like any tool's, so a preview of an untrusted system taints the run and is flagged in the approver view; idempotency-key support |
| `pip_adapter` | Answers ownership and status questions about its resources. Each **relation** it offers is registered with the set of `(system, field)` it is answered from, including every field a join traverses. A relation is **anchor-capable** only if every backing field is in a `system_of_record` that is neither `external_ingress` nor `agent_writable` by derivation (which follows `sources[]`), or that carries `provenance_tag` and marks the field as verified through an authenticated channel; and none of the fields is in any registered tool's `writes_fields[]`. Anchor capability is a REG-maintained property, recomputed whenever a manifest, a system capability, a `sources[]` entry, or a feed-review result changes. REG refuses to register a writing tool or a feed that would remove anchor capability from a relation any published release depends on, unless the owner of each such release first republishes without it. A change REG cannot refuse (a truthful capability-record update, a failed feed re-review) suspends every published release that anchors on the affected relation: its effects resolve by denial until it is republished, and the owner is notified. The decision request carries the anchor-capability version REG stamped on the release, and the PDP denies a call whose anchors are no longer capable. |

**Tool manifest**, one per tool version, authored by the owning system team, approved by security and compliance. Agent builders consume manifests; they do not write them.

| Field | Purpose |
|---|---|
| `tool_id`, `version`, `schema_hash`, `target_system` | Identity; the hash covers the argument schema and the description the model sees; the target system's capability record |
| `side_effect_class` | `none` · `internal_store` · `delivery` · `spawn` · `reversible_internal` · `external` · `financial_legal`. **Partly derived:** `internal_store` is derived for any writing tool whose target is of `kind = memory`; `delivery` for any tool that sends content to a target of `kind = interface` or writes to a `sink_store` (a read tool over a sink store is `none` and `per_item`); `spawn` for agent tools; these three cannot be authored. The effect classes and `none` are authored and approved, except that REG refuses `none` for a tool whose `target_system` is outside the boundary definition, or whose `parameter_roles` declare a `destination` whose class can resolve outside it: a call to such a tool sends its parameters outside the trust boundary, so the tool carries an effect class, its calls are effects with the `external` factor, and their content-bearing parameters fall under the exposure rule (5.4); for every rule keyed on a `destination` resolving outside the trust boundary (the `external` factor, the exposure rule in 5.4 and A.3, `dlp_check` in A.3 and A.7, and security approval in 4.4), a tool whose `target_system` is outside the boundary definition resolves outside, its registered target counting as the anchored `destination`. It follows that a read of a system outside the trust boundary is an `effect` node, never a `read` or `loop` node, is `irreversible` unless a reversing tool exists, and defaults to A1; and that a system outside the trust boundary has no `preview_tool`. **Node-type matrix, enforced by the linter and at runtime by the PDP, which denies any call to a tool the node does not declare in the release:** `read`: `none` or `internal_store` tools; `loop`: `none` tools only; `sanitize`: one sanitizer (`none`); `effect`: exactly one effect-class tool, plus its system's `preview_tool` when instructed by RUN; `compensate`: the mapped reversing tool; `output`: exactly one `delivery` tool; `handoff` and `service`: one `spawn` tool. |
| `bulk` | One call can change many records |
| `compliance_flag` | Set by compliance; every call is `regulated` |
| `reads_data_class`, `writes_data_class`, `writes_fields[]` | Classification of what the tool returns and changes, and the `(system, field)` list it can change. A **writing tool** is one with a non-empty `writes_fields[]`. A writing tool whose target is a `system_of_record` or `derived_store` must carry an effect class; REG refuses `none` for it. |
| `untrusted_source` | **Derived** from the target system: `per_item` if `provenance_tag`; else `always` if `external_ingress` or `agent_writable`; else `never`. Not authorable. |
| `parameter_roles` | Which parameters are `resource`, `destination`, `amount`. A `destination` carries a **destination class** (network location, payment instrument, email, phone, or postal address, account identifier); the boundary definition says, per class, how a value resolves inside or outside. Every tool with a side effect, and every read tool whose `reads_data_class` is above `internal`, declares a `resource`, or `none` with a security-approved justification. |
| `compensation` | A parameter mapping, expressed only as field references into the original call's recorded `parameters` and `result`, onto the reversing tool; or `irreversible` |
| `maintainer` | A named person |

The PEP hashes the tool's live schema and description whenever the tool server supplies them (at session start with the server and on any call that carries them), and on S1 the platform supplies the description it renders to the model through the hook contract so PEP-P can hash that too, and compares with `schema_hash`; on mismatch the tool is unregistered (I5) until re-registered. The delivery tool an `output` node names is one whose target is of `kind = interface` or `sink_store` (4.2).

**Factor derivation**, computed by the PEP per call:

| Factor | Present when |
|---|---|
| `irreversible` | `compensation = irreversible` |
| `external` | `side_effect_class ∈ {external, financial_legal}`, or the `destination` parameter resolves outside the trust boundary. For the linter, a `destination` whose class can resolve outside counts as a static `external` factor. |
| `regulated` | `side_effect_class = financial_legal` or `compliance_flag` |
| `sensitive` | `reads_data_class` or `writes_data_class` is `restricted`, or `bulk` |

**Trigger registration.** `trigger_id`; source system and the workload key it signs with; `kind` (`user_session`: a person is present and the runtime holds their token; `subject_claim`: the source asserts whom the run is about; `event`: neither); `subject_claim` schema; schedule or event. A trigger has a **signed envelope** (trigger id, kind, subject claim, timestamp) and a **payload**. The envelope is trusted because the source signed it with its registered workload key; the subject claim is a field of the envelope and is never part of the payload. A `subject_claim` trigger is registrable only if the source authenticates the subject (a session, a signed identifier from the identity provider, or an account lookup keyed by an authenticated channel) before signing, and the registration records how; a subject parsed from content is not registrable. **Payload trust is derived** from the source system by the same rule as `untrusted_source`: per-field from tags if the source has `provenance_tag`, any untagged field from such a source being treated as tainted; untrusted if it has `external_ingress` or `agent_writable`; trusted otherwise.

**Release linter.** A release is publishable only if: it has a graph with a stable node id per node and declares its surface and PEP form, the surface equal to the agent's registered surface; no node's tier exceeds the cap for that surface and form (S4: A1; SDK form: A2); no effect node carrying any factor is A3; a fast-path claim is accepted only if the graph has no `effect` node, no tool in it has `reads_data_class` above `internal`, and it has no `handoff` or `service` node; every node that is `irreversible` and `regulated` has an auto limit at or below the two-approver threshold, and is A1 if its tool has no `amount` role; every node calls only tools its type may call under the node-type matrix, and no node other than a `sanitize` node calls a sanitizer; every `read`, `loop`, `effect`, and `output` node's bounds pass the anchoring rule (4.3), an `output` node's bound being its recipient for an `interface` target (`recipient ∈ release.recipients` or `recipient == acting_user`) or its store for a `sink_store` target (`sink ∈ release.sinks`), and `compensate` nodes being exempt because the mapping fixes their parameters; every anchor relation is anchor-capable in REG at publish time, and remains so by the REG refusal rule above; every effect node declares a `compensate` node or `irreversible`; every `output` node names a delivery tool whose target is of `kind = interface` or `sink_store`; every held effect has a resumption path (grant permitted, or substitution permitted, substitution counting only for a node with no bound anchored to `acting_user`) under the current policy bundle; the PEP version (PEP-E build, or PEP-P version for S1) is on the allow-list. When a new policy bundle is published, every release is re-linted; a release whose held effects lose their resumption path is flagged to its owner, and until it is republished those effects resolve by denial.

**Rotation and review.** Agent identities carry a root trust (a key or federation relationship) that rotates on the access-review cycle. Access reviews compare an identity's actual grants against the registry's permitted tools and data classes, and on the same cycle review trigger registrations, tool manifests, `sources[]` entries, and feed reviews.

**Enforcement hook.** IDS issues an agent identity only against a current REG entry; a lapsed entry suspends the identity (I5).

**Contract.** `register_agent`, `publish_release`, `get_release`, `get_tool_manifest`, `get_trigger`, `get_system_capabilities`, `get_sanitizer`, `suspend`.

### A.2 IDS, Identity Service

**Holds:** agent identities; workload bindings and the PEP-E build allow-list; delegation state for acting users; the record of each approved-action credential it issued; recovery identities.

**Agent identity.** One per agent, non-human, issued only against a REG entry, bound to the workloads REG permits to host it. A workload proves itself by attestation; the attestation of a PEP-E host includes the PEP-E build hash, and IDS issues credentials only when that hash is on the allow-list. A builder can host PEP-E but not alter it: an altered build changes the hash and gets no credentials. The allow-list records each build's form (sidecar, SDK, or proxy for PEP-P) and each workload binding records its surface class; IDS refuses a credential when the release named in the request declares a form other than the attested build's or a surface other than the attested workload's class, so a tier cap tied to form or surface cannot be evaded by declaration. A multi-tenant platform (S1) is one attested workload hosting many agents and asserts which agent a run belongs to; that assertion is a trust the architecture accepts and records (residual R-1).

**Who presents credentials.** Only a PEP bound to the agent's hosting workload presents a credential downstream. RUN never does. Previews, resumes, compensations, and replays are executed by the run's PEP on RUN's instruction; deliveries and child-run spawns are runtime-originated calls through the same PEP.

**Credentials.** Sender-constrained to the requesting PEP's workload identity (not a process instance, so a replacement instance of the same workload can present). Audience-bound to the target system. Lifetime at most one hour; a `normal` credential may be reused for further calls to the same audience within its lifetime and within the same node; `compensation` and `replay` credentials are issued per call. Model calls use the same mechanism: the PEP requests a per-node `model` credential and presents it to MGW on the runtime's behalf (model calls pass through the PEP like tool calls); MGW attributes tokens to the run and node and reports them to RUN (A.8). When RUN signals `cap_reached` for a node, the PEP refuses the node's next model credential request, which ends a `loop` node at its token cap.

**Binding strength by surface.** On S1 and S2 the workload is a server-side deployment with attestation. On S4 the workload is a developer's device; the key lives in the operating system's keystore bound to the PEP-E process as far as the platform allows, credentials are per call with no reuse, and the surface is capped at A1. The binding on S4 is weaker than on S2, and that is recorded as a declared residual.

**Acting user.** Exists for `user_session` triggers, and for one held action when an approver substitutes. The runtime holds the user's session token; IDS exchanges it for a delegated credential whose actor chain carries the user and every agent. `delegation_status(user)` reports whether that session's delegation is still valid; RUN calls it at approval and the PEP's redemption re-checks it. A `subject_claim` trigger creates no acting user: the subject is a bound anchor, not a principal, and the chain holds agents only until a substitution adds one for a single action.

**Downstream presentation (D3).**

| Capability | What the system sees | Who checks the acting user's entitlement, if there is one |
|---|---|---|
| `chained` | A token carrying user and agent chain | The system itself |
| `per_agent` | The agent's own credential | PDP, via PIP, before the call |

**Approval record.** When an approver decides through OPS, OPS forwards the approver's identity-provider assertion; RUN embeds its identifier and claims in the approval record, signs it, and marks it `grant` or `substitution`. IDS verifies RUN's signature and the assertion.

**Resumption grant (D4).** Minted at hold when policy permits one: single-use for redemption; bound to the action hash; audience IDS; encrypted under a hardware-backed key; stored by RUN. It expires at the approval timeout, or, if an approval is recorded before then, at the end of the resume window that follows the approval. After the PDP allows the resubmitted decision and the PEP has written that `decision` (A.3), a PEP bound to the agent's workload redeems the grant with the approval record. IDS verifies grant, signature, presenter binding, and (for an acting user) delegation status, then issues a credential to that workload, delegated where there is an acting user. RUN records an **approved-action record** for the action hash beside the hold, valid to the end of the resume window and invalidated on `effect.executed`, `effect.failed`, a later hold or denial of the same action hash, or stop. If the PEP instance fails before the `decision` was written, a replacement instance of the same workload obtains the grant from RUN (`instruct(resume)` carries it) and proceeds from the resubmission. If it fails after the `decision` was written, the node is in doubt (A.5) and is resolved by replay, under a credential with `purpose = replay` on the agent's authority, or by park; the replacement never executes afresh. `credential_for_approved_action` serves the substitution path only. IDS acts on a RUN-signed assertion of the record's current status presented with each request, so IDS needs no notification of effects or stops. The grant itself is invalidated on redemption, denial, timeout, stop, or a later hold of the same action hash, which also invalidates any earlier grant for that hash before a new one is minted. **Expiry and suspension.** The grant carries no clock of its own. IDS computes expiry from RUN-signed timer state presented at redemption (hold time, approval time, suspensions) and the policy values for the approval timeout and resume window. While a held run is parked for any reason (host loss or degradation, 4.8), RUN suspends both timers up to the policy value `max_park`; beyond it the timers run again. When the park was RUN's own outage, RUN reconstructs the suspension interval from its outage window on return and includes it in the timer state. An approval recorded during the park is honoured if the run leaves `PARKED` before the window expires. If the window expires after an approval, the hold is re-opened with the same causes and the same approver set, the discharged set cleared so the re-approval is a real decision, counting toward the re-hold maximum, recorded as `hold.resolved` with outcome `expired` and a new `run.held`. If the approval timeout itself expires while the run is parked beyond `max_park`, the hold is denied on recovery and the denial branch runs. 

**Reversal and replay authority.** Compensation and replay credentials are issued on the agent's and release's authority, carrying the original action hash and the original principal chain as a *record* claim, not as live delegation. Systems of record accept a credential with `purpose = compensation` or `purpose = replay` for reversing or re-presenting an action they already recorded under that hash; a system with idempotency support treats a replay whose key it has not seen as the first execution. The acting user's delegation is therefore not needed to undo or complete what it authorised. This is a design decision recorded in the rationale.

**Substitution path.** RUN marks the approval record `substitution` when policy permits substitution and no grant was minted, or when `delegation_status` at approval reports the delegation revoked and policy permits substitution. If IDS finds the delegation revoked only at redemption, it returns `revoked`; the PEP releases its reservation and writes `effect.failed` with `error = revoked`, so the node is not in doubt, and the approved-action record is invalidated by that event. The PEP reports to RUN, which, where policy permits substitution, opens a **new hold** for the same action hash with the single cause `substitution_required`, which counts toward the re-hold maximum; the approver approves it, RUN signs a fresh `substitution` record, and the PEP resubmits the decision with the approver as acting user (A.3) and proceeds by `credential_for_approved_action`. Where policy does not permit, RUN records a denial and the denial branch runs. Any other credential refusal after a resume `ALLOW` is handled the same way, so retries are bounded by the re-hold maximum. A bound anchored to `acting_user` is evaluated against the substituting approver on resubmission, so a node with such a bound resolves by denial under substitution. With a `substitution` record, the PEP calls `credential_for_approved_action`; IDS verifies the record and the approver's assertion, issues a credential with the approver as acting user and the original user recorded as the requested principal, and records the approved action. No grant is involved.

If the delegation is revoked and substitution is forbidden, the hold is denied and the denial branch runs. The linter guarantees at release that at least one path is permitted; revocation at runtime is handled by that denial rule.

**Handoff and service credentials.** On a `handoff`, the child's PEP requests credentials against the parent run's delegation state held by RUN and IDS (`exchange(run_ref, target_agent)`), yielding a chain extended by the target agent; the parent's own credential is never passed on. On a `service`, the child presents the service agent's identity, and the credential's claims carry the caller chain and the acting user.

**Recovery identities.** A separate class, vaulted, released by two named people, accepted directly by systems with `recovery_accepted`, every use an incident (6.3).

**Contract.** `issue_agent_identity`, `bind_workload`, `issue_credential(workload, run, release, node, call, principal_chain, audience, purpose ∈ {normal, compensation, replay, model})`, `exchange`, `mint_resumption_grant`, `redeem_resumption_grant(workload, grant, approval_record, run_status_assertion)`, `credential_for_approved_action(workload, approval_record, run_status_assertion)`, `delegation_status`, `release_recovery_identity(two_approvers, incident)`, `revoke(agent | run)`. The `run_status_assertion` is RUN-signed and carries the approved-action record's status and the timer state (hold time, approval time, suspension intervals); IDS computes expiry from its own clock and that state.

### A.3 PDP, Policy Decision Point

Evaluates policy as code against a decision request. Holds no run state; holds signed policy bundles and distributes the signed stop list OPS publishes (4.9).

**Decision request:**

```
purpose              normal | compensation | replay | delivery | spawn
principal_chain      acting_user?, [agent ids root..current]
agent, release       ids and versions
run, trace, node     ids; node type
tool, version, schema_hash
parameters           typed, per the manifest schema, parameter_roles resolved;
                     each value carries a provenance flag the PEP sets:
                     template (a template id in the release), sanitized (the
                     canonical value hash matches an accepted output, in a
                     sanitize.result of this run, of a sanitizer whose output
                     schema has no string field at all, of any length, except
                     enumerations and identifiers matching a registered pattern;
                     the rendering sanitizer does not qualify), or model.
                     A content-bearing parameter is one with no parameter role.
action_hash
subject              the signed subject claim, if any
run_state            data_classes_touched, exposed, tainted_reads[],
                     step_count, spend_to_date
counters             post-reservation counts for agent, subject, destination
factors              derived by PEP
approval_ref         present on resume, with the RUN-signed approval record
                     attached, including the cumulative causes_discharged[]
                     for the action hash
anchor_version       the REG anchor-capability version stamped on the release;
                     the PDP denies when REG's current version marks any of the
                     node's anchors as no longer capable
original_ref         for compensation and replay: the original decision and
                     effect event references, with their recorded parameters and
                     result attached by the PEP from EVS or its journal
stop_list_seq        sequence of the stop list the PEP holds
```

**Decision:** `ALLOW` · `DENY(reason)` · `HOLD(hold_causes[], approver_set, substitution_allowed)`, where `hold_causes` names every rule that held (`limit_band`, `tier_a1`, `velocity:<key>`, `exposure`, `factor_at_runtime`, `substitution_required`, `pack:<rule_id>`), plus obligations: `evidence_first` (always), `redact_for_approver[]`, `apply_provenance_tag`, `require_sanitizer`, `dlp_check`.

**Evaluation order.** Rules are applied in this order and the first `DENY` is final; a `HOLD` is final only if no later rule denies. Node declaration first: a call to a tool the node does not declare in the release is denied. Then tier guard: a call on an A3 node that derives any factor at runtime is held with cause `factor_at_runtime`, because factored effects are never A3 (4.4). Then stop scope: an effect decision with `purpose = normal`, any `delivery` or `spawn` request, and any read of `restricted` data, in scope of a stop, is denied; other reads are not denied by this rule, since the run is leaving `RUNNING` (4.9); `purpose = compensation` and `purpose = replay` are outside stop scope. Then, for `purpose = normal`, hard limits (deny). For `purpose = compensation`: allow if the parameters equal the manifest's mapping applied to the attached recorded original call and the attached record verifies against the EVS hash chain, the PEP journal signature, or RUN's checkpoint signature, deny otherwise; never held; this rule is terminal and no later rule applies. For `purpose = replay`: allow if the action hash and idempotency key match the attached recorded `decision = ALLOW` whose `effect.*` events, if any, are all `effect.indeterminate`, and there is no later `hold.resolved` with outcome `denied`, `revoked`, or `stopped` for that action hash, which the PEP attaches to `original_ref` from the same source as the decision, deny otherwise; never held; terminal. A compensation that returns indeterminate is replayed by the same rule against its own `decision`. Then intersection, bounds, counters, and the policy pack. For `purpose = delivery`: the delivery tool's recipient against `data_classes_touched`, and `require_sanitizer` when exposed. For `purpose = spawn` (a `handoff` or `service` node calling an agent tool): the caller chain's authority to invoke that agent or service, evaluated per principal; on `ALLOW` the PEP calls `start_run` for the child.

**Emitted obligations.** `apply_provenance_tag` is emitted on every `delivery` and `internal_store` call, and on every effect of an exposed run whose target supports tags. `dlp_check` is emitted on every effect whose `destination` resolves outside the trust boundary. `require_sanitizer` is emitted on every delivery of an exposed run.

**Counter breaches.** A velocity limit breach is a `HOLD` with cause `velocity:<key>`, so a legitimate burst can be approved; a hard velocity cap, where policy sets one, is a `DENY`. Compensation and replay requests do not reserve.

**Intersection (I2).** The PDP evaluates the request once per principal in the chain against that principal's policy entitlements (which tools, which systems, which resource ranges) and allows only if every evaluation allows. Agent entitlements are policy content and travel in the signed bundle; the PIP serves acting-user entitlements and resource relations. An agents-only chain can therefore be evaluated from the bundle alone. Resource-level entitlement (may this user see this record) is enforced by the system itself for `chained` presentation and by the PDP through the PIP for `per_agent` presentation: before such a call, the PDP evaluates the acting user's entitlement to the specific resource through the PIP where there is an acting user, and the bounds' anchoring to the subject where there is a subject. A subject is not evaluated; it anchors bounds.

**On resume.** Before any credential is obtained, the PEP re-reserves counters (a new reservation id) and resubmits a request for the same action hash with `approval_ref`; on substitution the chain carries the approver as acting user. The PDP evaluates the request in full. RUN keeps, in the hold record for the action hash, the cumulative set of **discharged causes**; an approval adds the causes it covers to that set, and a rule whose cause is in the set does not hold again for that action hash until the action executes, is denied, is stopped, or the resume window expires (A.2). Any cause not yet discharged holds again with only the new causes, which supersedes the approval record (the discharged set is kept) and starts a new approval for the new causes only. Policy sets a maximum number of re-holds per action hash, after which the call is denied. Hard limits and hard velocity caps are deny-only and cannot be discharged. Bounds and the intersection are never a hold cause; a call that fails them is denied. The approver view shows the hold causes, the causes already discharged, and the counters the call would consume.

**PIP, Policy Information Point.** Adapters that answer entitlement and ownership questions at decision time. Cached no longer than the call.

### A.4 PEP, Policy Enforcement Point

Every tool call a governed agent makes passes through a PEP: reads, retrieval, memory, sanitizers, previews, deliveries, and effects. Two forms, one contract, one conformance suite:

- **PEP-P, proxy.** A network intermediary for surfaces that cannot embed anything. The platform's network permits tool egress only to PEP-P (Appendix C).
- **PEP-E, embedded.** A signed SDK or sidecar inside a code runtime, carrying the RUN client, so hosting PEP-E means hosting checkpoint and resume. Its build hash is attested (A.2).

**Duties, per call.** On PEP-E, write `node.entered` with the node's inputs on the first call of a node and `node.exited` at checkpoint; on S1, RUN writes both from the platform's hooks, which carry the inputs reference, and PEP-P writes call-level events; RUN fills `node.exited` from the acknowledged run-state updates. Fetch run state from RUN (`get_run_state`) at node entry and keep it current locally; count calls per node as `step_count` and end a `loop` node at its step cap by denying further calls in it and reporting to RUN; resolve parameter roles and derive factors; compute the action hash; for an effect, `reserve` counters with RUN (compare-and-reserve; RUN returns a reservation id and the post-reservation counts, which go in the request; reads, deliveries, compensation, and replay do not reserve); build and submit the decision request with the current stop-list sequence; write a `decision` event for every decision (for reads, deliveries, and spawns without waiting); reject any call for a node until RUN confirms the node's `node_entered` hook (on PEP-E the SDK calls the hook itself); the PEP is the sole releaser of its reservations: on `DENY` or `HOLD`, `release(reservation_id)`, which is idempotent; on `ALLOW` of an effect: derive the idempotency key from the action hash, write `decision` (parameters, key, `approval_ref` if resuming) and wait for the durable acknowledgement (I3), obtain the credential (by grant redemption or approved action when resuming), execute; write `effect.executed` on a confirmed result, `effect.failed` only on a definitive negative (the system refused or errored before committing, or the call was cancelled by a stop, refused for a revoked delegation, or blocked by the `dlp_check` obligation before anything was sent, the last with `error = dlp`, after which the node follows the failure branch), and `effect.indeterminate` when the outcome is unknown (timeout, lost response), which leaves the node in doubt and keeps the reservation until the outcome is recorded; otherwise `confirm` or `release` the reservation; for a delivery, write `delivery.executed` or `delivery.failed`; for a model call, obtain and present the `model` credential to MGW; apply obligations (`dlp_check` before anything is sent, `redact_for_approver` at hold, the rest as they fall); update run state with data classes read and taint at RUN, acknowledged, before releasing any call's result to the runtime (under a RUN outage, in the journal, which is replayed to RUN before the run continues); treat any item from a `per_item` source that arrives without a tag as tainted; write `node.exited` at checkpoint; send RUN a heartbeat on a timer whenever the run is `RUNNING`, including while a tool call, model call, or spawn is outstanding. Calls the PEP originates itself (previews, compensations, replays, resumed calls) carry a `(run_id, node_id)` header the PEP signs; runtime-originated calls carry the runtime's.

**Credential binding.** A governed agent's credentials are sender-constrained to its PEP's workload, so authority obtained through a PEP cannot be presented from anywhere else. Systems distinguish governed-agent credentials from other classes they accept (vendor grants, user sessions, recovery identities) and may apply different limits to each. The architecture does not claim systems accept only governed-agent credentials; it claims a governed agent's authority cannot leave its PEP.

**Compensation and replay execution.** On RUN's instruction the PEP executes a `compensate` node as a deterministic call with no runtime loop and no model: parameters come from the manifest mapping over the recorded original call, which the PEP attaches to the request as `original_ref` from EVS, from its own journal, or from the RUN-signed copy in the checkpoint that `instruct` carries; the request carries `purpose = compensation`; the credential carries `purpose = compensation`. A replay of an effect in doubt is the same mechanism with `purpose = replay`, the recorded parameters, and the recorded idempotency key. The PDP rules in A.3 apply. Both need RUN to instruct and IDS to issue; neither needs the model.

**Local journal and bundle.** Both forms hold the current signed policy bundle (local evaluation is part of the conformance suite), keep an append-only journal signed with the workload key on persistent local storage, used only in degraded mode (section 6), and local degraded-mode counters. If an instance dies with an unreconciled journal, its orchestrator recovers the journal and submits it to `reconcile`; a reservation left unconfirmed by a dead instance expires at the end of its window.

**PEP-E forms.** In the sidecar form the credential never enters the builder's process. In the SDK form, builder code shares the process and could extract a credential the SDK holds; the SDK form is permitted only for agents capped at A2, and this is a declared residual (section 9).

**Stop list.** Both forms hold the current signed stop list. While a stop in scope is current, or when the list is older than the staleness limit, the PEP refuses any effect decision other than compensation and replay, refuses deliveries and spawns, refuses any read of `restricted` data, and cuts `loop` nodes in scope at once.

**Inbound contract.** `instruct(run, node, purpose ∈ {preview, compensation, replay, resume}, original_ref?, approval_ref?, grant?)` from RUN; `cap_reached(run, node)` from RUN. On `resume` the PEP resubmits the held call.

**What hosting is not.** A builder's deployment hosts a PEP-E process; it does not administer it (I8). Administration is the build, its allow-listing, bundle and stop-list issuance, and key issuance, all outside the builder's control. The workload key is issued by IDS to the attested build and signs the journal. A host with root can still tamper with a running process; attestation narrows that, the S4 tier cap bounds it on devices, the orchestrator's own integrity controls are the mitigation on S2, and it is a declared residual.

### A.5 RUN, Run Coordinator

Owns the lifecycle of every governed run. Always central: a platform integrates through checkpoint and resume hooks; it does not host RUN.

**Holds:** run records; node checkpoints; holds and encrypted grants; the park queue; counters; token usage per run and node (from MGW); the stop register; the signing key for approval records; per-run heartbeats.

**Hook contract.** Every governed runtime, including an S1 platform, implements: `start_run`, `node_entered(run, node_id, node_type, inputs_ref)`, `checkpoint`, `heartbeat`, `rendered_description(tool)`, `hold` and `resume` callbacks (a held run's runtime-originated calls are rejected by the PEP by run state), and a signed `(run_id, node_id)` header on every runtime-originated PEP call so the PEP can attribute the call to a node. Input from a `human` node enters through RUN and is tainted unless the input role is registered as internal; an internal role pasting external content launders it, which is residual R-17. RUN writes `node.hook` for each hook call it receives. A platform that cannot implement the contract is ungoverned.

**Run start.** Verifies the trigger signature against REG; records `subject` for `subject_claim` triggers and establishes the acting user for `user_session` triggers; sets `exposed_at_start` from the derived payload trust; initializes the principal chain as the acting user, if any, then the root agent; IDS confirms that the hosting workload and PEP build are bound and allow-listed before any credential issues (A.2).

**Checkpoint and liveness.** At every node boundary RUN persists node outputs, run state, the next node, and, for every effect executed so far in the run, a RUN-signed copy of the recorded parameters, the result fields the manifest's compensation mapping references, the result reference, and event hashes, which the PEP supplies to RUN with `confirm`, which is an admitted source for compensation when EVS is unreachable (A.3) and is reconciled against the hash chain when EVS returns. Node entry has one source: the runtime's `node_entered` hook, which RUN records as `node.hook`; RUN rejects a hook for any node other than the checkpointed next node or the declared denial or failure branch target, and the PEP then rejects that node's calls. A `spawn` call is synchronous from the parent's PEP: RUN reports the child's final exposure when it returns, and the parent's PEP applies the taint before the node continues. A `handoff` or `service` node whose child run exists is never re-entered on restart: RUN accepts the restarted runtime's hook for that node, and the PEP returns the child's result instead of spawning. A child whose parent is cancelled continues to its own declared state and its return is discarded. A child run inherits the parent's `subject`. During a RUN outage a PEP-E records the hook in its journal, applies the next-node rule against its local checkpoint, accepts that local record as confirmation, and RUN reconciles the journal on return before resuming liveness judgments, with a grace period so queued heartbeats are not read as host loss. Mid-node, the `decision` event is the capture for an effect in flight. The PEP heartbeats on a timer while the run is `RUNNING`, so a long call or an outstanding spawn is not silence; on S1 the platform also heartbeats through the hook contract, so a hung platform run is detected; a `RUNNING` run with no heartbeat past the policy deadline is treated as *host lost*. A `HELD` run makes no runtime-originated calls and is not judged by silence (the PEP-originated preview is the one call it makes); on resume, the PEP's first call proves liveness, and if the runtime cannot be resumed RUN parks the run.

**Effects in doubt.** An effect node is *in doubt* when RUN has its `node_entered` hook, no exit checkpoint, the *latest* `decision` with `purpose = normal` for the effect's own action hash (preview reads in the node, and `decision` events with `purpose = replay` or `compensation`, do not count) is `ALLOW`, and there is either no `effect.*` event for it or the latest `effect.*` event for it is `effect.indeterminate`. By I3 no effect executes without a durably written `decision`, so a node with no `decision` in reconciled evidence is not in doubt and may be re-entered on restart. While a journal is unreconciled, RUN cannot know which case holds and parks the run until the journal is recovered. RUN never concludes that no effect executed from the absence of evidence it cannot see. A runtime restarted from a checkpoint never re-enters a node that is in doubt; RUN resolves it first: where the system supports idempotency, a replay with the recorded key (A.4), up to a policy-set number of consecutive indeterminate replays, a denied replay or the exhausted count parking the run; otherwise park with the on-call resolver, who verifies against the system and records the outcome with `record_outcome(run, node, executed | not_executed, evidence_ref, result_fields?)`, where `result_fields` carries, on `executed`, the result fields the manifest's compensation mapping references, and `not_executed` is written as `effect.failed` with `error = not_executed`, after which RUN writes the matching `effect.*` event with `recorded_by = resolver` and the run may resume or compensate. When a replay or a resolver outcome resolves a node as executed, RUN writes its `node.exited` with outputs from the recorded result, advances the checkpoint, and the restarted runtime enters the successor; on resume, a node whose outcome was recorded as `not_executed` is re-entered for a fresh decision. The runtime is restarted by its orchestrator (S1, S2) or when its host returns (S4); until then the run is parked.

**Hold.** On `HOLD`: persist the pending effect (the PEP has already released its reservation); request a grant from IDS, or, where policy permits substitution, record substitution as the only path; if IDS is unreachable and policy does not permit substitution, or the node has a bound anchored to `acting_user`, park the run and request the grant when IDS returns, before the run enters `HELD`; where the system has a `preview_tool`, `instruct` the PEP to call it as a PEP-originated read within the held node, attributed to that node id, decided like any read, its data classes and taint entering run state; assemble the approver view (4.5); hold the run at the node in `HELD`.

**Counters.** `reserve(keys, window)` atomically increments, returns a reservation id and the new counts before the decision; `release(reservation_id)`, idempotent, by the PEP on deny, hold, or failure; `confirm(reservation_id)` on `effect.executed`. RUN reconciles unconfirmed reservations against `effect.executed` events in EVS, matched by action hash to the original `decision` event's reservation id (a replay or resolver outcome carries the original action hash), at the end of each window and whenever a resolver records an outcome, so an effect whose PEP died before confirming is still counted. Keys: `agent_id`; `subject`, or the acting user when there is no subject, or the agent alone when there is neither; the resolved `destination`. Windows are policy content. Only when RUN itself is down do PEPs fall back to local counters, with tighter policy-set caps that account for the number of PEP instances.

**Stop register.** Records every stop OPS issues with scope and sequence.

**Contract.** `start_run` (creates the run record; for a child run, RUN then calls the target agent's registered `launcher`), `node_entered`, `checkpoint`, `heartbeat`, `get_run_state(run)`, `hold`, `resume(run, approval_record)`, `cancel(run)`, `park`, `record_outcome`, `reserve`, `release`, `confirm` (on an expired reservation, re-increments the window), `record_usage`, `record_stop`; outbound to the PEP: `instruct`, `cap_reached`.

### A.6 EVS, Evidence Store

Append-only, per event, written before effects. Integrity by hash chain, witnessed on a schedule by a system outside the operator's control, which timestamps the chain head, verified by a party that neither builds agents nor operates the store. Payloads that may contain personal data live in a separate store referenced by keyed hash; a payload can be erased while the event stands, and the run is then marked by `erasure.applied` as not fully reconstructable.

**Contract.** `append(event) → durable_ack`, `read(run | trace)`, `verify(range)`, `reconcile(journal)`.

### A.7 DBS, Data Boundary Service

All of it is reached through the PEP as tools.

- **Retrieval.** Returns only what the agent is cleared for *and* what the acting user may see. Over a live `chained` source, the source enforces. Over a `per_agent` source, the PDP's PIP check stands in. Over a derived store, entitlements are as fresh as the store's last sync; the registry records the cadence, and a derived store may hold `restricted` data only if its entitlement sync is event-driven.
- **Memory.** A store of `kind = memory`, read through a `per_item` tool: writes carry `apply_provenance_tag`, items written during an exposed run are stored tainted and returned flagged. A memory write is a decided call, not an effect.
- **Derived stores.** Every index, embedding store, cache, and memory is registered with source classification, entitlement-sync cadence, residency, retention, and deletion propagation.
- **Sanitizers.** Deterministic, versioned functions (5.3), executed by the PEP as tools with `side_effect_class = none`.
- **Delivery tools.** Registered tools whose target is an `interface` (delivery to the acting user or a registered recipient role, which resolves only to principals inside the boundary definition; the delivery event is the only record) or a `sink_store`. A delivery tool has `writes_data_class`. A delivery is a decision like any call (`purpose = delivery`), always carries `apply_provenance_tag` where the target stores anything, and writes `delivery.executed` or `delivery.failed`. Reads from a sink store are `per_item` by derivation, so an item delivered by an exposed run returns tainted.
- **Outbound checks.** Data-loss inspection, invoked by the PEP under the `dlp_check` obligation on any effect whose `destination` resolves outside the trust boundary.

### A.8 MGW, Model Gateway

Routes a model call only to a model within the release's declared route; pins versions; routes only through region-pinned deployment modes; accepts only per-node `model` credentials presented by a PEP; attributes tokens to run and node and reports usage to RUN, which is where `spend_to_date` and the `loop` node's token cap are enforced, `spend_to_date` in a decision request being as fresh as the last usage report (R-11); applies token budgets per agent per period, the budgets being policy content; logs. Routes are release content (I6).

### A.9 OPS, Operations Control

Issues stops into RUN's register and **signs and publishes the stop list** with a sequence number and a validity period; PDP distributes it; PEPs hold it. Runs the park queue and its resolvers, the recovery path, drills, and service indicators for RUN, PDP, PEP, EVS, IDS.

---

## Appendix B. Run states and resolvers (normative)

### B.1 Run states

```
CREATED ─► RUNNING ─► COMPLETED
              │
              ├─► HELD ──(approve)──► RUNNING
              │     ├──(deny | timeout | revoked and no substitution)──► RUNNING (denial branch)
              │     ├──(stop)──► STOPPING
              │     └──(degradation | host lost)──► PARKED ──(recovered, no approval yet)──► HELD
              │                                        └──(recovered, approval recorded before or during park)──► RUNNING (resume)
              │
              ├─► (degradation | host lost | wall-clock budget | unreconciled journal | IDS unreachable at hold) ──► PARKED
              │
              ├─► STOPPING ──(no effect node ever entered in this run)──► CANCELLED
              │       └──(any effect node entered)──► PARKED
              │
              ├─► PARKED ──(resolver: resume)──► RUNNING
              │       ├──(recovered: IDS returned, grant minted)──► HELD
              │       ├──(recovered: approval timeout expired beyond max_park)──► RUNNING (denial branch)
              │       ├──(recovered: cause cleared or runtime restarted; effects in doubt resolved first)──► RUNNING (resume, cause recovered)
              │       ├──(resolver: cancel)──► COMPENSATING ──► COMPENSATED
              │       │                             └─(a compensation fails | irreversible)─► PARKED
              │       ├──(deadline)──► ESCALATED ──(owner: resume | cancel | close)──► RUNNING | COMPENSATING | CLOSED_WITH_EXCEPTION
              │       │                     └──(owner deadline passed; OPS)──► COMPENSATING (declared compensations) then CLOSED_WITH_EXCEPTION (disposition owner_deadline_passed; unconditional, a failed compensation is recorded, not re-parked)
              │       └──(owner: close, with disposition)──► CLOSED_WITH_EXCEPTION
              │
              └─► (runtime error) ──(no effect node ever entered)──► FAILED
                                   ──(any effect node entered)──► PARKED (effects in doubt resolved first)
```

Terminal states and the rules governing `FAILED`, `CANCELLED`, and `CLOSED_WITH_EXCEPTION` are in 4.8.

### B.2 Resolvers

The park queue has a standing on-call resolver role with authority to resume, cancel (which triggers declared compensation), record a hand-verified outcome for an effect in doubt (A.5), or escalate to the owner. The resolver cannot widen bounds or approve a held factored effect; those still need the approver set. The owner is notified of every park and decides anything beyond the resolver's authority by the deadline.

---

## Appendix C. Hosting (normative)

For each of platform, PEP-P, RUN, PDP, EVS, IDS, and models, the deployment records: tenancy; what traffic crosses the boundary (prompts, telemetry, licence checks, updates, support access); who patches and when; region, pinned; key custody. A platform's network permits tool and model egress only to its PEP-P, which forwards model calls to MGW; an S2 workload's egress is pinned by orchestrator network policy to its PEP-E and MGW, which pins by workload identity and so cannot separate builder code from the PEP in the SDK form or in a sidecar sharing the pod's network identity (R-18); on S4 device egress cannot be fully pinned and is residual R-15; and the platform's native memory is registered as a `memory` store and native retrieval as a `derived_store`, each reached only through PEP-P, and native models are routed through PEP-P to MGW, or each is disabled. Managed model services are routed only through region-pinned deployment modes. Platform, runtime, and PEP versions are release content (I6), so a vendor-pushed upgrade is a material change.

---

## Appendix D. Evidence schema (normative)

One event per occurrence, written in order. Fields marked * are required. Run events carry the run header; events outside a run carry `scope*` instead.

**Run header:** `event_id*`, `timestamp*`, `prev_hash*`, `hash*`, `trace_id*`, `run_id*`, `parent_run_id`, `node_id` (absent on `run.*` events), `agent_id*`, `release_version*`, `surface*`.

| Event | Fields |
|---|---|
| `run.created` | `trigger*`, `trigger_kind*`, `signature_verified*`, `subject`, `principal_chain*`, `exposed_at_start*` |
| `run.started` / `run.held` / `run.resumed` (cause `approved`, `denial_branch`, `resolver`, `owner`, or `recovered`) / `run.stopping` / `run.parked` / `run.escalated` / `run.escalation_resolved` / `run.compensating` | `cause*`, `stop_ref`, `decided_by` as applicable; `resolver*` and `deadline*` on `run.parked` and `run.escalated` |
| `run.completed` / `run.compensated` / `run.cancelled` / `run.failed` / `run.closed_with_exception` | `final_state*`, `exposed*`, `data_classes_touched*`, `effects_in_doubt[]`, `disposition` (required on `closed_with_exception`: `loss_accepted`, `manual_remediation`, `incident`, or `owner_deadline_passed`) |
| `node.entered` | `node_type*`, `inputs_ref*` (pointer and keyed hash per item, data class, taint flag; the flag is the run-level `exposed` unless the runtime claims per-item provenance, in which case `provenance_claimed = true`) |
| `decision` | `purpose*`, `tool*`, `version*`, `schema_hash*`, `parameters_ref*`, `parameter_roles*`, `action_hash*`, `factors*`, `tier`, `decision*`, `rule_id*`, `obligations*`, `reservation_id` and `counters_snapshot` (required for `purpose = normal` effects), `idempotency_key`, `approval_ref`, `stop_list_seq*` |
| `effect.executed` / `effect.failed` / `effect.indeterminate` | `purpose*`, `credential_presentation*` (`chained` / `per_agent`), `result_ref*` or `error*` (`stopped` when cancelled by a stop, `revoked` on a refused resume, `dlp` when blocked by the outbound check, `not_executed` when a resolver so records) or `last_known*`, `idempotency_key`, `recorded_by` (`pep` or `resolver`) |
| `delivery.executed` / `delivery.failed` | `sink*`, `sanitizer_applied*`, `result_ref*` or `error*` |
| `node.hook` (by RUN) | `node_id*`, `node_type*`; RUN's record of the runtime's `node_entered` hook call, a separate occurrence from the PEP's `node.entered` |
| `usage.recorded` (by MGW via RUN) | `node_id*`, `tokens*`, `model*` |
| `hold.created` | `kind*` (`effect` / `input`), `action_hash`, `hold_causes[]*`, `approver_set*`, `grant_id`, `substitution_only*`, `preview_ref`, `view_ref*` |
| `hold.resolved` | `outcome*` (`approved` / `denied` / `timeout` / `stopped` / `revoked` / `expired` / `superseded`), `approvers[]*`, `causes_discharged[]`, `causes_remaining[]`, `substitution*`, `reason` |
| `taint.applied` | `source*`, `items[]*` |
| `sanitize.result` | `sanitizer*`, `version*`, `accepted_ref*`, `rejected_ref*` |
| `node.exited` | `outputs_ref*`, `data_classes_touched*`, `exposed*`, `model_account_ref` |
| `grant.minted` / `grant.redeemed` / `grant.invalidated` / `approved_action.used` | `grant_id*` or `approval_ref*`, `action_hash*`, `presenter_workload` |
| `stop` | `scope*`, `sequence*`, `issued_by*`, `validity*` |
| `recovery.used` | `scope*`, `identity*`, `releasers*`, `incident_id*`, `actions_ref*` |
| `journal.reconciled` | `scope*`, `gap_start*`, `gap_end*`, `events_count*`, `counters_merged*` |
| `external.imported` | `scope*`, `source*`, `fields_present[]*`, `fields_missing[]*`, `raw_ref*` |
| `erasure.applied` | `run_id*`, `payload_refs[]*`, `authority*` |

Compensation and replay calls write `decision` and `effect.*` with their `purpose`. Payload stores referenced by `*_ref` hold content that may include personal data, separable and erasable (A.6). `model_account_ref` is the model's own stated rationale, labelled as such.
