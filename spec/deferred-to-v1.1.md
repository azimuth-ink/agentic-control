# Deferred to v1.1 (from internal specification 1.12)

Text removed from the v1.0 body as sequence restatements, targets, cadence, or program framing. Vocabulary edits applied; section numbers are those of internal 1.12. The availability-objective sentence of 6.3 was later restored into v1.0 section 6.2 (round thirteen); the rest stays deferred. Round sixteen's fourteen recommended items are listed in the v1.0 changelog, not here.

## 4. Identity flows (D3, D4)



### 4.1 Run start

1. A registered trigger starts a run, signed with its source's workload key. RUN verifies the signature.
2. `user_session`: the runtime holds the user's token; IDS exchanges it for a delegated credential; the user becomes the acting user and heads the chain. `subject_claim`: the subject is recorded and anchors bounds; the chain holds agents only. `event`: neither.
3. `exposed_at_start` is set from the derived payload trust.
4. IDS confirms the hosting workload and PEP-E build are bound and allowed.

### 4.2 A node makes a tool call

1. The PEP resolves roles, derives factors, computes the action hash, reserves counters.
2. The PDP evaluates and returns a decision.
3. On `ALLOW` of an effect: `decision` written and acknowledged (I3); credential obtained; executed; `effect.executed` or `effect.failed` written; reservation confirmed or released.

### 4.3 A node is held

1. The PEP releases its reservation; RUN persists the pending effect and requests a grant or records substitution as the only path.
2. Where the system has a `preview_tool`, RUN instructs the PEP to call it as a PEP-originated read within the held node; its data classes enter run state. RUN assembles the approver view.
3. The approver decides within the timeout through OPS, authenticated by the identity provider; RUN signs the approval record.
4. On approval, RUN checks `delegation_status`, marks the record `grant` or `substitution`, and sends `instruct(resume)` with the approval reference and the grant. The PEP re-reserves counters and resubmits with `approval_ref`; the PDP evaluates in full (2.3) and allows, denies, or holds again. On `ALLOW`, the PEP writes `decision` with `approval_ref` and waits for the acknowledgement; then it redeems the grant, or calls `credential_for_approved_action` with a substitution record where that is the path; IDS issues the credential; the PEP executes and writes `effect.*`. If the PEP instance fails before the `decision` was written, a replacement instance of the same workload repeats this step from the resubmission; if it fails after, the node is in doubt and 2.5 applies.
5. On revoked delegation with substitution permitted, the approver becomes the acting user for this action; the credential records the original user. On revoked delegation without substitution, the hold is denied.
6. On denial or timeout, the grant is invalidated and the denial branch runs.

### 4.4 Handoff and service

- `handoff`: the node calls the target's agent tool through the PEP (`purpose = spawn`); on allow the PEP calls `start_run`, and the child's PEP requests credentials against the parent run's delegation state held by RUN and IDS (`exchange(run_ref, target_agent)`), yielding a chain extended by the target agent; the parent's own credential is never passed on. The child's calls are evaluated against every principal.
- `service`: the node calls the service's agent tool through the PEP (`purpose = spawn`), where the PDP checks the caller chain's authority to invoke it; on allow the child runs presenting the service agent's identity, the credential's claims carry the caller chain and the acting user, and the PDP evaluates each of the service's calls against the service's bounds and every principal.

### 4.5 Systems that cannot take a chained token

The PEP requests a `per_agent` credential. Before the call, the PDP evaluates the acting user's entitlement to the specific resource through the PIP where there is an acting user, and the bounds' anchoring to the subject where there is a subject.

### 6.3 Availability targets

RUN, PDP, EVS, IDS, and each PEP-P carry an availability objective at least equal to the most critical system they front, and a latency budget per decision published as a measure. The evidence acknowledgement path is on the budget.

### 6.5 Drills

Quarterly: an agent-scope stop, a tool-scope stop, a fleet-scope stop in a test environment, one recovery-identity release, one reconciliation from journal, one restart from checkpoint with an effect in doubt, one hold resumed after a PEP instance failure.

## 9. Extension points for Phase 2

| Extension point | Owner of the pattern | What it supplies |
|---|---|---|
| System capabilities and tool manifests | Owning system teams; approved by security and compliance | Presentation, ingress, writability, provenance, roles, compensation mappings |
| Policy packs | Security, compliance, FinOps | Rules over decision-request fields; velocity windows; degraded-mode caps; two-approver threshold; budget caps |
| PIP adapters | Identity engineering, owning system teams | Entitlement, ownership, and status relations per system |
| System-of-record contract | Application engineering | Credential presentation, idempotency, preview, compensation endpoint, provenance tag, error model |
| Trigger registrations | Owning system teams | Signing keys, kinds, subject schemas |
| Sanitizer catalog | Data governance, security | Deterministic parsers, validators, the rendering sanitizer |
| Derived-store registry | Data governance | Index, embedding, memory, cache entries with classification, sync cadence, deletion propagation |
| Surface adapters | Platform engineering | PEP-P and PEP-E builds, the conformance suite, RUN hooks per runtime, the build allow-list |
| Hosting patterns | Cloud and infrastructure | Boundary definition, egress pinning, region, key custody per component, orchestrator integrity controls |
| Evidence consumers | Internal audit, compliance, FinOps | Verification, anchoring, retention schedules, obligation mapping, cost attribution |
| Evaluation harness | AI governance | Pre-release and drift evaluation per release; thresholds per tier; sampling rates |
| Operations runbooks | SRE | Resolver authority, degradation playbooks, drill scripts, ungoverned-surface stop steps |
| Supplier controls | Procurement | Platform, model, connector, and control-plane vendors |
| Builder pack | Business-unit enablement | Factor questionnaire, self-check, bounds proposal form |

A pattern that needs something not on this list is asking for a change to the core, which goes through the rationale.

