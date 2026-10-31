# agentic-control

Reference implementation of the **Agentic Control Architecture v1.0** — a control plane for agents that act on enterprise systems under delegated authority. The specification and its design rationale (under `spec/`) are the normative documents; this repository is an executable reading of them: nine in-process components with the contracts of Appendix A, the worked flow of section 8 as a runnable example, and a conformance suite that reproduces the nine findings (F1–F9) the specification's verification rounds were organised around.

Status: pre-release (0.1.0). Nothing depends on it. The interfaces follow the specification's appendix names and will move with the specification.

## What is here

```
src/agentic_control/
  common.py       canonical JSON, hashing, injectable Clock, the exception types (Refused, Denied, Unavailable)
  crypto.py       Ed25519 envelopes, a role-keyed trust store, sealed (Fernet) tokens
  release.py      Bound grammar, Node, Release, the node-type matrix, the anchoring rule
  registry.py     REG (A.1): capability records, manifests, triggers, sanitizers, derived trust fields,
                  anchor capability with refusal and suspension, the release linter, factor derivation
  events.py       the evidence schema (Appendix D)
  evidence.py     EVS (A.2): hash-chained store, payload store with erasure, witness, PEP journal, reconcile
  identity.py     IDS (A.6): workload attestation, credentials, delegation, grants, approved-action records,
                  substitution, recovery identities
  policy.py       PDP (A.3): bundle, stop list, the evaluation order, bounds, counters, compensation and replay rules
  coordinator.py  RUN (A.5, Appendix B): run start, hooks and checkpoints, counters, holds, parks, recovery,
                  effects in doubt, stops, escalation, the OPS close, child runs
  enforcement.py  PEP (A.4): the per-call duties, degraded modes, deliveries, spawns, model calls,
                  RUN-instructed previews, resumes, compensations and replays
  dbs.py          DBS (A.7) and the system-of-record contract the fake systems follow; sanitizers
  gateway.py      MGW (A.8) and OPS (A.9)
  runtime.py      a minimal agent runtime that walks a release graph through the PEP
  platform.py     wiring; outage toggles for the degradation tests
spec/               the specification, its design rationale, and the v1.1 deferral list (the normative text)
docs/               spec map, conformance matrix, ADRs, and the architecture field guide (field-guide.html)
examples/warranty/  the section-8 worked flow with adversarial model behaviours and graph variants
tests/conformance/  F1–F9, each test marked with the specification clauses it covers
tests/unit/         primitives
tools/conformance_report.py   the clause → test matrix; `--check` fails CI if a finding has no test
```

Everything runs in one process with injected time. There is no network, no database, and no real model: the point is to make the control semantics executable and testable, not to ship a product.

## Run it

```
pip install -e ".[dev]"
pytest                                    # 155 tests
python tools/conformance_report.py        # which clauses and findings are covered
```

The worked flow, by hand:

```python
from warranty import build_scenario

sc = build_scenario()                     # untrusted ticket → exposed run
run = sc.start(ticket_body="My device is broken.")
sc.execute(run)                           # read → loop → sanitize → effect (ship) → effect (reply) → output (log)
print(run.state, sc.types(run))           # COMPLETED, the evidence trail

sc = build_scenario(behaviour="inject_address")
run = sc.start(ticket_address="99 Evil Rd")
sc.execute(run)                           # the destination bound fails: denied, denial branch, no shipment

sc = build_scenario(trigger="clean-ticket"); sc.model.amount = 500.0
run = sc.start(); sc.execute(run)         # between the limits: HELD with cause limit_band
sc.platform.ops.approve(run, "n4", "approver-1")   # grant redeemed, same action hash, executes
```

`build_scenario` variants: `behaviour` (normal, inject_address, inject_sku, over_limit, wrong_device, inject_reply, bad_topic), `trigger` (fault-ticket, clean-ticket, console), `surface`/`form`/`tier_n4`, `internal_effect`, `regulated_irreversible`, `with_child`, `ship_address_editable`. `platform.outage("EVS"|"PDP"|"RUN"|"IDS"|"PIP")` drives the degradation matrix.

## How the specification maps to the code

`docs/spec-map.md` lists each specification clause with the module and the tests that cover it. The short version:

| Specification | Module |
|---|---|
| 1 Invariants I1–I8, D1–D6 | enforced across components; see `docs/spec-map.md` |
| 3 Mechanisms 1–16 | `registry.py`, `policy.py`, `enforcement.py`, `coordinator.py` |
| 4.3 Anchoring rule | `release.anchored_params`, `registry.lint_release`, `policy._bounds` |
| 4.4 Holds and approval | `coordinator.hold/approve/rehold`, `identity.redeem_resumption_grant`, `enforcement._resume` |
| 4.6 Effects in doubt | `coordinator.in_doubt/resolve_in_doubt/record_outcome`, `enforcement._replay` |
| 4.9 Stops | `gateway.Operations.issue_stop`, `coordinator.apply_stop/stop_refusal`, `enforcement._stopped` |
| 5 Taint | `enforcement._apply_read_result`, `coordinator.provide_input`, `enforcement._spawn`, `dbs.System` tags |
| 6.1 Degradation matrix | `enforcement._local_decide`, journal paths, `coordinator.recover`, `platform.outage` |
| A.1 REG | `registry.py` |
| A.2 EVS | `evidence.py`, `events.py` |
| A.3 PDP | `policy.py` |
| A.4 PEP | `enforcement.py` |
| A.5 RUN | `coordinator.py` |
| A.6 IDS | `identity.py` |
| A.7 DBS | `dbs.py` |
| A.8 MGW, A.9 OPS | `gateway.py` |
| B.1 Run states, B.2 Resolvers | `coordinator.py` |
| D Evidence schema | `events.py` |

## What the suite found

Writing the conformance tests against the first cut of the code surfaced defects that a reading of the specification alone had not: a replacement PEP recomputed provenance from a local set that no longer existed (now rebuilt from `sanitize.result` evidence); the host-lost timer kept running through a hold; an approval during an IDS outage raised instead of being recorded; degraded-mode effects were counted twice; the compensation mapping was looked up on the reversing tool rather than the reversed effect's manifest; a run started under a current stop ran its reads and completed on denial branches rather than being refused; an IDS refusal propagated out of the PEP as an exception rather than a recorded failure. An independent review of the first cut against the text then found a second set: factored and exposed effects continuing through EVS and RUN outages, reads and deliveries presenting no credential, a replay failure erasing doubt, `deny` without `approve`'s guards, a skippable `human` node. `CHANGELOG.md` has both lists and `tests/conformance/test_review_fixes.py` pins the second. The point of recording them here is that the specification's verification record is about the text; this is the first record about an implementation of it.

## What this is not

- Not a product, not hardened, not performance-tested. Components are Python objects in one process; availability is a flag.
- Not the specification's prose. Where the code and the text disagree, the text wins and the code is wrong; open an issue naming the clause.
- The decisions deferred to v1.1 in the specification (section 11) are deferred here too.

## Licence

Apache-2.0. The specification text is published separately under CC0.
