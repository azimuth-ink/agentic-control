# ADR 0001 — One process, nine objects

**Status:** accepted (0.1.0)

## Context

The specification describes nine components (REG, IDS, PDP, PEP, RUN, EVS, DBS, MGW, OPS) as roles with contracts, and says several may be one product. A reference implementation can either stand up nine services with real transports, or model the nine contracts as objects in one process.

## Decision

One process. Each component is a class whose public methods are the contract's operations (A.1–A.9), and the only coupling between them is those methods. Availability is a flag (`Availability.available`) checked at the contract boundary; a component that is "down" raises `Unavailable(component)` from every contract method, which is what a caller would see from a dead service. There is no network, serialization, or persistence.

## Consequences

- Every clause of sections 4–6 and the appendices is testable in milliseconds with injected time (`Clock`), including the degradation matrix (`platform.outage`) and multi-hour timer behaviour.
- The implementation says nothing about latency, throughput, or availability objectives (6.2); those are deployment content.
- Because availability is a flag, a component that is "down" still holds state; a test that wants the memory-loss case (RUN restarting, counters gone) clears the state explicitly (see `test_counters_are_reconciled_from_evidence`).
- The contracts' argument shapes are Python objects rather than wire schemas. A deployment would put a transport behind each class; the method surface is the contract to keep.
