# ADR 0003 — Time is a parameter

**Status:** accepted (0.1.0)

## Context

Holds have approval timeouts and resume windows; parks suspend those timers up to `max_park`; credentials expire; stop lists go stale; counters have windows; hosts have heartbeat deadlines; parks have resolver and owner deadlines. All of these interact (an approval during a park, an expiry after an approval while parked, a stale list after a long hold), and the specification's verification rounds spent effort on exactly those interactions.

## Decision

Every component takes a `Clock` and reads `clock.now()`; nothing reads the wall clock. Tests advance time explicitly (`clock.advance(seconds)`) and drive RUN's timers with `RunCoordinator.tick()`. IDS computes grant expiry from RUN-signed timer state plus its own clock, as the specification requires, so the grant stays clock-free.

## Consequences

- Timer interactions are deterministic and fast to test (`test_f2_holds.py`, `test_f6_degradation.py`).
- Advancing the clock past the stop list's validity makes it stale, as it would in production; tests that advance time far must republish the list (`ops.republish_stop_list()`), which is the channel's own heartbeat. Several tests were first written without that and failed correctly.
- A deployment replaces `Clock` with a real one and `tick()` with a scheduler; no component logic changes.
