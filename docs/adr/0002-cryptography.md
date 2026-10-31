# ADR 0002 — Signatures, trust roles, and sealed grants

**Status:** accepted (0.1.0)

## Context

The specification signs several things: the policy bundle and stop list (PDP, OPS), approval records and run-status assertions (RUN), credentials (IDS), journal entries (the workload key), trigger envelopes (the source system), and it seals resumption grants under a key only IDS opens. What a verifier trusts is a key *in a role*: a RUN-signed record is accepted only from the RUN key, not from any trusted key.

## Decision

- **Ed25519** for every signature (`crypto.Signer`), over canonical JSON of the payload (`common.canonical_json`: sorted keys, sets as sorted lists, compact separators). An envelope is `{payload, key_id, sig}`.
- A **role-keyed trust store** (`crypto.TrustStore`): `trust(key, role)` and `verify(envelope, role=...)`. Verifiers always name the role (`run`, `ops`, `ids`, `identity_provider`, `workload`, `policy`), so a key trusted for one role cannot sign for another.
- **Fernet** (AES-128-CBC + HMAC-SHA256) for the resumption grant (`crypto.Sealer`): the grant is opaque to RUN, which stores it, and opens only at IDS. The grant carries no clock; expiry is computed at redemption from RUN-signed timer state (4.4).
- Keys are generated in memory per component instance. There is no key management, rotation, or hardware backing; the specification's "hardware-backed key" for grants is a deployment matter.

## Consequences

- Tamper tests are real: a changed payload byte fails verification (`tests/unit/test_crypto_and_common.py`, the journal and evidence-chain tests).
- The only external dependency is `cryptography`. Nothing is hand-rolled.
- Trigger envelopes are verified against the public key REG holds for the trigger (`registry.Trigger.signing_key`), not the trust store, because the source system is not a control-plane role.
