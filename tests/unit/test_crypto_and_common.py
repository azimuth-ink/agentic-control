"""Unit: canonical JSON, hashing, the injectable clock, Ed25519 envelopes, the trust store, sealed tokens."""
import pytest

from agentic_control.common import Clock, Denied, Refused, Unavailable, canonical_json, digest, new_id, sha256_hex
from agentic_control.crypto import PublicKey, Sealer, Signer, TrustStore


def test_canonical_json_is_order_independent_and_handles_sets():
    a = canonical_json({"b": 1, "a": [3, 2], "s": {"y", "x"}})
    b = canonical_json({"a": [3, 2], "s": {"x", "y"}, "b": 1})
    assert a == b and b'"a":[3,2]' in a and b'["x","y"]' in a
    assert digest({"x": 1}) == digest({"x": 1}) != digest({"x": 2})
    assert len(sha256_hex(b"")) == 64


def test_clock_is_injectable_and_monotone():
    c = Clock(100.0)
    assert c.now() == 100.0
    assert c.advance(5) == 105.0 and c.now() == 105.0


def test_ids_are_prefixed_and_unique():
    ids = {new_id("run") for _ in range(100)}
    assert len(ids) == 100 and all(i.startswith("run-") for i in ids)


def test_signatures_verify_and_tampering_is_detected():
    s = Signer("alice")
    env = s.sign({"n": 1, "m": [1, 2]})
    assert set(env) == {"payload", "key_id", "sig"}
    assert s.public().verify(env)
    tampered = {**env, "payload": {"n": 2, "m": [1, 2]}}
    assert not s.public().verify(tampered)
    other = Signer("bob")
    assert not other.public().verify(env)
    assert not s.public().verify({**env, "sig": env["sig"][:-4] + "AAAA"})


def test_trust_store_verifies_by_role():
    t = TrustStore()
    run, ops = Signer("RUN"), Signer("OPS")
    t.trust(run, "run"); t.trust(ops, "ops")
    env = run.sign({"a": 1})
    assert t.verify(env, role="run") and t.verify(env) and not t.verify(env, role="ops")
    assert not t.verify(Signer("stranger").sign({"a": 1}))
    t.trust(PublicKey("k", Signer("carol").public().raw), "workload") if hasattr(Signer("carol").public(), "raw") else None


def test_sealed_tokens_open_only_with_the_sealer_key():
    a, b = Sealer(), Sealer()
    tok = a.seal({"grant_id": "g-1", "aud": "IDS"})
    assert a.open(tok) == {"grant_id": "g-1", "aud": "IDS"}
    assert b.open(tok) is None
    assert a.open(tok[:-3] + "xyz") is None


def test_exception_types():
    assert isinstance(Unavailable("EVS"), Exception) and Unavailable("EVS").component == "EVS"
    assert Denied("x").reason == "x"
    with pytest.raises(Refused):
        raise Refused("no")
