"""Signatures and sealed tokens.

Ed25519 for everything that is signed (policy bundles, stop lists, approval records, RUN status
assertions, credentials, journals, trigger envelopes). A symmetric seal (Fernet) for resumption
grants, standing in for the hardware-backed key the specification requires (A.2). Keys are
in-memory; a deployment replaces this module with its key custody (Appendix C)."""
from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .common import canonical_json, sha256_hex


class Signer:
    """Holds a private key and signs canonical JSON. `key_id` is the hash of the public key."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._priv = Ed25519PrivateKey.generate()
        self.public_bytes = self._priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = sha256_hex(self.public_bytes)[:16]

    def sign(self, payload: Any) -> dict[str, Any]:
        """Returns a signed envelope: {payload, key_id, sig}. The payload is kept in the clear."""
        sig = self._priv.sign(canonical_json(payload))
        return {"payload": payload, "key_id": self.key_id, "sig": base64.b64encode(sig).decode("ascii")}

    def public(self) -> "PublicKey":
        return PublicKey(self.key_id, self.public_bytes)


class PublicKey:
    def __init__(self, key_id: str, raw: bytes) -> None:
        self.key_id = key_id
        self._pub = Ed25519PublicKey.from_public_bytes(raw)

    def verify(self, envelope: dict[str, Any]) -> bool:
        try:
            self._pub.verify(base64.b64decode(envelope["sig"]), canonical_json(envelope["payload"]))
            return True
        except (InvalidSignature, KeyError, ValueError):
            return False


class TrustStore:
    """Maps key ids to public keys and, optionally, to the role the key is trusted for."""

    def __init__(self) -> None:
        self._keys: dict[str, PublicKey] = {}
        self._roles: dict[str, set[str]] = {}

    def trust(self, signer_or_key: Signer | PublicKey, role: str) -> None:
        key = signer_or_key.public() if isinstance(signer_or_key, Signer) else signer_or_key
        self._keys[key.key_id] = key
        self._roles.setdefault(key.key_id, set()).add(role)

    def verify(self, envelope: dict[str, Any], role: str | None = None) -> bool:
        key = self._keys.get(envelope.get("key_id", ""))
        if key is None:
            return False
        if role is not None and role not in self._roles.get(key.key_id, set()):
            return False
        return key.verify(envelope)


class Sealer:
    """Authenticated encryption for opaque tokens (resumption grants)."""

    def __init__(self) -> None:
        self._f = Fernet(Fernet.generate_key())

    def seal(self, payload: Any) -> str:
        return self._f.encrypt(canonical_json(payload)).decode("ascii")

    def open(self, token: str) -> Any | None:
        try:
            return json.loads(self._f.decrypt(token.encode("ascii")))
        except (InvalidToken, ValueError):
            return None
