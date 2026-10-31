"""Shared primitives: canonical JSON, hashing, identifiers, an injectable clock, and the error types
components raise. Section references in docstrings are to the specification, v1.0."""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Deterministic serialisation used for every hash and signature in the reference implementation.
    Sorted keys, no whitespace, UTF-8. Not RFC 8785; adequate for a single implementation that
    both writes and reads its own records."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_default).encode("utf-8")


def _default(o: Any) -> Any:
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    if hasattr(o, "to_dict"):
        return o.to_dict()
    raise TypeError(f"not serialisable: {type(o).__name__}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> str:
    """Hash of the canonical form of a JSON-like value."""
    return sha256_hex(canonical_json(obj))


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class Clock:
    """Injectable time source. Every timer in the architecture (approval timeout, resume window,
    `max_park`, heartbeat deadline, wall-clock budget, credential lifetime) reads this clock, so tests
    advance it instead of sleeping."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self._t = float(start)

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> float:
        self._t += float(seconds)
        return self._t


class ControlError(Exception):
    """Base class for refusals and failures raised by components."""


class Refused(ControlError):
    """A registration, publication, or request was refused by rule (REG refusals, IDS refusals)."""


class Unavailable(ControlError):
    """A component is unreachable. Raised by any call on a component whose `available` flag is off;
    the enforcement point's degraded-mode behaviour (section 6) is built on catching this."""

    def __init__(self, component: str) -> None:
        super().__init__(f"{component} unavailable")
        self.component = component


class Denied(ControlError):
    """A call was denied by the decision point or refused by the enforcement point."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Availability:
    """Mixin giving a component an on/off switch for degradation tests (6.1)."""

    name: str = "component"
    available: bool = True

    def _check(self) -> None:
        if not self.available:
            raise Unavailable(self.name)


@dataclass
class Record:
    """A small helper for dataclasses that need a dict form for hashing."""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in self.__dict__.items():
            if k.startswith("_"):
                continue
            out[k] = _plain(v)
        return out


def _plain(v: Any) -> Any:
    if isinstance(v, Record):
        return v.to_dict()
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    if isinstance(v, (set, frozenset)):
        return sorted(_plain(x) for x in v)
    return v


__all__ = [
    "canonical_json", "sha256_hex", "digest", "new_id", "Clock",
    "ControlError", "Refused", "Unavailable", "Denied", "Availability", "Record", "field",
]
