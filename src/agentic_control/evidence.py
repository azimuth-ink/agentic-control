"""EVS, the Evidence Store (spec A.6), and the PEP's signed local journal (A.4).

Append-only, per event, hash-chained; `append` returns a durable acknowledgement; the chain head is
witnessed on a schedule by a party outside the operator; payloads that may hold personal data live in a
separate store referenced by keyed hash and can be erased while the event stands."""
from __future__ import annotations

from typing import Any, Callable

from . import events as schema
from .common import Availability, Clock, canonical_json, digest, new_id, sha256_hex
from .crypto import Signer, TrustStore


class PayloadStore:
    """Separable, erasable payloads referenced by keyed hash (A.6)."""

    def __init__(self) -> None:
        self._items: dict[str, Any] = {}
        self.erased: set[str] = set()

    def put(self, payload: Any) -> str:
        ref = "p:" + digest(payload)
        self._items[ref] = payload
        return ref

    def get(self, ref: str) -> Any:
        if ref in self.erased:
            raise KeyError(f"{ref} erased")
        return self._items[ref]

    def erase(self, ref: str) -> None:
        self._items.pop(ref, None)
        self.erased.add(ref)


class EvidenceStore(Availability):
    name = "EVS"

    def __init__(self, clock: Clock, witness: Callable[[str, float], dict[str, Any]] | None = None) -> None:
        self.clock = clock
        self.events: list[dict[str, Any]] = []
        self.payloads = PayloadStore()
        self._witness = witness or (lambda head, t: {"head": head, "witnessed_at": t, "by": "external-witness"})
        self.witness_log: list[dict[str, Any]] = []
        self.ack_count = 0

    @property
    def head(self) -> str:
        return self.events[-1]["hash"] if self.events else "genesis"

    def append(self, event: dict[str, Any]) -> str:
        """Validates, chains and durably acknowledges one event. Returns the event id."""
        self._check()
        ev = dict(event)
        ev.setdefault("event_id", new_id("ev"))
        ev.setdefault("timestamp", self.clock.now())
        schema.validate(ev)
        ev["prev_hash"] = self.head
        body = {k: v for k, v in ev.items() if k != "hash"}
        ev["hash"] = sha256_hex(canonical_json(body))
        self.events.append(ev)
        self.ack_count += 1
        return ev["event_id"]

    def read(self, run_id: str | None = None, trace_id: str | None = None) -> list[dict[str, Any]]:
        self._check()
        return [e for e in self.events if (run_id is None or e.get("run_id") == run_id)
                and (trace_id is None or e.get("trace_id") == trace_id)]

    def read_unchecked(self, run_id: str) -> list[dict[str, Any]]:
        """For a verifier or a test: read without the availability gate."""
        return [e for e in self.events if e.get("run_id") == run_id]

    def verify(self, start: int = 0, end: int | None = None) -> bool:
        """Recomputes the chain over a range."""
        end = len(self.events) if end is None else end
        prev = self.events[start - 1]["hash"] if start > 0 else "genesis"
        for e in self.events[start:end]:
            if e["prev_hash"] != prev:
                return False
            body = {k: v for k, v in e.items() if k != "hash"}
            if sha256_hex(canonical_json(body)) != e["hash"]:
                return False
            prev = e["hash"]
        return True

    def witness(self) -> dict[str, Any]:
        """The chain head is witnessed (timestamped) by a system outside the operator's control."""
        rec = self._witness(self.head, self.clock.now())
        self.witness_log.append(rec)
        return rec

    def event_verifies(self, event_id: str) -> bool:
        """Whether a recorded event verifies against the hash chain (used by the PDP for compensation)."""
        for i, e in enumerate(self.events):
            if e["event_id"] == event_id:
                return self.verify(i, i + 1)
        return False

    def reconcile(self, journal: "Journal", trust: TrustStore) -> int:
        """Journals reconcile into EVS in order with a journal.reconciled event naming the gap."""
        self._check()
        entries = journal.drain(trust)
        for e in entries:
            e = dict(e)
            e.pop("prev_hash", None); e.pop("hash", None)
            self.append(e)
        if entries:
            self.append({"type": "journal.reconciled", "scope": journal.workload,
                         "gap_start": entries[0].get("timestamp"), "gap_end": entries[-1].get("timestamp"),
                         "events_count": len(entries), "counters_merged": journal.counters_merged()})
        return len(entries)

    def erase(self, run_id: str, refs: list[str], authority: str) -> None:
        for r in refs:
            self.payloads.erase(r)
        self.append({"type": "erasure.applied", "scope": run_id, "run_id": run_id, "payload_refs": refs, "authority": authority})


class Journal:
    """The PEP's append-only local journal, signed with the workload key, used only in degraded mode."""

    def __init__(self, workload: str, signer: Signer, clock: Clock) -> None:
        self.workload = workload
        self.signer = signer
        self.clock = clock
        self.entries: list[dict[str, Any]] = []
        self.local_counters: dict[str, int] = {}

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        ev = dict(event)
        ev.setdefault("event_id", new_id("jv"))
        ev.setdefault("timestamp", self.clock.now())
        schema.validate(ev)
        signed = self.signer.sign(ev)
        self.entries.append(signed)
        return ev

    def events(self) -> list[dict[str, Any]]:
        return [e["payload"] for e in self.entries]

    def drain(self, trust: TrustStore) -> list[dict[str, Any]]:
        out = []
        for e in self.entries:
            if not trust.verify(e, role="workload"):
                raise ValueError("journal entry signature invalid")
            out.append(e["payload"])
        self.entries = []
        return out

    def counters_merged(self) -> int:
        n = sum(self.local_counters.values())
        self.local_counters = {}
        return n

    def entry_verifies(self, event_id: str, trust: TrustStore) -> bool:
        for e in self.entries:
            if e["payload"].get("event_id") == event_id:
                return trust.verify(e, role="workload")
        return False
