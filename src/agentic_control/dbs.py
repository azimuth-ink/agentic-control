"""DBS, the Data Boundary Service (spec A.7), plus the system-of-record contract the reference
implementation's fake systems follow.

Everything here is reached through the PEP as tools: retrieval, memory, derived stores, sanitizers,
delivery tools (to an interface or a sink store), and the outbound data-loss check."""
from __future__ import annotations

import re
from typing import Any, Callable

from .common import Availability, digest


class SystemRefused(Exception):
    """A definitive negative from a system of record: it refused or errored before committing."""


class Indeterminate(Exception):
    """The outcome is unknown: a timeout or a lost response after the call was sent."""


class System(Availability):
    """A system of record or a DBS-managed store. Records are dicts; a tagging system stores a per-field
    provenance tag (`_tags`: field -> 'untrusted' | 'exposed' | 'verified')."""

    def __init__(self, system_id: str, ids: Any, tagging: bool = False, idempotent: bool = False) -> None:
        self.name = system_id
        self.system_id = system_id
        self.ids = ids
        self.tagging = tagging
        self.idempotent = idempotent
        self.records: dict[str, dict[str, Any]] = {}
        self.calls: list[dict[str, Any]] = []
        self.seen_keys: dict[str, dict[str, Any]] = {}
        self.fail_next: str | None = None        # 'refuse' | 'indeterminate' | 'indeterminate_but_executed'
        self.accepted_classes: set[str] = {"governed_agent", "recovery"}

    # --- credential acceptance: what a system checks
    def _accept(self, credential: dict[str, Any] | None, presenter: str, purpose: str, action_hash: str | None) -> None:
        if credential is None:
            raise SystemRefused("no credential")
        if not self.ids.verify_credential(credential, presenter, self.system_id):
            raise SystemRefused("credential rejected: signature, presenter binding, audience or expiry")
        c = credential["payload"]
        if c["purpose"] in {"compensation", "replay"}:
            if c["action_hash"] != action_hash:
                raise SystemRefused("reversal or replay credential does not carry this action hash")
        elif c["purpose"] != "normal":
            raise SystemRefused("purpose not accepted")

    def read(self, tool: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Default read: returns records whose key matches params. Items carry `tainted` from tags."""
        self._check()
        out = []
        for k, rec in self.records.items():
            if all(rec.get(p) == v for p, v in params.items() if p in rec):
                item = dict(rec)
                tags = rec.get("_tags", {})
                item["tainted"] = any(t in {"untrusted", "exposed"} for t in tags.values()) if self.tagging else False
                out.append(item)
        return out

    def execute(self, tool: str, params: dict[str, Any], credential: dict[str, Any] | None, presenter: str,
                purpose: str = "normal", action_hash: str | None = None, idempotency_key: str | None = None,
                tag: str | None = None) -> dict[str, Any]:
        """An effect. Idempotent systems replay a seen key by returning the recorded result."""
        self._check()
        self._accept(credential, presenter, purpose, action_hash)
        if self.fail_next == "refuse":
            self.fail_next = None
            raise SystemRefused("system refused")
        if idempotency_key and idempotency_key in self.seen_keys:
            return self.seen_keys[idempotency_key]
        if self.fail_next == "indeterminate":
            self.fail_next = None
            raise Indeterminate("timeout")
        result = self.apply(tool, params, tag)
        self.calls.append({"tool": tool, "params": dict(params), "purpose": purpose, "result": result})
        if idempotency_key and self.idempotent:
            self.seen_keys[idempotency_key] = result
        if self.fail_next == "indeterminate_but_executed":
            self.fail_next = None
            raise Indeterminate("response lost")
        return result

    def apply(self, tool: str, params: dict[str, Any], tag: str | None) -> dict[str, Any]:
        raise NotImplementedError

    def preview(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"would_change": params}

    def write_record(self, key: str, rec: dict[str, Any], tag: str | None) -> None:
        r = dict(rec)
        if self.tagging:
            tags = dict(self.records.get(key, {}).get("_tags", {}))
            for f_ in rec:
                tags[f_] = tag or "clean"
            r["_tags"] = tags
        self.records[key] = r


class MemoryStore(System):
    """kind = memory: writes carry apply_provenance_tag; items written during an exposed run are stored
    tainted and returned flagged. A memory write is a decided call, not an effect."""

    def __init__(self, system_id: str, ids: Any) -> None:
        super().__init__(system_id, ids, tagging=True)

    def apply(self, tool: str, params: dict[str, Any], tag: str | None) -> dict[str, Any]:
        key = params.get("key") or digest(params)
        self.write_record(key, {"key": key, "value": params.get("value")}, tag)
        return {"stored": key}

    def execute(self, tool, params, credential, presenter, purpose="normal", action_hash=None, idempotency_key=None, tag=None):
        self._check()
        return self.apply(tool, params, tag)


class SinkStore(MemoryStore):
    """kind = sink_store: append-only, provenance-tagged, internal; never the target of a side-effect tool."""

    def apply(self, tool: str, params: dict[str, Any], tag: str | None) -> dict[str, Any]:
        key = digest({"n": len(self.records), "p": params})
        self.write_record(key, {"key": key, "content": params.get("content"), "sink": params.get("sink")}, tag)
        return {"stored": key}


class Interface(System):
    """kind = interface: the enterprise delivery surface; stores nothing; the delivery event is the record."""

    def __init__(self, system_id: str, ids: Any) -> None:
        super().__init__(system_id, ids)
        self.delivered: list[dict[str, Any]] = []

    def execute(self, tool, params, credential, presenter, purpose="normal", action_hash=None, idempotency_key=None, tag=None):
        self._check()
        self.delivered.append({"recipient": params.get("recipient"), "content": params.get("content"), "tag": tag})
        return {"delivered_to": params.get("recipient")}


class DLP:
    """Data-loss inspection, invoked by the PEP under the dlp_check obligation before anything is sent."""

    def __init__(self, blocked_patterns: list[str] | None = None) -> None:
        self.patterns = [re.compile(p) for p in (blocked_patterns or [r"SSN-\d{3}-\d{2}-\d{4}"])]
        self.checked: list[dict[str, Any]] = []

    def check(self, params: dict[str, Any]) -> bool:
        text = " ".join(str(v) for v in params.values())
        ok = not any(p.search(text) for p in self.patterns)
        self.checked.append({"params": params, "ok": ok})
        return ok


# ---------------------------------------------------------------------- sanitizers (5.3)
def rendering_sanitizer(inp: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Removes hyperlinks, image and media references, data URIs, query strings, and runs of encoded
    data above a registered length; passes plain text and declared structured fields."""
    text = str(inp.get("content", ""))
    rejected: list[str] = []

    def strip(pattern: str, s: str) -> str:
        found = re.findall(pattern, s)
        rejected.extend(found)
        return re.sub(pattern, "", s)

    text = strip(r"https?://\S+", text)
    text = strip(r"data:[\w/+.-]+;base64,[A-Za-z0-9+/=]+", text)
    text = strip(r"!\[[^\]]*\]\([^)]*\)", text)
    text = strip(r"\?[\w=&%.-]{3,}", text)
    text = strip(r"[A-Za-z0-9+/]{64,}={0,2}", text)
    return {"content": text.strip()}, {"removed": rejected}


def identifier_numeric_extractor(pattern: str, fields: dict[str, str]) -> Callable[[dict[str, Any]], tuple[dict[str, Any], dict[str, Any]]]:
    """A deterministic extractor: identifiers must match the registered pattern; amounts must be numeric.
    Output schema has no free string field, so its accepted values carry sanitized provenance."""
    rx = re.compile(pattern)

    def fn(inp: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        accepted: dict[str, Any] = {}
        rejected: dict[str, Any] = {}
        for f_, kind in fields.items():
            v = inp.get(f_)
            if kind == "identifier":
                if isinstance(v, str) and rx.fullmatch(v):
                    accepted[f_] = v
                else:
                    rejected[f_] = v
            elif kind == "number":
                try:
                    accepted[f_] = float(v)
                except (TypeError, ValueError):
                    rejected[f_] = v
        return accepted, rejected

    return fn
