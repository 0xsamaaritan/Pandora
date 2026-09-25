"""Finding model + stable dedupe key."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# Rough severity ordering so reports can sort worst-first.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    source: str                       # which source produced it, e.g. "crtsh"
    mode: str                         # "surface" or "dark"
    title: str                        # short human-readable label
    url: str = ""                     # where it lives (may be empty for a leak record)
    snippet: str = ""                 # context / excerpt
    matched_terms: list[str] = field(default_factory=list)
    severity: str = "info"            # critical|high|medium|low|info
    raw: dict[str, Any] = field(default_factory=dict)  # source-specific extras
    first_seen: str = field(default_factory=_now_iso)
    last_seen: str = field(default_factory=_now_iso)

    def dedupe_key(self) -> str:
        """Stable identity so the same hit across runs is recognised, not re-alerted.

        Deliberately excludes timestamps and the snippet (which can wobble).
        """
        basis = f"{self.source}|{self.mode}|{self.url}|{self.title}".lower()
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["id"] = self.dedupe_key()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        d = dict(d)
        d.pop("id", None)
        return cls(**d)
