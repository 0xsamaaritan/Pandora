"""Persistent state so scheduled runs alert only on NEW findings.

Stored as a single JSON file keyed by each finding's dedupe key. Last-seen is
refreshed for repeats; brand-new keys are returned as `new` for alerting.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Iterable

from .model import Finding


class Store:
    def __init__(self, path: str):
        self.path = path
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                self._data = json.load(fh)

    def save(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, self.path)  # atomic

    def reconcile(self, findings: Iterable[Finding]) -> list[Finding]:
        """Merge a run's findings into state; return only the NEW ones."""
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        new: list[Finding] = []
        for f in findings:
            key = f.dedupe_key()
            if key in self._data:
                self._data[key]["last_seen"] = now
            else:
                rec = f.to_dict()
                rec["first_seen"] = now
                rec["last_seen"] = now
                self._data[key] = rec
                new.append(Finding.from_dict(rec))
        return new

    def all_findings(self) -> list[Finding]:
        return [Finding.from_dict(v) for v in self._data.values()]
