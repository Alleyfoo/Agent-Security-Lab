"""An append-only record of what each completed step produced.

Case 10's candidate control. The object's artifact map is a *stored
conclusion*: "type T is at key K". The premises are older and narrower — a step
ran, it was required, and it produced one artifact of one type. Recording the
premises and deriving the map is the same move case 08 tested one level up.

Append-only *by API*, in the same sense as the product's `EventLog` and
`ReceiptLedger`. It is not tamper-evident: no chain, and same-process code
reaches `_records`. What it changes is the shape of a successful edit — a
rebinding becomes an append that has to coexist with the record it contradicts,
rather than an overwrite that erases it.

One invariant, and it is the whole reason this might be better than a dict:

    an artifact type is produced at most once per object

so a second record for a type already produced is a conflict rather than a
replacement.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional


class LedgerIntegrityError(RuntimeError):
    """The production record contradicts itself."""


@dataclass(frozen=True)
class ProductionRecord:
    object_id: str
    at_state: str
    skill: str
    artifact_type: str
    key: str


class ProductionLedger:
    """Runner-owned. Objects do not hold one and cannot append through one."""

    __slots__ = ("_records", "_path")

    def __init__(self, path: Optional[str] = None) -> None:
        self._records: List[ProductionRecord] = []
        self._path = path

    # -- append ----------------------------------------------------------
    def record(self, object_id: str, at_state: str, skill: str,
               artifact_type: str, key: str) -> ProductionRecord:
        entry = ProductionRecord(object_id, at_state, skill, artifact_type, key)
        self._append(entry, check=True)
        return entry

    def _append(self, entry: ProductionRecord, check: bool) -> None:
        if check:
            existing = self._first_for(entry.object_id, entry.artifact_type)
            if existing is not None:
                raise LedgerIntegrityError(
                    f"{entry.artifact_type!r} was already produced for "
                    f"{entry.object_id!r} at key {existing.key!r} by "
                    f"{existing.skill!r}; refusing to record it again at "
                    f"{entry.key!r}"
                )
        self._records.append(entry)
        if self._path:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(entry), sort_keys=True) + "\n")

    # -- read ------------------------------------------------------------
    def _first_for(self, object_id: str,
                   artifact_type: str) -> Optional[ProductionRecord]:
        for entry in self._records:
            if entry.object_id == object_id and entry.artifact_type == artifact_type:
                return entry
        return None

    def records_for(self, object_id: str) -> List[ProductionRecord]:
        return [e for e in self._records if e.object_id == object_id]

    def conflicts_for(self, object_id: str) -> List[str]:
        """Types recorded more than once. Empty on an untampered ledger,
        because ``record`` refuses the second one - so a non-empty result means
        something wrote past the API."""
        seen: Dict[str, str] = {}
        conflicts: List[str] = []
        for entry in self.records_for(object_id):
            if entry.artifact_type in seen and seen[entry.artifact_type] != entry.key:
                conflicts.append(
                    f"{entry.artifact_type!r}: {seen[entry.artifact_type]!r} "
                    f"then {entry.key!r}")
            seen.setdefault(entry.artifact_type, entry.key)
        return conflicts

    def map_for(self, object_id: str) -> Dict[str, str]:
        """Derive the type-to-key map. First production wins, so a later
        contradicting append does not silently replace an earlier binding."""
        derived: Dict[str, str] = {}
        for entry in self.records_for(object_id):
            derived.setdefault(entry.artifact_type, entry.key)
        return derived

    def __len__(self) -> int:
        return len(self._records)

    def __bool__(self) -> bool:
        """A ledger with nothing in it is still a ledger.

        Without this, ``__len__`` makes a fresh one falsy and ``if ledger:``
        silently selects the stored-map arm - which is exactly how the first
        run of case 10's harness measured the wrong thing.
        """
        return True

    @classmethod
    def load(cls, path: str) -> "ProductionLedger":
        ledger = cls(path=path)
        if not os.path.exists(path):
            return ledger
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    # No check on reload: the file is the record, conflicts and
                    # all. conflicts_for() is how a caller finds out.
                    ledger._records.append(ProductionRecord(**json.loads(line)))
        return ledger

    def seed(self, object_id: str, artifacts: Dict[str, str],
             at_state: str = "intake", skill: str = "intake") -> None:
        """Record artifacts an object arrived with rather than produced."""
        for artifact_type, key in artifacts.items():
            self.record(object_id, at_state, skill, artifact_type, key)
