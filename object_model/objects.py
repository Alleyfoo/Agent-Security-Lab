"""The work object, the ready-work item, and the grant they resolve to.

The object carries its type, its workflow state, and the map binding artifact
*types* to concrete keys. Objects are persisted, because the architecture
intends them to be — and because "the tampering survives a resume" has to be a
measurement rather than an assumption (case 08).

The artifact map is the record case 08 measured as the cheapest authority
surface in this model. Nothing here protects it. That is case 10's subject and
this module should not pretend otherwise.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass(frozen=True)
class Grant:
    """What a step is permitted to do. Computed at use time, never stored.

    Not a capability in the concept note's §5 sense — no audience, no expiry,
    no use count, no issuer — and it must not be called one.
    """

    read_keys: List[str] = field(default_factory=list)
    write_key: str = ""
    actions: List[str] = field(default_factory=list)
    skill: str = ""

    def permits_read(self, key: str) -> bool:
        return key in self.read_keys

    def describe(self) -> str:
        return f"reads {sorted(self.read_keys)} writes {self.write_key!r}"


@dataclass
class WorkObject:
    """Type, state, and the type-to-key artifact map."""

    object_id: str
    object_type: str
    state: str
    artifacts: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class QueueItem:
    """Ready work. A proposal, re-validated by the manager (§12)."""

    object_id: str
    skill: str


def save_object(obj: WorkObject, store_dir: str) -> str:
    os.makedirs(store_dir, exist_ok=True)
    path = os.path.join(store_dir, f"{obj.object_id}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj.to_dict(), fh, indent=2)
    return path


def load_object(object_id: str, store_dir: str) -> WorkObject:
    path = os.path.join(store_dir, f"{object_id}.json")
    with open(path, "r", encoding="utf-8") as fh:
        return WorkObject(**json.load(fh))
