"""Immutable shared artifacts accessed through capability-scoped views."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_source_hash(artifact: Dict[str, Any]) -> str:
    payload = {k: v for k, v in artifact.items() if k != "source_hash"}
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


class DuplicateKeyError(KeyError):
    """Raised when an immutable key is reused for different content."""


class ArtifactIntegrityError(RuntimeError):
    """Raised when a stored artifact no longer matches its registered hash.

    Distinct from :class:`DuplicateKeyError` (an attempt to rebind a key) and
    from ``ContractError`` (an agent exceeding its grant). This one means the
    bytes under an existing key changed after registration - corruption of the
    data plane, which is a different incident and warrants different triage.

    Detection, not prevention: by the time this raises, the mutation has
    already happened. See cases/02-artifact-mutation/README.md.
    """


def _integrity_error(key: str, stored: str, recomputed: str) -> ArtifactIntegrityError:
    return ArtifactIntegrityError(
        f"artifact {key!r} failed integrity verification: stored hash "
        f"{stored[:8]}... does not match recomputed {recomputed[:8]}... - "
        "the artifact was modified in place after registration"
    )


@dataclass
class ArtifactStore:
    """In-memory registry whose public reads always return deep copies."""

    _artifacts: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def register(self, key: str, artifact: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(artifact, dict):
            raise TypeError("artifact must be a dict")
        if "type" not in artifact:
            raise ValueError(f"artifact for {key!r} missing required 'type' field")

        content = deepcopy(artifact)
        stored = {**content, "source_hash": compute_source_hash(content)}
        existing = self._artifacts.get(key)
        if existing is not None:
            if existing["source_hash"] != stored["source_hash"]:
                raise DuplicateKeyError(
                    f"key {key!r} already registered with different content "
                    f"(existing hash {existing['source_hash'][:8]}..., "
                    f"new hash {stored['source_hash'][:8]}...)"
                )
            return deepcopy(existing)

        self._artifacts[key] = stored
        return deepcopy(stored)

    def get(self, key: str) -> Dict[str, Any]:
        """Return a deep copy, after verifying the artifact still matches the
        hash registered for it (control C1, case 02).

        Guarantee: no consumer receives artifact content that does not match
        its registered hash.
        """
        try:
            stored = self._artifacts[key]
        except KeyError:
            raise KeyError(key)
        self._verify(key, stored)
        return deepcopy(stored)

    @staticmethod
    def _verify(key: str, stored: Dict[str, Any]) -> None:
        recorded = stored.get("source_hash", "")
        recomputed = compute_source_hash(
            {k: v for k, v in stored.items() if k != "source_hash"}
        )
        if recorded != recomputed:
            raise _integrity_error(key, recorded, recomputed)

    def verify_all(self) -> List[str]:
        """Return the keys of every artifact whose content no longer matches
        its registered hash (control C2, case 02).

        Guarantee: an in-place mutation is detected at the end of the step in
        which it occurred, whether or not anything subsequently reads the
        artifact. Returns rather than raises, so the caller can report every
        affected key instead of only the first.
        """
        corrupted: List[str] = []
        for key, stored in self._artifacts.items():
            try:
                self._verify(key, stored)
            except ArtifactIntegrityError:
                corrupted.append(key)
        return corrupted

    def has(self, key: str) -> bool:
        return key in self._artifacts

    def keys(self) -> List[str]:
        return list(self._artifacts.keys())

    def as_dict(self) -> Dict[str, Dict[str, Any]]:
        return deepcopy(self._artifacts)

    def __contains__(self, key: str) -> bool:
        return key in self._artifacts

    def __iter__(self) -> Iterator[str]:
        return iter(self._artifacts)

    def __len__(self) -> int:
        return len(self._artifacts)

    def to_snapshot(self) -> Dict[str, Dict[str, Any]]:
        return self.as_dict()

    @classmethod
    def from_snapshot(cls, snapshot: Dict[str, Dict[str, Any]]) -> "ArtifactStore":
        store = cls()
        for key, artifact in snapshot.items():
            if not isinstance(artifact, dict) or "source_hash" not in artifact:
                raise ValueError(f"snapshot artifact {key!r} missing source_hash")
            if artifact["source_hash"] != compute_source_hash(artifact):
                raise ValueError(f"snapshot artifact {key!r} has invalid source_hash")
            store._artifacts[key] = deepcopy(artifact)
        return store

    def summary(self) -> List[Dict[str, Any]]:
        return [
            {"key": key, "type": value.get("type"), "status": value.get("status"),
             "source_hash": value.get("source_hash")}
            for key, value in self._artifacts.items()
        ]

    def view(self, read_keys: List[str], write_key: str = "") -> "StoreView":
        return StoreView(self, read_keys=read_keys, write_key=write_key)


class StoreView:
    """Capability-scoped store handle that records actual reads and writes."""

    def __init__(self, store: ArtifactStore, read_keys: List[str],
                 write_key: str = "") -> None:
        self._store = store
        self._read_grants = set(read_keys)
        self._write_grant = write_key
        self._read_log: List[str] = []
        self._write_log: List[str] = []

    @property
    def read_keys(self) -> List[str]:
        return list(self._read_log)

    @property
    def written_keys(self) -> List[str]:
        return list(self._write_log)

    @staticmethod
    def _contract_error(message: str):
        from agent_network_demo.contracts import ContractError
        return ContractError(message)

    def get(self, key: str) -> Dict[str, Any]:
        if key not in self._read_grants:
            raise self._contract_error(
                f"read of {key!r} denied: granted {sorted(self._read_grants)}"
            )
        self._read_log.append(key)
        return self._store.get(key)

    def has(self, key: str) -> bool:
        return key in self._read_grants and self._store.has(key)

    def register(self, key: str, artifact: Dict[str, Any]) -> Dict[str, Any]:
        if not self._write_grant:
            raise self._contract_error(
                f"write of {key!r} denied: this envelope declared no output_contract"
            )
        if key != self._write_grant:
            raise self._contract_error(
                f"write of {key!r} denied: granted {self._write_grant!r}"
            )
        result = self._store.register(key, artifact)
        self._write_log.append(key)
        return result
