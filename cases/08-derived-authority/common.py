"""Shared vocabulary for the two arms, so the comparison is like for like."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


class AuthorizationError(RuntimeError):
    """No grant could be resolved. Both arms raise this, for their own reasons."""


@dataclass(frozen=True)
class Grant:
    """What a step is permitted to do. The unit of comparison.

    Both arms produce this. Arm A reads it out of a table; arm B computes it.
    Nothing here is a capability in the concept note's §5 sense - no audience,
    no expiry, no use count, no issuer - and it must not be called one.
    """

    read_keys: List[str] = field(default_factory=list)
    write_key: str = ""
    actions: List[str] = field(default_factory=list)
    source: str = ""

    def permits_read(self, key: str) -> bool:
        return key in self.read_keys

    def describe(self) -> str:
        return f"reads {sorted(self.read_keys)} writes {self.write_key!r}"
