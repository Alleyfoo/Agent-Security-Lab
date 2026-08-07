"""The work objects, and the queue item that refers to one.

The queue item carries a **reference**, not an instruction:

    QueueItem(object_id, skill)

which is the target architecture's direction of control and, not by accident,
the same shape `object_model.QueueItem` already had. The runtime re-derives
what a skill is permitted to do from the object's own state rather than
trusting the item, so the queue is not authoritative about what should happen.

`object_model` is deliberately **not** imported. Cases 10 and 11 published
tables against its registry and workflow table, and adding reservation skills
to it would change a published measurement. The idioms are shared; the code is
not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple


# -- request lifecycle ------------------------------------------------------
PENDING = "pending"
BOOKED = "booked"
REFUSED = "refused"
# Step C: the agent looked for somewhere else to put this and found nothing.
# It is a state, not a decision about who should look at it - the escalation
# taxonomy is an output of the simulation, not an input.
UNRESOLVED = "unresolved"

# -- reservation lifecycle --------------------------------------------------
CONFIRMED = "confirmed"
CANCELLED = "cancelled"


@dataclass
class ReservationRequest:
    """A structured request. Already valid on arrival - there is no parsing
    step in this demo and there is not meant to be one."""

    request_id: str
    facility_id: str
    day: int
    start: int                      # minutes from midnight
    end: int
    activity: str
    participants: int
    requires: FrozenSet[str] = frozenset()
    state: str = PENDING
    # Filled in by check_availability. Advisory only: create_reservation does
    # not trust it and re-checks, which is what stops the queue from being
    # authoritative.
    last_check: Optional[bool] = None
    reservation_id: Optional[str] = None
    # Filled in by find_alternative. Advisory, exactly like last_check:
    # move_reservation re-derives the slot's availability rather than
    # trusting it.
    candidate: Optional[Tuple[str, int, int]] = None

    def describe(self) -> str:
        return (f"{self.activity} in {self.facility_id} "
                f"d{self.day} {self.start}-{self.end} "
                f"({self.participants}p)")


@dataclass
class Reservation:
    """A confirmed booking. The thing the invariant checker inspects."""

    reservation_id: str
    request_id: str
    facility_id: str
    day: int
    start: int
    end: int
    activity: str
    participants: int
    requires: FrozenSet[str] = frozenset()
    state: str = CONFIRMED

    def overlaps(self, other: "Reservation") -> bool:
        return (self.facility_id == other.facility_id
                and self.day == other.day
                and self.start < other.end and other.start < self.end)


@dataclass(frozen=True)
class QueueItem:
    """Ready work: which object, which skill. No parameters, no instructions."""

    object_id: str
    skill: str


@dataclass(frozen=True)
class Result:
    """What one skill call did. Returned for measurement, never for authority.

    `ok=False` is an ordinary refusal - a slot was taken, a hall is too small.
    Step A has no notion of an exception or an escalation and must not grow
    one; that is step C.
    """

    skill: str
    object_id: str
    ok: bool
    detail: str = ""
    produced: Optional[str] = None


@dataclass
class Receipt:
    """The runtime's own record of a step. Runner-owned: skills never write it,
    which is case 00's finding applied before anyone attacks this one."""

    seq: int
    object_id: str
    skill: str
    ok: bool
    detail: str
    refused_transition: bool = False


@dataclass
class Store:
    """Everything that persists. One place, so the invariant checker can be
    handed a schedule without being handed the machinery that made it."""

    requests: Dict[str, ReservationRequest] = field(default_factory=dict)
    reservations: Dict[str, Reservation] = field(default_factory=dict)

    def schedule(self) -> List[Reservation]:
        """Confirmed reservations only. Cancelled ones stay in the store as
        history and must not appear here, or the invariant checker would find
        overlaps that are not real."""
        return [r for r in self.reservations.values() if r.state == CONFIRMED]

    def counts(self) -> Dict[str, int]:
        by_state: Dict[str, int] = {}
        for request in self.requests.values():
            by_state[request.state] = by_state.get(request.state, 0) + 1
        return by_state
