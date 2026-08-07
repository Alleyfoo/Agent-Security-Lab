"""The bounded skill set. This is the authority boundary.

Four skills, and the set is the whole of what a worker can cause. There is no
`find_alternative` here on purpose - searching for a different slot is step C,
and putting it in now would let step A quietly start solving problems it is
supposed to only report.

Each skill declares which object states it may run against. The runtime
re-derives that from the object rather than trusting the queue item, so a
queue asking for a transition the object does not permit is refused and
counted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Tuple

from demo_reservation.objects import (
    BOOKED, CANCELLED, CONFIRMED, PENDING, REFUSED, Reservation,
    ReservationRequest, Result, Store,
)
from demo_reservation.world import World


@dataclass(frozen=True)
class Skill:
    """One approved transformation, and the states it may run against."""

    name: str
    permitted_states: Tuple[str, ...]
    mutates: bool


CHECK_AVAILABILITY = "check_availability"
CREATE_RESERVATION = "create_reservation"
CANCEL_RESERVATION = "cancel_reservation"
QUERY_SCHEDULE = "query_schedule"


_REGISTRY: Dict[str, Skill] = {
    CHECK_AVAILABILITY: Skill(CHECK_AVAILABILITY, (PENDING,), mutates=False),
    CREATE_RESERVATION: Skill(CREATE_RESERVATION, (PENDING,), mutates=True),
    CANCEL_RESERVATION: Skill(CANCEL_RESERVATION, (BOOKED,), mutates=True),
    QUERY_SCHEDULE: Skill(QUERY_SCHEDULE, (PENDING, BOOKED, REFUSED),
                          mutates=False),
}

REGISTRY: Dict[str, Skill] = dict(_REGISTRY)


# ---------------------------------------------------------------------------
# Availability. One definition, used by check and create alike, so the two
# cannot drift - the reason case 05 gave for sharing one derivation.
# ---------------------------------------------------------------------------

def _blockers(request: ReservationRequest, store: Store,
              world: World) -> Tuple[str, ...]:
    facility = world.get(request.facility_id)
    if facility is None:
        return (f"no facility {request.facility_id!r}",)

    reasons = []
    if not facility.hours.is_open(request.day, request.start, request.end):
        reasons.append("outside opening hours")
    if request.participants > facility.capacity:
        reasons.append(
            f"capacity {facility.capacity} < {request.participants}")
    missing = set(request.requires) - set(facility.features)
    if missing:
        reasons.append(f"missing {sorted(missing)}")
    for existing in store.schedule():
        if (existing.facility_id == request.facility_id
                and existing.day == request.day
                and existing.start < request.end
                and request.start < existing.end):
            reasons.append(f"occupied by {existing.reservation_id}")
            break
    return tuple(reasons)


# ---------------------------------------------------------------------------
# The skills.
# ---------------------------------------------------------------------------

def check_availability(request: ReservationRequest, store: Store,
                       world: World) -> Result:
    blockers = _blockers(request, store, world)
    request.last_check = not blockers
    return Result(CHECK_AVAILABILITY, request.request_id, ok=not blockers,
                  detail="available" if not blockers else "; ".join(blockers))


def create_reservation(request: ReservationRequest, store: Store,
                       world: World) -> Result:
    """Re-checks rather than trusting `last_check`.

    The queue may have said this was available three steps ago and the world
    may have moved. Trusting the advisory field would make the queue
    authoritative about the outcome, which is the shape this architecture
    exists to avoid.
    """
    blockers = _blockers(request, store, world)
    if blockers:
        request.state = REFUSED
        return Result(CREATE_RESERVATION, request.request_id, ok=False,
                      detail="; ".join(blockers))

    reservation_id = f"res_{request.request_id.split('_')[-1]}"
    store.reservations[reservation_id] = Reservation(
        reservation_id=reservation_id, request_id=request.request_id,
        facility_id=request.facility_id, day=request.day,
        start=request.start, end=request.end, activity=request.activity,
        participants=request.participants, requires=request.requires)
    request.state = BOOKED
    request.reservation_id = reservation_id
    return Result(CREATE_RESERVATION, request.request_id, ok=True,
                  detail="booked", produced=reservation_id)


def cancel_reservation(request: ReservationRequest, store: Store,
                       world: World) -> Result:
    reservation = store.reservations.get(request.reservation_id or "")
    if reservation is None or reservation.state != CONFIRMED:
        return Result(CANCEL_RESERVATION, request.request_id, ok=False,
                      detail="no confirmed reservation to cancel")
    reservation.state = CANCELLED
    request.state = REFUSED
    return Result(CANCEL_RESERVATION, request.request_id, ok=True,
                  detail=f"cancelled {reservation.reservation_id}")


def query_schedule(request: ReservationRequest, store: Store,
                   world: World) -> Result:
    """Read-only. Reports what is already booked in the facility on that day."""
    same_day = [r for r in store.schedule()
                if r.facility_id == request.facility_id
                and r.day == request.day]
    return Result(QUERY_SCHEDULE, request.request_id, ok=True,
                  detail=f"{len(same_day)} reservation(s) that day")


HANDLERS: Dict[str, Callable[[ReservationRequest, Store, World], Result]] = {
    CHECK_AVAILABILITY: check_availability,
    CREATE_RESERVATION: create_reservation,
    CANCEL_RESERVATION: cancel_reservation,
    QUERY_SCHEDULE: query_schedule,
}
