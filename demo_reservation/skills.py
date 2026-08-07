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
    BOOKED, CANCELLED, CONFIRMED, PENDING, REFUSED, UNRESOLVED, Reservation,
    ReservationRequest, Result, Store,
)
from demo_reservation.world import DAYS, SLOT_MINUTES, World


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
# Step C, and these two are the whole of the new authority.
FIND_ALTERNATIVE = "find_alternative"
MOVE_RESERVATION = "move_reservation"
# Step D. Displacing a confirmed reservation is a protected transformation:
# the worker may propose it and may not perform it. The protection is attached
# to the KIND of transformation, not to a risk score - creating a new booking
# stays local, modifying somebody's existing one does not.
PROPOSE_DISPLACEMENT = "propose_displacement"
EXECUTE_DISPLACEMENT = "execute_displacement"


_REGISTRY: Dict[str, Skill] = {
    CHECK_AVAILABILITY: Skill(CHECK_AVAILABILITY, (PENDING,), mutates=False),
    CREATE_RESERVATION: Skill(CREATE_RESERVATION, (PENDING,), mutates=True),
    CANCEL_RESERVATION: Skill(CANCEL_RESERVATION, (BOOKED,), mutates=True),
    QUERY_SCHEDULE: Skill(QUERY_SCHEDULE, (PENDING, BOOKED, REFUSED),
                          mutates=False),
    FIND_ALTERNATIVE: Skill(FIND_ALTERNATIVE, (BOOKED,), mutates=False),
    MOVE_RESERVATION: Skill(MOVE_RESERVATION, (BOOKED,), mutates=True),
    PROPOSE_DISPLACEMENT: Skill(PROPOSE_DISPLACEMENT, (BOOKED,),
                                mutates=False),
    EXECUTE_DISPLACEMENT: Skill(EXECUTE_DISPLACEMENT, (BOOKED,), mutates=True),
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
    if not world.is_open(request.facility_id, request.day, request.start,
                         request.end):
        reasons.append("outside opening hours")
    capacity = world.capacity_of(request.facility_id)
    if request.participants > capacity:
        reasons.append(f"capacity {capacity} < {request.participants}")
    missing = set(request.requires) - world.features_of(request.facility_id)
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
                       world: World, runtime=None) -> Result:
    blockers = _blockers(request, store, world)
    request.last_check = not blockers
    return Result(CHECK_AVAILABILITY, request.request_id, ok=not blockers,
                  detail="available" if not blockers else "; ".join(blockers))


def create_reservation(request: ReservationRequest, store: Store,
                       world: World, runtime=None) -> Result:
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
                       world: World, runtime=None) -> Result:
    reservation = store.reservations.get(request.reservation_id or "")
    if reservation is None or reservation.state != CONFIRMED:
        return Result(CANCEL_RESERVATION, request.request_id, ok=False,
                      detail="no confirmed reservation to cancel")
    reservation.state = CANCELLED
    request.state = REFUSED
    return Result(CANCEL_RESERVATION, request.request_id, ok=True,
                  detail=f"cancelled {reservation.reservation_id}")


def query_schedule(request: ReservationRequest, store: Store,
                   world: World, runtime=None) -> Result:
    """Read-only. Reports what is already booked in the facility on that day."""
    same_day = [r for r in store.schedule()
                if r.facility_id == request.facility_id
                and r.day == request.day]
    return Result(QUERY_SCHEDULE, request.request_id, ok=True,
                  detail=f"{len(same_day)} reservation(s) that day")


def _slot_free(facility_id: str, day: int, start: int, end: int,
               store: Store, ignoring: str) -> bool:
    return not any(
        r.facility_id == facility_id and r.day == day
        and r.start < end and start < r.end
        and r.reservation_id != ignoring
        for r in store.schedule())


def _move_checks(reservation, candidate, store: Store, world: World) -> str:
    """The physical reasons a move cannot happen. One definition, shared by
    the unprotected verb and the gated one - case 05's rule about a single
    derivation, so the two cannot drift and let a gated move do something the
    ungated one would refuse.
    """
    facility_id, day, start = candidate
    end = start + (reservation.end - reservation.start)

    if not world.is_open(facility_id, day, start, end):
        return "candidate is outside opening hours"
    if world.capacity_of(facility_id) < reservation.participants:
        return "candidate capacity too small"
    if not set(reservation.requires) <= world.features_of(facility_id):
        return "candidate lacks required features"
    if not _slot_free(facility_id, day, start, end, store,
                      reservation.reservation_id):
        return "candidate was taken since the search"
    return ""


def _apply_move(reservation, request) -> None:
    facility_id, day, start = request.candidate
    duration = reservation.end - reservation.start      # before start moves
    reservation.facility_id, reservation.day = facility_id, day
    reservation.start, reservation.end = start, start + duration
    request.candidate = None
    # The version moves with the reservation, so an approval naming the slot
    # it used to be in can never authorise a move from where it is now.
    request.version += 1


def find_alternative(request: ReservationRequest, store: Store,
                     world: World, runtime=None) -> Result:
    """The agent's own search. Greedy first fit, and deliberately so.

    It shares no code with `oracle.feasible`, which searches jointly with
    backtracking. If the two were the same routine, the false-escalation
    metric would be the agent grading its own homework.

    First fit is not a strawman - it is what a worker with no view of its
    neighbours' needs can do. Whether that is good enough is exactly what step
    C measures, and nothing here is tuned after seeing the answer.
    """
    reservation = store.reservations.get(request.reservation_id or "")
    if reservation is None:
        return Result(FIND_ALTERNATIVE, request.request_id, ok=False,
                      detail="no reservation to relocate")

    duration = reservation.end - reservation.start
    for facility_id in world.ids():
        if not set(reservation.requires) <= world.features_of(facility_id):
            continue
        if world.capacity_of(facility_id) < reservation.participants:
            continue
        for day in range(DAYS):
            window = world.window(facility_id, day)
            if window is None:
                continue
            opens, closes = window
            for start in range(opens, closes - duration + 1, SLOT_MINUTES):
                if _slot_free(facility_id, day, start, start + duration,
                              store, reservation.reservation_id):
                    request.candidate = (facility_id, day, start)
                    return Result(FIND_ALTERNATIVE, request.request_id,
                                  ok=True,
                                  detail=f"{facility_id} d{day} {start}")

    request.candidate = None
    request.state = UNRESOLVED
    return Result(FIND_ALTERNATIVE, request.request_id, ok=False,
                  detail="no candidate slot found")


def move_reservation(request: ReservationRequest, store: Store,
                     world: World, runtime=None) -> Result:
    """Re-derives the candidate's validity rather than trusting it.

    `candidate` is advisory in exactly the way `last_check` is. The world may
    have moved between the search and the move - another worker may have taken
    the slot - and a queue that could force a stale move would be
    authoritative about the outcome.
    """
    if request.candidate is None:
        return Result(MOVE_RESERVATION, request.request_id, ok=False,
                      detail="no candidate to move to")
    reservation = store.reservations.get(request.reservation_id or "")
    if reservation is None:
        return Result(MOVE_RESERVATION, request.request_id, ok=False,
                      detail="no reservation to move")

    physical = _move_checks(reservation, request.candidate, store, world)
    if physical:
        return Result(MOVE_RESERVATION, request.request_id, ok=False,
                      detail=physical)

    facility_id, day, start = request.candidate
    _apply_move(reservation, request)
    return Result(MOVE_RESERVATION, request.request_id, ok=True,
                  detail=f"moved to {facility_id} d{day} {start}")


def propose_displacement(request: ReservationRequest, store: Store,
                         world: World, runtime=None) -> Result:
    """The worker's half. It writes an attestation and moves nothing."""
    from demo_reservation.signoff import WORKER, displacement_for

    if runtime is None or runtime.signoff is None:
        return Result(PROPOSE_DISPLACEMENT, request.request_id, ok=False,
                      detail="no sign-off store configured")
    if request.candidate is None:
        return Result(PROPOSE_DISPLACEMENT, request.request_id, ok=False,
                      detail="no candidate to propose")
    reservation = store.reservations.get(request.reservation_id or "")
    if reservation is None:
        return Result(PROPOSE_DISPLACEMENT, request.request_id, ok=False,
                      detail="no reservation to displace")

    action = displacement_for(reservation, request.candidate, request.version)
    runtime.signoff.propose(WORKER, action)
    return Result(PROPOSE_DISPLACEMENT, request.request_id, ok=True,
                  detail=f"proposed {action.describe()}")


def execute_displacement(request: ReservationRequest, store: Store,
                         world: World, runtime=None) -> Result:
    """The gate. It re-derives the action it is about to perform and requires
    a proposal and an unspent approval for *that* action.

    The physical re-checks from `move_reservation` still apply: an approved
    displacement into a slot somebody has since taken is refused, because an
    approval authorises an action and cannot conjure a free room.
    """
    from demo_reservation.signoff import SignoffRefused, displacement_for

    if runtime is None or runtime.signoff is None:
        return Result(EXECUTE_DISPLACEMENT, request.request_id, ok=False,
                      detail="no sign-off store configured")
    if request.candidate is None:
        return Result(EXECUTE_DISPLACEMENT, request.request_id, ok=False,
                      detail="no candidate to move to")
    reservation = store.reservations.get(request.reservation_id or "")
    if reservation is None:
        return Result(EXECUTE_DISPLACEMENT, request.request_id, ok=False,
                      detail="no reservation to move")

    action = displacement_for(reservation, request.candidate, request.version)
    try:
        runtime.signoff.verify_and_spend(action)
    except SignoffRefused as exc:
        return Result(EXECUTE_DISPLACEMENT, request.request_id, ok=False,
                      detail=f"REFUSED: {exc}")

    physical = _move_checks(reservation, request.candidate, store, world)
    if physical:
        return Result(EXECUTE_DISPLACEMENT, request.request_id, ok=False,
                      detail=physical)

    _apply_move(reservation, request)
    return Result(EXECUTE_DISPLACEMENT, request.request_id, ok=True,
                  detail=f"displaced to {action.to_slot}")


HANDLERS: Dict[str, Callable[..., Result]] = {
    CHECK_AVAILABILITY: check_availability,
    CREATE_RESERVATION: create_reservation,
    CANCEL_RESERVATION: cancel_reservation,
    QUERY_SCHEDULE: query_schedule,
    FIND_ALTERNATIVE: find_alternative,
    MOVE_RESERVATION: move_reservation,
    PROPOSE_DISPLACEMENT: propose_displacement,
    EXECUTE_DISPLACEMENT: execute_displacement,
}
