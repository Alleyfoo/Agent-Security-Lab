"""Step A of the reservation-queue demo: the boring foundation.

Contract: `docs/demo-reservation-queue.md`. Step A freezes four things and
nothing else:

    world.py       facilities, opening hours, a one-month grid
    objects.py     the request, the reservation, the queue item, the receipt
    skills.py      the bounded skill set - this IS the authority boundary
    runtime.py     validate the skill against object state, execute, receipt

plus `invariants.py`, which checks a finished schedule **independently** and
imports none of the above machinery.

Deliberately absent, and it must stay that way until the contract says
otherwise: `find_alternative`, disruption, recovery, escalation, exceptions,
sign-off, healing. A refusal here is a defined outcome, not a problem to solve.

`object_model` is not imported. Cases 10 and 11 published tables against its
registry and workflow table; the idioms are shared, the code is not.
"""

from __future__ import annotations

from demo_reservation.generate import generate_requests
from demo_reservation.invariants import check
from demo_reservation.objects import (
    QueueItem, Receipt, Reservation, ReservationRequest, Result, Store,
)
from demo_reservation.runtime import Runtime, straight_through
from demo_reservation.world import World, default_world

__all__ = [
    "generate_requests", "check",
    "QueueItem", "Receipt", "Reservation", "ReservationRequest", "Result",
    "Store", "Runtime", "straight_through", "World", "default_world",
]
