"""The request queue: valid structured requests, deterministically generated.

Every request is well-formed - a real facility, a slot on the grid, a sensible
duration. Some of them will not be bookable, and that is the point: the world
fills up, two requests want the same evening, a studio is too small for a
twenty-person class. The runtime must refuse those cleanly rather than solve
them.

**No request is generated to be unbookable.** The refusals emerge from the
world's own constraints and from contention, which keeps step A's numbers a
property of the world rather than of the generator. Step B's disruption
generator has the same rule for a stronger reason and states it more loudly.
"""

from __future__ import annotations

import random
from typing import FrozenSet, List, Tuple

from demo_reservation.objects import ReservationRequest
from demo_reservation.world import DAYS, SLOT_MINUTES, World, default_world

# Activities with the features they genuinely need and a plausible size.
ACTIVITIES: Tuple[Tuple[str, FrozenSet[str], int, int], ...] = (
    ("boxing", frozenset({"ring", "mats"}), 8, 24),
    ("basketball", frozenset({"hoops"}), 10, 30),
    ("yoga", frozenset({"mirrors", "mats"}), 6, 14),
    ("circuit", frozenset({"mats"}), 8, 25),
    ("dance", frozenset({"mirrors"}), 6, 14),
)

DURATIONS = (60, 90, 120)


def generate_requests(n: int, world: World = None,
                      seed: int = 20260807) -> List[ReservationRequest]:
    world = world or default_world()
    rng = random.Random(seed)
    facility_ids = world.ids()
    requests: List[ReservationRequest] = []

    for i in range(n):
        activity, requires, low, high = ACTIVITIES[i % len(ACTIVITIES)]
        participants = rng.randint(low, high)
        duration = rng.choice(DURATIONS)

        # Requests are *physically plausible*: a facility that can host this
        # activity, at a time it is open. Asking for boxing in a hall with no
        # ring is not a realistic request, it is noise - and an early version
        # of this generator produced 342 such refusals, drowning the 98 that
        # came from contention, which is the signal steps B and C need.
        #
        # This is emphatically NOT the same as aiming requests at free slots.
        # Nothing here consults the schedule. Every refusal that follows comes
        # from two requests wanting the same room at the same time.
        candidates = [
            f for f in (world.get(fid) for fid in facility_ids)
            if requires <= f.features and f.capacity >= participants
        ]
        if not candidates:
            continue
        facility = rng.choice(candidates)

        open_days = [d for d in range(DAYS)
                     if facility.hours.window(d) is not None]
        if not open_days:
            continue
        day = rng.choice(open_days)
        opens, closes = facility.hours.window(day)

        latest = closes - duration
        if latest < opens:
            continue
        # Evenings are popular, which is what creates contention.
        slots = [t for t in range(opens, latest + 1, SLOT_MINUTES)]
        evening = [t for t in slots if t >= 17 * 60]
        start = rng.choice(evening * 3 + slots) if evening else rng.choice(slots)

        requests.append(ReservationRequest(
            request_id=f"req_{i:05d}",
            facility_id=facility.facility_id,
            day=day,
            start=start,
            end=start + duration,
            activity=activity,
            participants=participants,
            requires=requires,
        ))

    _assert_well_formed(requests)
    return requests


def _assert_well_formed(requests: List[ReservationRequest]) -> None:
    """Requests are structurally valid on arrival. There is no parsing step in
    this demo and nothing downstream may assume it has to clean them up."""
    for r in requests:
        assert r.start < r.end
        assert r.start % SLOT_MINUTES == 0 and r.end % SLOT_MINUTES == 0
        assert 0 <= r.day < DAYS
        assert r.participants > 0
