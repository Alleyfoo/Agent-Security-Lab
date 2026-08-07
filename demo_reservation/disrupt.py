"""Step B: damage a valid world, identify the blast radius, and stop.

    INPUT      a valid world and a valid booked schedule
    OUTPUT     the changed world, the affected reservation ids, and an
               independent invariant result
    STOP       no recovery, no alternative search, no escalation, no sign-off

**This module is written before step C exists**, and that is the whole point.
Case 17 measured a beautiful reduction that turned out to be a generator
parameter; a disruption set chosen because the agents cope with it would
measure the author. So the vocabulary is fixed here, now, in ignorance of how
anything will resolve it.

What this module may and may not know
-------------------------------------

**May:** which reservations it damages. Identifying affected objects is step
B's job.

**May not:** whether those reservations are *recoverable*. Nothing here looks
for a free slot, counts alternatives, measures conflict complexity, or prefers
a closure that leaves an escape route. A test asserts the module never consults
the schedule for availability.

One conditioning rule is permitted and used: a disruption is re-drawn until it
affects at least one existing reservation. That guarantees the experiment
contains a disturbance; it does not grade step C, because *number affected* is
not *number solvable*.

One honest exception to "world facts only": `priority_block_inserted` writes a
reservation rather than a world fact. It is in the vocabulary because a
priority booking is a real disruption, and it is called out here rather than
quietly filed with the others.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from demo_reservation.objects import Reservation, Store
from demo_reservation.world import DAYS, SLOT_MINUTES, World, hhmm, weekday

FACILITY_CLOSED = "facility_closed"
OPENING_HOURS_REDUCED = "opening_hours_reduced"
CAPACITY_REDUCED = "capacity_reduced"
FEATURE_UNAVAILABLE = "feature_unavailable"
PRIORITY_BLOCK_INSERTED = "priority_block_inserted"

VOCABULARY = (FACILITY_CLOSED, OPENING_HOURS_REDUCED, CAPACITY_REDUCED,
              FEATURE_UNAVAILABLE, PRIORITY_BLOCK_INSERTED)


@dataclass
class Disruption:
    kind: str
    facility_id: str
    params: Dict[str, object] = field(default_factory=dict)
    # Pre-existing reservations this disruption damaged.
    affected: Tuple[str, ...] = ()
    # Reservations the disruption itself added. Only the priority block has
    # any, and they are declared separately so the cross-check compares like
    # with like: the checker sees the block violating too, and it is right to
    # - it is the cause, not a casualty.
    introduced: Tuple[str, ...] = ()

    def describe(self) -> str:
        p = self.params
        if self.kind == FACILITY_CLOSED:
            return (f"{self.facility_id} closed, days "
                    f"{p['day_from']}-{p['day_to']}")
        if self.kind == OPENING_HOURS_REDUCED:
            opens, closes = p["window"]
            return (f"{self.facility_id} weekday {p['weekday']} now "
                    f"{hhmm(opens)}-{hhmm(closes)}")
        if self.kind == CAPACITY_REDUCED:
            return f"{self.facility_id} capacity now {p['capacity']}"
        if self.kind == FEATURE_UNAVAILABLE:
            return f"{self.facility_id} lost {p['feature']!r}"
        if self.kind == PRIORITY_BLOCK_INSERTED:
            return (f"priority block in {self.facility_id} day {p['day']} "
                    f"{hhmm(p['start'])}-{hhmm(p['end'])}")
        return self.kind


# ---------------------------------------------------------------------------
# Appliers. Each writes the change and returns the reservations it damaged.
# ---------------------------------------------------------------------------

def _apply_facility_closed(d: Disruption, world: World,
                           store: Store) -> Set[str]:
    days = set(range(int(d.params["day_from"]), int(d.params["day_to"]) + 1))
    world.closed_days.setdefault(d.facility_id, set()).update(days)
    return {r.reservation_id for r in store.schedule()
            if r.facility_id == d.facility_id and r.day in days}


def _apply_hours_reduced(d: Disruption, world: World,
                         store: Store) -> Set[str]:
    wd = int(d.params["weekday"])
    opens, closes = d.params["window"]
    world.hours_override[(d.facility_id, wd)] = (opens, closes)
    return {r.reservation_id for r in store.schedule()
            if r.facility_id == d.facility_id and weekday(r.day) == wd
            and not (opens <= r.start and r.end <= closes)}


def _apply_capacity_reduced(d: Disruption, world: World,
                            store: Store) -> Set[str]:
    capacity = int(d.params["capacity"])
    world.capacity_override[d.facility_id] = capacity
    return {r.reservation_id for r in store.schedule()
            if r.facility_id == d.facility_id and r.participants > capacity}


def _apply_feature_unavailable(d: Disruption, world: World,
                               store: Store) -> Set[str]:
    feature = str(d.params["feature"])
    world.features_removed.setdefault(d.facility_id, set()).add(feature)
    return {r.reservation_id for r in store.schedule()
            if r.facility_id == d.facility_id and feature in r.requires}


def _apply_priority_block(d: Disruption, world: World,
                          store: Store) -> Set[str]:
    day = int(d.params["day"])
    start, end = int(d.params["start"]), int(d.params["end"])
    block = Reservation(
        reservation_id=str(d.params["block_id"]), request_id="priority",
        facility_id=d.facility_id, day=day, start=start, end=end,
        activity="priority", participants=1, requires=frozenset())
    store.reservations[block.reservation_id] = block
    return {r.reservation_id for r in store.schedule()
            if r.reservation_id != block.reservation_id
            and r.facility_id == d.facility_id and r.day == day
            and r.start < end and start < r.end}


APPLIERS = {
    FACILITY_CLOSED: _apply_facility_closed,
    OPENING_HOURS_REDUCED: _apply_hours_reduced,
    CAPACITY_REDUCED: _apply_capacity_reduced,
    FEATURE_UNAVAILABLE: _apply_feature_unavailable,
    PRIORITY_BLOCK_INSERTED: _apply_priority_block,
}


def apply(d: Disruption, world: World, store: Store) -> Disruption:
    before = set(store.reservations)
    d.affected = tuple(sorted(APPLIERS[d.kind](d, world, store)))
    d.introduced = tuple(sorted(set(store.reservations) - before))
    return d


def claimed_damage(d: Disruption) -> Set[str]:
    """What the generator says the checker should find in violation.

    Everything it damaged, plus anything it added - because a block that
    overlaps two bookings makes three reservations invalid, not two.
    """
    return set(d.affected) | set(d.introduced)


# ---------------------------------------------------------------------------
# Drawing a disruption. Blind to solvability.
# ---------------------------------------------------------------------------

def _candidate(rng: random.Random, kind: str, world: World,
               seq: int) -> Optional[Disruption]:
    facility_id = rng.choice(world.ids())
    facility = world.get(facility_id)

    if kind == FACILITY_CLOSED:
        day_from = rng.randrange(DAYS - 5)
        return Disruption(kind, facility_id, {
            "day_from": day_from, "day_to": day_from + rng.randint(1, 4)})

    if kind == OPENING_HOURS_REDUCED:
        wd = rng.randrange(7)
        window = facility.hours.window(wd)
        if window is None:
            return None
        opens, closes = window
        if closes - opens < 4 * 60:
            return None
        return Disruption(kind, facility_id, {
            "weekday": wd, "window": (opens, closes - rng.choice([120, 180]))})

    if kind == CAPACITY_REDUCED:
        return Disruption(kind, facility_id, {
            "capacity": max(1, int(facility.capacity * rng.choice([0.3, 0.5])))})

    if kind == FEATURE_UNAVAILABLE:
        if not facility.features:
            return None
        return Disruption(kind, facility_id, {
            "feature": rng.choice(sorted(facility.features))})

    if kind == PRIORITY_BLOCK_INSERTED:
        day = rng.randrange(DAYS)
        window = facility.hours.window(day)
        if window is None:
            return None
        opens, closes = window
        latest = closes - 120
        if latest < opens:
            return None
        start = rng.randrange(opens, latest + 1, SLOT_MINUTES)
        return Disruption(kind, facility_id, {
            "day": day, "start": start, "end": start + 120,
            "block_id": f"res_priority_{seq}"})

    return None


def draw(world: World, store: Store, kind: Optional[str] = None,
         seed: int = 5150, attempts: int = 400) -> Optional[Disruption]:
    """Draw one disruption that damages at least one existing reservation.

    The retry condition is `affected > 0` and nothing else. It guarantees the
    experiment contains a disturbance. It does **not** look at how many
    alternatives exist, how tangled the resulting conflicts are, or whether
    anything downstream could fix it - those would grade step C before step C
    is written.
    """
    rng = random.Random(seed)
    for seq in range(attempts):
        chosen = kind or rng.choice(VOCABULARY)
        candidate = _candidate(rng, chosen, world, seq)
        if candidate is None:
            continue
        # Try it on a throwaway pair so a miss leaves nothing behind.
        trial_world = _clone_world(world)
        trial_store = _clone_store(store)
        affected = APPLIERS[chosen](candidate, trial_world, trial_store)
        if affected:
            return apply(candidate, world, store)
    return None


def _clone_world(world: World) -> World:
    return World(
        facilities=dict(world.facilities),
        closed_days={k: set(v) for k, v in world.closed_days.items()},
        hours_override=dict(world.hours_override),
        capacity_override=dict(world.capacity_override),
        features_removed={k: set(v) for k, v in world.features_removed.items()},
    )


def _clone_store(store: Store) -> Store:
    clone = Store()
    clone.requests = dict(store.requests)
    clone.reservations = {k: Reservation(**vars(v))
                          for k, v in store.reservations.items()}
    return clone
