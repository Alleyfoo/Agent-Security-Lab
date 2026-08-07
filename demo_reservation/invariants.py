"""The independent schedule-invariant checker.

**This module must not import the skills or the runtime, and a test asserts
it.** It inspects a finished schedule and the world, and answers boring facts.
If it went through the same code that produced the schedule it would confirm
that the producer agrees with itself, which is worth nothing - the failure case
24 measured in another guise, and the reason step C's oracle has the same rule.

Six invariants, each reported separately so a violation names itself rather
than collapsing into "invalid":

    no overlapping reservations for the same facility
    reservation inside opening hours
    capacity >= participants
    required features satisfied
    reservation references an existing facility
    start < end
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from demo_reservation.objects import Reservation
from demo_reservation.world import DAYS, SLOT_MINUTES, World, hhmm


@dataclass
class Violation:
    invariant: str
    reservation_id: str
    detail: str


@dataclass
class Report:
    violations: List[Violation] = field(default_factory=list)
    checked: int = 0

    @property
    def ok(self) -> bool:
        return not self.violations

    def by_invariant(self) -> dict:
        out: dict = {}
        for v in self.violations:
            out.setdefault(v.invariant, []).append(v)
        return out

    def summary(self) -> str:
        if self.ok:
            return f"PASS ({self.checked} reservations)"
        kinds = ", ".join(f"{k} x{len(v)}"
                          for k, v in sorted(self.by_invariant().items()))
        return f"FAIL ({len(self.violations)} violations: {kinds})"


def check(schedule: List[Reservation], world: World) -> Report:
    report = Report(checked=len(schedule))

    def fail(invariant: str, r: Reservation, detail: str) -> None:
        report.violations.append(Violation(invariant, r.reservation_id, detail))

    for r in schedule:
        # -- start < end, and on the grid ---------------------------------
        if r.start >= r.end:
            fail("start_before_end", r, f"{r.start} >= {r.end}")
        if r.start % SLOT_MINUTES or r.end % SLOT_MINUTES:
            fail("on_the_grid", r,
                 f"{hhmm(r.start)}-{hhmm(r.end)} is not on a "
                 f"{SLOT_MINUTES}-minute boundary")
        if not 0 <= r.day < DAYS:
            fail("day_in_range", r, f"day {r.day} outside 0..{DAYS - 1}")

        # -- the facility exists ------------------------------------------
        facility = world.get(r.facility_id)
        if facility is None:
            fail("facility_exists", r, f"no facility {r.facility_id!r}")
            continue

        # -- opening hours -------------------------------------------------
        if not facility.hours.is_open(r.day, r.start, r.end):
            window = facility.hours.window(r.day)
            fail("inside_opening_hours", r,
                 f"{hhmm(r.start)}-{hhmm(r.end)} on day {r.day}, "
                 + (f"open {hhmm(window[0])}-{hhmm(window[1])}"
                    if window else "closed that day"))

        # -- capacity ------------------------------------------------------
        if r.participants > facility.capacity:
            fail("capacity_sufficient", r,
                 f"{r.participants} people, capacity {facility.capacity}")

        # -- features ------------------------------------------------------
        missing = set(r.requires) - set(facility.features)
        if missing:
            fail("features_satisfied", r,
                 f"{facility.facility_id} lacks {sorted(missing)}")

    # -- no double booking -------------------------------------------------
    ordered = sorted(schedule, key=lambda r: (r.facility_id, r.day, r.start))
    for a, b in zip(ordered, ordered[1:]):
        if a.overlaps(b):
            fail("no_overlap", b,
                 f"overlaps {a.reservation_id} in {a.facility_id} day {a.day} "
                 f"({hhmm(a.start)}-{hhmm(a.end)} vs "
                 f"{hhmm(b.start)}-{hhmm(b.end)})")

    return report


INVARIANTS = (
    "start_before_end", "on_the_grid", "day_in_range", "facility_exists",
    "inside_opening_hours", "capacity_sufficient", "features_satisfied",
    "no_overlap",
)
