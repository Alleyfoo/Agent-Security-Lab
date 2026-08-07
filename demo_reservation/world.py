"""The world: facilities, opening hours, and a one-month time grid.

Deliberately small enough to check by hand. Every measurement this demo
eventually produces has to be verifiable against a schedule a person can read,
which is a requirement rather than a convenience.

Nothing here knows about agents, skills, queues or reservations. It is the
physical world the reservations are *about*, and keeping it ignorant of them is
what lets `invariants.py` inspect a schedule without going through the same
code that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple

DAYS = 28                       # four clean weeks; day 0 is a Monday
SLOT_MINUTES = 30               # the grid everything snaps to


def weekday(day: int) -> int:
    """0 = Monday ... 6 = Sunday."""
    return day % 7


def hhmm(minutes: int) -> str:
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


@dataclass(frozen=True)
class OpeningHours:
    """Per weekday, in minutes from midnight. A weekday absent from the map is
    closed all day, which is how a facility says "no Sundays"."""

    by_weekday: Dict[int, Tuple[int, int]]

    def window(self, day: int) -> Optional[Tuple[int, int]]:
        return self.by_weekday.get(weekday(day))

    def is_open(self, day: int, start: int, end: int) -> bool:
        window = self.window(day)
        if window is None:
            return False
        opens, closes = window
        return opens <= start and end <= closes


@dataclass(frozen=True)
class Facility:
    facility_id: str
    name: str
    capacity: int
    features: FrozenSet[str]
    hours: OpeningHours

    def describe(self) -> str:
        return f"{self.name} (cap {self.capacity}, {sorted(self.features)})"


@dataclass
class World:
    """The set of facilities. Mutable only because later steps (B) will damage
    it; nothing in step A changes it after construction."""

    facilities: Dict[str, Facility] = field(default_factory=dict)

    def get(self, facility_id: str) -> Optional[Facility]:
        return self.facilities.get(facility_id)

    def ids(self) -> List[str]:
        return sorted(self.facilities)


def _hours(spec: Dict[int, Tuple[int, int]]) -> OpeningHours:
    return OpeningHours(by_weekday=dict(spec))


WEEKDAY_EVENING = {d: (8 * 60, 22 * 60) for d in range(5)}
WEEKEND_SHORT = {5: (9 * 60, 18 * 60), 6: (10 * 60, 16 * 60)}


def default_world() -> World:
    """Three halls with genuinely different constraints, so a request can fail
    for four distinguishable reasons rather than only one."""
    return World(facilities={
        "hall_a": Facility(
            "hall_a", "Hall A", capacity=40,
            features=frozenset({"ring", "mats", "showers"}),
            hours=_hours({**WEEKDAY_EVENING, **WEEKEND_SHORT})),
        "hall_b": Facility(
            "hall_b", "Hall B", capacity=60,
            features=frozenset({"hoops", "mats", "showers"}),
            hours=_hours({**WEEKDAY_EVENING, **WEEKEND_SHORT})),
        "studio_c": Facility(
            "studio_c", "Studio C", capacity=15,
            features=frozenset({"mirrors", "mats"}),
            # Weekdays only, and it shuts earlier.
            hours=_hours({d: (9 * 60, 20 * 60) for d in range(5)})),
    })
