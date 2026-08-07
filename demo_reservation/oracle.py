"""The independent oracle: was a complete recovery possible?

**Evaluator only.** Nothing an agent can reach imports this module, and a test
enforces it. An agent that could read the witness would be measuring the oracle
rather than itself.

It shares no code with the agents' `find_alternative`. If the agents' own
search decided whether an alternative existed, the escalation metrics would be
self-graded - case 24's finding in another costume.

Jointly, not one at a time
--------------------------

Per-reservation answers are wrong in both directions. Two damaged bookings can
each have "a" slot and not have two; and a greedy agent can take the only slot
its neighbour could use while a complete assignment existed. So this searches
for an assignment of *the whole damaged set at once* and reports a witness.

Three-valued on purpose
-----------------------

Joint feasibility is a constraint problem with no guaranteed budget, so the
answer is `yes` / `no` / `unknown` and `unknown` is counted rather than rounded
to whichever side flatters the result.

* a `yes` carries a witness, and the witness is validated by the same
  independent invariant checker the schedule is - the oracle's positive claims
  are verified, not believed;
* a `no` is sound only if the search completed inside its budget; otherwise
  the answer is `unknown`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from demo_reservation.invariants import check
from demo_reservation.objects import Reservation
from demo_reservation.world import DAYS, SLOT_MINUTES, World

YES, NO, UNKNOWN = "yes", "no", "unknown"

# Nodes the backtracking search may expand before giving up and saying so.
DEFAULT_BUDGET = 200_000


@dataclass
class Verdict:
    answer: str
    witness: Optional[Dict[str, Tuple[str, int, int]]] = None
    nodes: int = 0
    note: str = ""

    @property
    def possible(self) -> bool:
        return self.answer == YES


@dataclass
class Outcome:
    """The three-way verdict on one unresolved reservation set."""

    initial: Verdict
    current: Verdict
    genuinely_impossible: List[str] = field(default_factory=list)
    false_escalations: List[str] = field(default_factory=list)
    dead_ends: List[str] = field(default_factory=list)
    undecided: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Candidate slots. Computed here, from the world, and never shared.
# ---------------------------------------------------------------------------

def _candidates(r: Reservation, world: World,
                fixed: List[Reservation]) -> List[Tuple[str, int, int]]:
    duration = r.end - r.start
    out: List[Tuple[str, int, int]] = []
    for facility_id in world.ids():
        if not set(r.requires) <= world.features_of(facility_id):
            continue
        if world.capacity_of(facility_id) < r.participants:
            continue
        for day in range(DAYS):
            window = world.window(facility_id, day)
            if window is None:
                continue
            opens, closes = window
            for start in range(opens, closes - duration + 1, SLOT_MINUTES):
                end = start + duration
                if any(f.facility_id == facility_id and f.day == day
                       and f.start < end and start < f.end for f in fixed):
                    continue
                out.append((facility_id, day, start))
    return out


def _conflicts(a: Tuple[str, int, int], dur_a: int,
               b: Tuple[str, int, int], dur_b: int) -> bool:
    if a[0] != b[0] or a[1] != b[1]:
        return False
    return a[2] < b[2] + dur_b and b[2] < a[2] + dur_a


def feasible(to_place: List[Reservation], fixed: List[Reservation],
             world: World, budget: int = DEFAULT_BUDGET) -> Verdict:
    """Can every reservation in `to_place` be given a slot at once?

    Most-constrained-first with backtracking. A `yes` returns the assignment;
    a `no` means the search space was exhausted; running out of budget returns
    `unknown` rather than guessing.
    """
    if not to_place:
        return Verdict(YES, witness={}, note="nothing to place")

    options = {r.reservation_id: _candidates(r, world, fixed)
               for r in to_place}
    if any(not opts for opts in options.values()):
        empty = [rid for rid, opts in options.items() if not opts]
        return Verdict(NO, nodes=0,
                       note=f"{len(empty)} reservation(s) have no slot at all")

    order = sorted(to_place, key=lambda r: len(options[r.reservation_id]))
    durations = {r.reservation_id: r.end - r.start for r in to_place}
    assignment: Dict[str, Tuple[str, int, int]] = {}
    nodes = [0]

    def place(index: int) -> bool:
        if index == len(order):
            return True
        r = order[index]
        for candidate in options[r.reservation_id]:
            nodes[0] += 1
            if nodes[0] > budget:
                return False
            clash = any(
                _conflicts(candidate, durations[r.reservation_id],
                           chosen, durations[rid])
                for rid, chosen in assignment.items())
            if clash:
                continue
            assignment[r.reservation_id] = candidate
            if place(index + 1):
                return True
            del assignment[r.reservation_id]
        return False

    solved = place(0)
    if solved:
        return Verdict(YES, witness=dict(assignment), nodes=nodes[0])
    if nodes[0] > budget:
        return Verdict(UNKNOWN, nodes=nodes[0],
                       note=f"search budget {budget} exhausted")
    return Verdict(NO, nodes=nodes[0], note="search space exhausted")


def verify_witness(verdict: Verdict, to_place: List[Reservation],
                   fixed: List[Reservation], world: World) -> bool:
    """The oracle is not trusted either.

    A positive answer is rebuilt into a schedule and handed to the same
    independent invariant checker the real schedule goes through. If the
    witness does not validate, the oracle is wrong and its `yes` is worthless.
    """
    if verdict.answer != YES or verdict.witness is None:
        return False
    placed = []
    for r in to_place:
        facility_id, day, start = verdict.witness[r.reservation_id]
        placed.append(Reservation(
            reservation_id=r.reservation_id, request_id=r.request_id,
            facility_id=facility_id, day=day, start=start,
            end=start + (r.end - r.start), activity=r.activity,
            participants=r.participants, requires=r.requires))
    return check(fixed + placed, world).ok


# ---------------------------------------------------------------------------
# The three-way verdict.
# ---------------------------------------------------------------------------

def classify(damaged: List[Reservation], survivors_at_start: List[Reservation],
             unresolved: List[Reservation], survivors_now: List[Reservation],
             world: World, budget: int = DEFAULT_BUDGET) -> Outcome:
    """Was the escalation justified, false, or a dead end the agent dug?

        initial x  -> genuinely impossible
        initial v, current v -> false escalation
        initial v, current x -> self-created dead end
    """
    initial = feasible(damaged, survivors_at_start, world, budget)
    current = feasible(unresolved, survivors_now, world, budget)

    outcome = Outcome(initial=initial, current=current)
    ids = [r.reservation_id for r in unresolved]

    if initial.answer == UNKNOWN or current.answer == UNKNOWN:
        outcome.undecided = ids
    elif initial.answer == NO:
        outcome.genuinely_impossible = ids
    elif current.answer == YES:
        outcome.false_escalations = ids
    else:
        outcome.dead_ends = ids
    return outcome
