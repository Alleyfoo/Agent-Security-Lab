"""The queue runtime: validate the skill against the object's state, execute,
record a receipt.

The three jobs, and the middle one is the architectural claim:

    take (object_ref, skill_ref)
    validate the skill against the object's CURRENT state, not the queue's
        opinion of it
    execute, and record a runner-owned receipt

A queue item that names a skill the object's state does not permit is
**refused and counted**. In a clean run that counter is zero; a test asks for
an impossible transition and checks that it is refused rather than performed.

Step A stops here. There is no exception object, no escalation, no retry and
no alternative search - a refusal is a defined outcome, not a problem to solve.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from demo_reservation.objects import (
    QueueItem, Receipt, ReservationRequest, Result, Store,
)
from demo_reservation.skills import HANDLERS, REGISTRY
from demo_reservation.world import World


class UnknownSkill(RuntimeError):
    """No approved skill by that name. Absent, not denied."""


class UnknownObject(RuntimeError):
    """The queue refers to an object that does not exist."""


@dataclass
class Runtime:
    store: Store
    world: World
    receipts: List[Receipt] = field(default_factory=list)
    refused_transitions: int = 0
    skill_calls: Dict[str, int] = field(default_factory=dict)
    # Step D: which skills this worker holds. `None` means the whole registry,
    # which is what steps A to C ran with and why their numbers are unchanged.
    # Narrowing it is how a protected transformation is actually removed from
    # a worker's authority rather than merely discouraged.
    worker_skills: Optional[Set[str]] = None
    # Step D: the sign-off store, when the worker's authority is narrowed.
    signoff: Optional[object] = None

    # -- the one entry point ------------------------------------------------
    def run(self, item: QueueItem) -> Optional[Result]:
        skill = REGISTRY.get(item.skill)
        if skill is None:
            raise UnknownSkill(f"no approved skill named {item.skill!r}")

        if self.worker_skills is not None and item.skill not in self.worker_skills:
            self.refused_transitions += 1
            self._receipt(item, ok=False, refused=True, detail=(
                f"{item.skill!r} is not in this worker's skill set"))
            return None

        request = self.store.requests.get(item.object_id)
        if request is None:
            raise UnknownObject(f"no object {item.object_id!r}")

        # The claim: permission comes from the object, not from the item.
        if request.state not in skill.permitted_states:
            self.refused_transitions += 1
            self._receipt(item, ok=False, refused=True, detail=(
                f"{item.skill!r} is not permitted for an object in state "
                f"{request.state!r}"))
            return None

        result = HANDLERS[item.skill](request, self.store, self.world,
                                      self)
        self.skill_calls[item.skill] = self.skill_calls.get(item.skill, 0) + 1
        self._receipt(item, ok=result.ok, refused=False, detail=result.detail)
        return result

    def run_all(self, queue: List[QueueItem]) -> List[Optional[Result]]:
        return [self.run(item) for item in queue]

    # -- runner-owned record ------------------------------------------------
    def _receipt(self, item: QueueItem, ok: bool, refused: bool,
                 detail: str) -> None:
        self.receipts.append(Receipt(
            seq=len(self.receipts), object_id=item.object_id,
            skill=item.skill, ok=ok, detail=detail,
            refused_transition=refused))

    # -- measurement --------------------------------------------------------
    def summary(self) -> Dict[str, object]:
        counts = self.store.counts()
        return {
            "requests": len(self.store.requests),
            "booked": counts.get("booked", 0),
            "refused": counts.get("refused", 0),
            "pending": counts.get("pending", 0),
            "skill_calls": dict(sorted(self.skill_calls.items())),
            "total_skill_calls": sum(self.skill_calls.values()),
            "refused_transitions": self.refused_transitions,
            "receipts": len(self.receipts),
        }


def straight_through(requests: List[ReservationRequest]) -> List[QueueItem]:
    """The step-A workflow, and it is deliberately witless.

    Every request gets a check and then an attempt. The check's answer is not
    consulted before the attempt - deciding *not* to try would be the first
    piece of cleverness, and cleverness belongs to step C.
    """
    queue: List[QueueItem] = []
    for request in requests:
        queue.append(QueueItem(request.request_id, "check_availability"))
        queue.append(QueueItem(request.request_id, "create_reservation"))
    return queue
