"""Step F: bounded recovery. Repair without general authority.

The claim, deliberately narrow again:

    Can a detected communication fault be recovered using **only explicitly
    granted recovery functions**, without giving the monitor general
    administrative authority?

The monitor does not gain a single verb. Step E's `monitor.py` is untouched by
this step - `git diff` says so. The shape is the one the rest of the repo has
been building toward:

    monitor            observes, and emits a communication_fault OBJECT
      |
    fault ledger       gives the observation an identity: fault_0007
      |
    recovery worker    receives the object. Holds no transport.
      |
    recovery runtime   derives the target FROM the object, checks the grant
      |
    bounded skill      retry / reroute / escalate
      |
    communication resumes, or the fault escalates

Observation creates an object; an authorised function acts on it. The recovery
worker never names a destination, never names an exchange, and never touches
the transport directly - it says `retry_exchange("fault_0007")` and the runtime
works out what that means.

The vocabulary, and nothing else
--------------------------------

    retry_exchange(fault_id)                 try the same work again
    reroute_exchange(fault_id)               try it via the REGISTERED backup
    escalate_communication_fault(fault_id)   bounded recovery is exhausted

Three verbs. That is the entire authority this step adds, and `RECOVERY_SKILLS`
is pinned by a test so the diff stays visible: anything a later step wants must
be added explicitly rather than acquired by being useful.

Note what is absent. There is no `restart_worker`, no `reroute_all`, no
`clear_faults`, no `mark_healthy`. The transport has `restart_all()` and it
genuinely works - it is the cheapest possible 100% recovery rate - and the
runtime refuses it because it is not in the vocabulary. This follows the
absence rule the Level 2 preventions in `cases/registry.py` all share: against
an adversary sharing the boundary, remove the thing rather than guard it.

Scope
-----

    Recovery may change only the failed communication path, or the work item
    associated with it.

Every effect the transport records carries an actor and a work item. A change
booked by the recovery worker against any work item other than the one it is
repairing is collateral, and `restart_all` books its damage against `"*"`,
which matches nothing. The metric is not decorative: a test drives collateral
above zero to show it fires.

Without that property, "self-healing" degenerates into the oldest trick in
operations - something looks wrong, restart everything, report 100% recovered.

What the recovery worker may not read
-------------------------------------

The transport knows exactly which fault it injected. The recovery worker must
not read it, or the staircase would be measuring a lookup table. It sees only
what the monitor could prove from the event stream, and it learns whether an
attempt worked the way anything else does: by whether a response came back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from demo_reservation.transport import (
    ESCALATED, RECOVERED_BY_REROUTE, RECOVERED_BY_RETRY, RECOVERY_WORKER,
    UNRESOLVED, Transport,
)

RETRY = "retry_exchange"
REROUTE = "reroute_exchange"
ESCALATE = "escalate_communication_fault"

#: The complete authority step F adds. Pinned by a test.
RECOVERY_SKILLS = (RETRY, REROUTE, ESCALATE)

# Refusal reasons, so an unauthorised operation is counted rather than merely
# prevented. Silence would make the guard indistinguishable from a system
# nobody attacked.
UNKNOWN_VERB = "not_a_recovery_verb"
NOT_GRANTED = "verb_not_granted_at_this_rung"
UNKNOWN_FAULT = "no_such_fault_object"

STILL_FAILING = "still_failing"
NO_BACKUP = "no_registered_backup"


@dataclass(frozen=True)
class FaultObject:
    """What the monitor's observation becomes once it has an identity.

    `observed` is the monitor's kind - `missing_expected_response` - and never
    a cause. Step E's whole point was that the stream cannot prove a crash, and
    handing recovery a diagnosis it was not entitled to make would smuggle the
    conclusion back in through the side door.
    """

    fault_id: str
    work_item: str
    correlation_id: int
    observed: str


@dataclass(frozen=True)
class Refusal:
    fault_id: str
    skill: str
    reason: str


@dataclass
class FaultLedger:
    """Turns monitor observations into addressable objects.

    Deliberately outside the monitor: giving faults identities is the recovery
    side's business, and step E stays byte-identical.

    One object per work item. A retry that also fails produces a new monitor
    observation under a new correlation id, and attaching it to the existing
    fault is what makes "recovery attempts per fault" mean anything.
    """

    faults: Dict[str, FaultObject] = field(default_factory=dict)
    by_work_item: Dict[str, str] = field(default_factory=dict)
    _seen: Set[int] = field(default_factory=set)

    def absorb(self, monitor, transport: Transport) -> List[FaultObject]:
        opened: List[FaultObject] = []
        for fault in monitor.faults:
            if fault.correlation_id in self._seen:
                continue
            self._seen.add(fault.correlation_id)
            work_item = transport.work_item_of_cid.get(fault.correlation_id)
            if work_item is None or work_item in self.by_work_item:
                continue
            fault_id = f"fault_{len(self.faults) + 1:04d}"
            obj = FaultObject(fault_id=fault_id, work_item=work_item,
                              correlation_id=fault.correlation_id,
                              observed=fault.kind)
            self.faults[fault_id] = obj
            self.by_work_item[work_item] = fault_id
            opened.append(obj)
        return opened


# ---------------------------------------------------------------------------
# The three skills. Each takes the transport and a fault OBJECT - never an
# identifier the caller composed, and never a destination.
# ---------------------------------------------------------------------------

def retry_exchange(transport: Transport, fault: FaultObject,
                   escalations: List[str]) -> str:
    ok = transport.resend(fault.work_item, actor=RECOVERY_WORKER)
    return RECOVERED_BY_RETRY if ok else STILL_FAILING


def reroute_exchange(transport: Transport, fault: FaultObject,
                     escalations: List[str]) -> str:
    if not transport.has_backup(fault.work_item):
        return NO_BACKUP
    ok = transport.resend(fault.work_item, use_backup=True,
                          actor=RECOVERY_WORKER)
    return RECOVERED_BY_REROUTE if ok else STILL_FAILING


def escalate_communication_fault(transport: Transport, fault: FaultObject,
                                 escalations: List[str]) -> str:
    escalations.append(fault.fault_id)
    return ESCALATED


_DISPATCH = {
    RETRY: retry_exchange,
    REROUTE: reroute_exchange,
    ESCALATE: escalate_communication_fault,
}


@dataclass
class RecoveryRuntime:
    """Derives the target from the fault object, and checks the grant.

    The recovery worker holds one of these and nothing else. It cannot reach
    the transport, so it cannot resend arbitrary work, cannot restart anything,
    and cannot read which fault was injected.
    """

    transport: Transport
    ledger: FaultLedger
    granted: Set[str] = field(default_factory=lambda: set(RECOVERY_SKILLS))
    refusals: List[Refusal] = field(default_factory=list)
    escalations: List[str] = field(default_factory=list)
    invocations: List[str] = field(default_factory=list)

    def invoke(self, skill: str, fault_id: str) -> str:
        if skill not in RECOVERY_SKILLS:
            return self._refuse(fault_id, skill, UNKNOWN_VERB)
        if skill not in self.granted:
            return self._refuse(fault_id, skill, NOT_GRANTED)
        fault = self.ledger.faults.get(fault_id)
        if fault is None:
            return self._refuse(fault_id, skill, UNKNOWN_FAULT)

        self.invocations.append(f"{skill}({fault_id})")
        return _DISPATCH[skill](self.transport, fault, self.escalations)

    def _refuse(self, fault_id: str, skill: str, reason: str) -> str:
        self.refusals.append(Refusal(fault_id, skill, reason))
        return reason


@dataclass
class RecoveryWorker:
    """The staircase: retry within budget, then the registered backup, then say
    so. It has no transport and no ground truth - only a runtime and a bound.
    """

    runtime: RecoveryRuntime
    retry_budget: int = 3
    outcomes: Dict[str, str] = field(default_factory=dict)
    attempts: Dict[str, int] = field(default_factory=dict)

    def handle(self, fault_id: str) -> str:
        attempts = 0

        for _ in range(self.retry_budget):
            attempts += 1
            result = self.runtime.invoke(RETRY, fault_id)
            if result == RECOVERED_BY_RETRY:
                return self._record(fault_id, result, attempts)
            if result in (NOT_GRANTED, UNKNOWN_VERB, UNKNOWN_FAULT):
                break

        attempts += 1
        result = self.runtime.invoke(REROUTE, fault_id)
        if result == RECOVERED_BY_REROUTE:
            return self._record(fault_id, result, attempts)

        attempts += 1
        result = self.runtime.invoke(ESCALATE, fault_id)
        if result == ESCALATED:
            return self._record(fault_id, result, attempts)
        return self._record(fault_id, UNRESOLVED, attempts)

    def _record(self, fault_id: str, outcome: str, attempts: int) -> str:
        self.outcomes[fault_id] = outcome
        self.attempts[fault_id] = attempts
        return outcome
