"""Step E: an independent observer that detects and cannot repair.

The claim, and it is deliberately small:

    Can an independent observer detect that an expected communication did not
    complete correctly, **without possessing authority to repair it**?

Not self-healing. Not diagnosis. Detection, and nothing else.

What the monitor may emit
-------------------------

Only things the event stream can prove:

    missing_expected_response      the deadline passed with nothing matching
    late_response                  it arrived after the deadline
    unexpected_response_identity   right id, wrong party
    duplicate_response             it arrived twice

**It must not conclude `availability_worker_crashed`.** The worker may be
alive and the message dropped. A monitor that infers causes from absences is
grading its own homework about a system it can only see the outside of - the
same failure case 24 measured on the severity plane.

What the monitor may not do
---------------------------

    may:  observe, correlate, detect, emit a communication fault
    NOT:  mutate the calendar, mutate the queue, invoke a worker skill,
          restart a worker, reroute work, change routing

Enforced by tests rather than intended: this module imports no store, no
runtime and no skills, and holds no reference to anything it could act on.
Step F must add every recovery verb explicitly, so the authority it gains is
visible as a diff rather than acquired by being useful.

Otherwise the architecture drifts the way observability always drifts:

    sees everything -> understands everything -> controls everything

which is a root account in a hi-vis vest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from demo_reservation.exchange import REQUEST, RESPONSE, Event

MISSING = "missing_expected_response"
LATE = "late_response"
UNEXPECTED_IDENTITY = "unexpected_response_identity"
DUPLICATE = "duplicate_response"

FAULT_KINDS = (MISSING, LATE, UNEXPECTED_IDENTITY, DUPLICATE)


@dataclass(frozen=True)
class CommunicationFault:
    """A structured observation. It names what the stream shows and stops."""

    kind: str
    correlation_id: int
    detected_tick: int
    expected_from: str = ""
    detail: str = ""

    def describe(self) -> str:
        return (f"t{self.detected_tick} {self.kind} #{self.correlation_id}"
                + (f" expected_from={self.expected_from}"
                   if self.expected_from else "")
                + (f" ({self.detail})" if self.detail else ""))


@dataclass
class _Open:
    request: Event
    responses: int = 0


@dataclass
class Monitor:
    """Sees copies of events. Holds nothing it could act upon."""

    open: Dict[int, _Open] = field(default_factory=dict)
    # correlation_id -> how it settled: by a response, or by its deadline
    # passing. The distinction is what separates a LATE arrival from a
    # DUPLICATE one, and without it a delayed response looks like a second
    # copy of a response that never came.
    settled: Dict[int, str] = field(default_factory=dict)
    faults: List[CommunicationFault] = field(default_factory=list)
    tick: int = 0

    # -- observation --------------------------------------------------------
    def observe(self, event: Event) -> None:
        self.tick = max(self.tick, event.tick)
        if event.kind == REQUEST:
            self.open[event.correlation_id] = _Open(request=event)
            return

        pending = self.open.get(event.correlation_id)
        if pending is None:
            how = self.settled.get(event.correlation_id)
            if how == "deadline":
                # Reported missing when the deadline passed - which was true
                # of the stream at that moment - and it has now turned up.
                # Both observations are honest and the second one is not a
                # duplicate.
                self._fault(LATE, event.correlation_id, event.tick,
                            expected_from=event.sender,
                            detail="arrived after being reported missing")
            elif how == "response":
                self._fault(DUPLICATE, event.correlation_id, event.tick,
                            detail="a second response after settlement")
            else:
                self._fault(UNEXPECTED_IDENTITY, event.correlation_id,
                            event.tick,
                            detail="response with no matching request")
            return

        expected_sender = pending.request.recipient
        if event.sender != expected_sender:
            self._fault(UNEXPECTED_IDENTITY, event.correlation_id, event.tick,
                        expected_from=expected_sender,
                        detail=f"arrived from {event.sender}")
            return

        pending.responses += 1
        if pending.responses > 1:
            self._fault(DUPLICATE, event.correlation_id, event.tick,
                        expected_from=expected_sender)
            return

        if event.tick > pending.request.deadline:
            self._fault(LATE, event.correlation_id, event.tick,
                        expected_from=expected_sender,
                        detail=f"deadline was t{pending.request.deadline}")
        self.settled[event.correlation_id] = "response"
        del self.open[event.correlation_id]

    def on_tick(self, tick: int) -> None:
        """A deadline passing is an observation, not an inference."""
        self.tick = tick
        for correlation_id, pending in list(self.open.items()):
            if tick > pending.request.deadline:
                self._fault(MISSING, correlation_id, tick,
                            expected_from=pending.request.recipient,
                            detail=f"deadline was t{pending.request.deadline}")
                self.settled[correlation_id] = "deadline"
                del self.open[correlation_id]

    # -- what it produces ---------------------------------------------------
    def _fault(self, kind: str, correlation_id: int, tick: int,
               expected_from: str = "", detail: str = "") -> None:
        self.faults.append(CommunicationFault(
            kind=kind, correlation_id=correlation_id, detected_tick=tick,
            expected_from=expected_from, detail=detail))

    def faults_by_correlation(self) -> Dict[int, List[CommunicationFault]]:
        out: Dict[int, List[CommunicationFault]] = {}
        for fault in self.faults:
            out.setdefault(fault.correlation_id, []).append(fault)
        return out
