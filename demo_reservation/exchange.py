"""Communication as explicit expectations, on a logical clock.

A vague "the monitor watches messages" cannot be measured. An exchange states
what it expects and by when, so a fault is a fact about the event stream rather
than an opinion:

    request   correlation_id, sender, recipient, expects, deadline
    response  correlation_id, sender, recipient, delivers

**Logical ticks, never wall-clock.** A deadline in seconds would measure
Windows scheduling and CI load rather than communication detection.

Nothing here can repair anything. The bus records and delivers; it has no
retry, no timeout handler and no route table.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

REQUEST = "request"
RESPONSE = "response"

RESERVATION_WORKER = "reservation_worker"
AVAILABILITY_WORKER = "availability_worker"
AVAILABILITY_RESULT = "availability_result"


@dataclass(frozen=True)
class Event:
    tick: int
    kind: str
    correlation_id: int
    sender: str
    recipient: str
    expects: str = ""          # requests only
    delivers: str = ""         # responses only
    deadline: int = 0          # requests only

    def describe(self) -> str:
        if self.kind == REQUEST:
            return (f"t{self.tick} {self.sender}->{self.recipient} "
                    f"#{self.correlation_id} expects {self.expects} "
                    f"by t{self.deadline}")
        return (f"t{self.tick} {self.sender}->{self.recipient} "
                f"#{self.correlation_id} delivers {self.delivers}")


@dataclass
class Bus:
    """Carries events and hands copies to observers.

    Observers receive **copies** and the log is a private list. An observer
    that could edit the stream would be able to hide its own misses, which is
    the audit-plane mistake case 00 exists to prevent.
    """

    tick: int = 0
    _log: List[Event] = field(default_factory=list)
    observers: List[object] = field(default_factory=list)

    def emit(self, event: Event) -> None:
        self._log.append(event)
        for observer in self.observers:
            observer.observe(Event(**vars(event)))

    def advance(self) -> int:
        self.tick += 1
        for observer in self.observers:
            if hasattr(observer, "on_tick"):
                observer.on_tick(self.tick)
        return self.tick

    def log(self) -> List[Event]:
        return list(self._log)


@dataclass
class Exchange:
    correlation_id: int
    sender: str = RESERVATION_WORKER
    recipient: str = AVAILABILITY_WORKER
    expects: str = AVAILABILITY_RESULT
    slack: int = 3

    def request(self, tick: int) -> Event:
        return Event(tick=tick, kind=REQUEST,
                     correlation_id=self.correlation_id, sender=self.sender,
                     recipient=self.recipient, expects=self.expects,
                     deadline=tick + self.slack)

    def response(self, tick: int, sender: Optional[str] = None,
                 recipient: Optional[str] = None,
                 correlation_id: Optional[int] = None) -> Event:
        return Event(tick=tick, kind=RESPONSE,
                     correlation_id=(self.correlation_id
                                     if correlation_id is None
                                     else correlation_id),
                     sender=sender or self.recipient,
                     recipient=recipient or self.sender,
                     delivers=self.expects)
