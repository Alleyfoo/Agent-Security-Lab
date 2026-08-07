"""Step E's fault injector. **Written before the detector exists.**

Same rule as step B's disruption generator, for the same reason: a fault set
chosen because the monitor catches it would measure the author. The vocabulary
is fixed here, now, in ignorance of how anything will detect it.

    drop_response              no response is ever emitted
    delay_past_deadline        the response arrives, too late
    wrong_correlation_id       a response arrives under a different id
    wrong_sender_or_recipient  the right id, the wrong party
    duplicate_response         the response arrives twice

The injector knows exactly which exchange it broke. **That is the ground
truth**, and it is the easy half of step C's oracle problem - there is nothing
to search for, only something to remember. The monitor must never read it, and
a test enforces that.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from demo_reservation.exchange import Bus, Exchange

DROP_RESPONSE = "drop_response"
DELAY_PAST_DEADLINE = "delay_past_deadline"
WRONG_CORRELATION_ID = "wrong_correlation_id"
WRONG_SENDER_OR_RECIPIENT = "wrong_sender_or_recipient"
DUPLICATE_RESPONSE = "duplicate_response"

VOCABULARY = (DROP_RESPONSE, DELAY_PAST_DEADLINE, WRONG_CORRELATION_ID,
              WRONG_SENDER_OR_RECIPIENT, DUPLICATE_RESPONSE)

# What a correct detector should say about each. Written here, beside the
# faults, so the mapping is preregistered rather than fitted afterwards.
EXPECTED_FAULT = {
    DROP_RESPONSE: "missing_expected_response",
    DELAY_PAST_DEADLINE: "late_response",
    WRONG_CORRELATION_ID: "missing_expected_response",
    WRONG_SENDER_OR_RECIPIENT: "unexpected_response_identity",
    DUPLICATE_RESPONSE: "duplicate_response",
}


@dataclass
class Injected:
    correlation_id: int
    kind: str
    request_tick: int


@dataclass
class Injector:
    """Runs the traffic and breaks some of it. Ground truth lives here."""

    rate: float = 0.05
    seed: int = 91100
    injected: Dict[int, Injected] = field(default_factory=dict)
    clean: List[int] = field(default_factory=list)

    def run(self, bus: Bus, exchanges: int = 1000) -> None:
        rng = random.Random(self.seed)
        for i in range(exchanges):
            exchange = Exchange(correlation_id=i)
            request = exchange.request(bus.tick)
            bus.emit(request)

            kind = (rng.choice(VOCABULARY) if rng.random() < self.rate
                    else None)
            if kind is None:
                self.clean.append(i)
                bus.advance()
                bus.emit(exchange.response(bus.tick))
            else:
                self.injected[i] = Injected(i, kind, request.tick)
                self._break(bus, exchange, kind, request)

            # Enough ticks for every deadline in flight to fall due.
            for _ in range(exchange.slack + 2):
                bus.advance()

    def _break(self, bus: Bus, exchange: Exchange, kind: str,
               request) -> None:
        if kind == DROP_RESPONSE:
            return
        if kind == DELAY_PAST_DEADLINE:
            for _ in range(exchange.slack + 1):
                bus.advance()
            bus.emit(exchange.response(bus.tick))
            return
        if kind == WRONG_CORRELATION_ID:
            bus.advance()
            bus.emit(exchange.response(bus.tick, correlation_id=900000 +
                                       exchange.correlation_id))
            return
        if kind == WRONG_SENDER_OR_RECIPIENT:
            bus.advance()
            bus.emit(exchange.response(bus.tick, sender="stranger_worker"))
            return
        if kind == DUPLICATE_RESPONSE:
            bus.advance()
            bus.emit(exchange.response(bus.tick))
            bus.emit(exchange.response(bus.tick))
            return

    # -- ground truth -------------------------------------------------------
    def truth(self) -> Dict[int, str]:
        return {cid: entry.kind for cid, entry in self.injected.items()}

    def request_tick(self, correlation_id: int) -> Optional[int]:
        entry = self.injected.get(correlation_id)
        return entry.request_tick if entry else None
