"""Application-API append-only event log for the agent pipeline.

Agent work and trusted-runner receipts are appended to JSONL and retained in
memory for UI read-back. This API has no update/delete operation; it is not a
cryptographic tamper-evidence mechanism.

``Event.agent`` used to be whatever the caller said it was, so an agent holding
the log could append an event carrying the trusted runner's identity (baseline
finding L4). Agents now receive an :class:`EventLogView` bound to the identity
the *routing table* assigns them, not the one they advertise. See
cases/04-forged-runner-event/README.md.

Scope, stated plainly: this binds attribution, not content, and it constrains
code that goes through the handle. It is not tamper evidence — there is no hash
chain, no signature, and the on-disk file is still rewritable (L5). What it
changes is the level of adversary required to forge an attribution.
"""

from __future__ import annotations

import json
import os
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# The identity the trusted runner writes under. No agent handle may be minted
# for it, and the runner verifies that every event carrying it is one it wrote.
RUNNER_IDENTITY = "trusted_runner"


class AuditIntegrityError(RuntimeError):
    """Raised when an event's attribution cannot be trusted.

    Two situations, deliberately one exception type raised in two places and
    handled differently by the runner:

    * an agent tried to append under an identity it was not assigned — denied
      at the handle, which the runner reports as a contract violation;
    * the log carries a runner-labelled event the runner did not write —
      detected by the post-step sweep, which quarantines the run.

    Distinct from :class:`~agent_network_demo.receipts.ReceiptIntegrityError`.
    Both concern the audit plane and they concern different objects: the ledger
    is the runner's evidence for a decision, the log is the narrative record.
    """


@dataclass
class Event:
    """One audit-trail entry."""

    run_id: str
    agent: str
    action: str
    input_keys: List[str] = field(default_factory=list)
    output_keys: List[str] = field(default_factory=list)
    status: str = "ok"  # ok | warn | error
    checks: Dict[str, Any] = field(default_factory=dict)
    message: str = ""
    event_id: str = ""       # assigned on append (evt_NNN)
    timestamp: str = ""      # assigned on append (ISO-8601, +00:00)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EventLogView:
    """Author-bound handle on an :class:`EventLog`, given to agents.

    The author is assigned by the runner from its own routing table. An event
    that claims a different one is refused by name; an event that claims none
    is stamped. Reads are kept — the view narrows *attribution*, not the
    capability to see the log, so this slice makes exactly one claim.

    Copies are taken on the way in and on the way out. Without them the
    guarantee is defeated in one line: ``log.append(e).agent = "trusted_runner"``
    would edit the stored object, and so would mutating anything ``all()``
    handed back.
    """

    __slots__ = ("_log", "_author")

    def __init__(self, log: "EventLog", author: str) -> None:
        self._log = log
        self._author = author

    @property
    def run_id(self) -> str:
        return self._log.run_id

    @property
    def author(self) -> str:
        return self._author

    def append(self, event: Event) -> Event:
        if event.agent and event.agent != self._author:
            raise AuditIntegrityError(
                f"event attribution denied: {self._author!r} may not append an "
                f"event attributed to {event.agent!r}. The audit log records "
                "who acted; an agent does not choose the identity it acts "
                "under."
            )
        candidate = deepcopy(event)
        candidate.agent = self._author
        candidate.run_id = self._log.run_id
        return deepcopy(self._log.append(candidate))

    # -- read-back -------------------------------------------------------
    def all(self) -> List[Event]:
        return deepcopy(self._log.all())

    def as_dicts(self) -> List[Dict[str, Any]]:
        return self._log.as_dicts()

    def __len__(self) -> int:
        return len(self._log)

    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        return f"<EventLogView author={self._author!r} {len(self)} events>"


class EventLog:
    """Append-only JSONL writer + in-memory read-back.

    The on-disk file is opened in append mode and flushed on every line so a
    crash mid-run still leaves a complete trail up to the last action.
    """

    def __init__(self, run_id: str, data_dir: str = "data") -> None:
        self.run_id = run_id
        self._events: List[Event] = []
        self._counter = 0
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self._path = os.path.join(data_dir, f"events_{run_id}.jsonl")
        # Start a fresh file per run.
        self._fh = open(self._path, "a", encoding="utf-8")

    # -- append ----------------------------------------------------------
    def append(self, event: Event) -> Event:
        """Assign ``event_id`` + ``timestamp``, persist, and store."""
        self._counter += 1
        event.event_id = f"evt_{self._counter:03d}"
        if not event.timestamp:
            event.timestamp = datetime.now(timezone.utc).isoformat()
        line = json.dumps(event.to_dict(), sort_keys=True, ensure_ascii=False)
        self._fh.write(line + "\n")
        self._fh.flush()
        self._events.append(event)
        return event

    # -- author-bound handles --------------------------------------------
    def view_for(self, author: str) -> EventLogView:
        """A handle that can only append under ``author``.

        Refuses the runner's own identity: an agent handle must never be
        mintable for it, whatever a routing table happens to say.
        """
        if not author:
            raise AuditIntegrityError("an event log handle needs an author")
        if author == RUNNER_IDENTITY:
            raise AuditIntegrityError(
                f"refusing to mint an agent handle under {RUNNER_IDENTITY!r}: "
                "the runner's identity is not delegable"
            )
        return EventLogView(self, author)

    # -- read-back -------------------------------------------------------
    def all(self) -> List[Event]:
        return list(self._events)

    def for_run(self, run_id: str) -> List[Event]:
        return [e for e in self._events if e.run_id == run_id]

    def as_dicts(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._events]

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._events)

    @property
    def path(self) -> str:
        return self._path

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()

    @classmethod
    def read_file(cls, path: str) -> List[Dict[str, Any]]:
        """Read back a JSONL event file (for UI/tests)."""
        events: List[Dict[str, Any]] = []
        if not os.path.exists(path):
            return events
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events
