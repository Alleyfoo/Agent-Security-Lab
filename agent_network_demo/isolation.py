"""Run one workflow stage in a separate interpreter (case 06).

`IsolatedAgent` implements the agent interface the runner already calls, so the
runner does not learn a second way to run a stage. What changes is where the
stage's code executes: a spawned interpreter whose address space contains no
`ArtifactStore`, no `RunSession` and no `EventLog`.

The parent is a **trusted resolver**. It does not hand the child the granted
artifacts up front; the child asks for a key and the parent decides. The
enforcement point therefore survives the boundary — per read, not per run — and
``view.read_keys`` still records what was actually read, which the runner's
reconciliation against the grant depends on.

What the boundary is:

    a containment boundary, not a trust boundary

The isolated stage is assumed captured. Its artifacts re-enter through the real
`StoreView` (write contract + hash registration), its events through the real
`EventLogView` (attribution binding), and its conclusions carry no more weight
than any other agent's. No control from cases 00-05 is switched off because
this boundary exists; those controls are what bounds the loss when it fails.

Scope, stated plainly: this contains reads of the runner's *Python objects*. It
is the same uid, the same filesystem and the same network as the runner. See
cases/06-process-isolation/README.md, which measures what remains.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_TIMEOUT = 60.0


class IsolationError(RuntimeError):
    """The isolated stage failed outside its own contract.

    A crash, a protocol violation, or a timeout. Distinct from a ContractError
    raised *by* the stage, which is ordinary Level 1 containment and reaches
    the runner unchanged.
    """


@dataclass(frozen=True)
class AgentSpec:
    """How to construct the stage's agent inside the child interpreter.

    A dotted module name, or a path to a file for hostile agents that live
    outside the package (case directories are not importable packages). Nothing
    here is authority: the runner still takes the acting identity from its own
    routing table (case 04).
    """

    module: str
    class_name: str
    init: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"module": self.module, "class": self.class_name,
                "init": dict(self.init)}


@dataclass
class IsolatedRun:
    """What came back across the boundary. Untrusted until validated."""

    artifacts: Dict[str, Any]
    events: List[Dict[str, Any]]
    read_keys: List[str]
    output_keys: List[str]
    summary: str
    operational_details: Dict[str, Any]


class IsolatedAgent:
    """Parent-side proxy for a stage that executes in another interpreter."""

    def __init__(self, spec: AgentSpec, name: str,
                 timeout: float = DEFAULT_TIMEOUT,
                 python: Optional[str] = None) -> None:
        self.spec = spec
        # Kept so the object looks like an agent; the runner does not read it
        # for anything that matters (case 04 C2).
        self.name = name
        self.timeout = timeout
        self.python = python or sys.executable
        self.last_run: Optional[IsolatedRun] = None

    # -- the agent interface ---------------------------------------------
    def run(self, envelope, view, log):
        from agent_network_demo.agents import AgentResult

        result = self._execute(envelope, view)
        self.last_run = result

        # Everything below re-enters through the ordinary controls. The order
        # matters: artifacts first, so a write the contract forbids fails
        # before any event describes it as done.
        for key, artifact in result.artifacts.items():
            view.register(key, artifact)
        for event in result.events:
            log.append(self._event_from(event, envelope.run_id))

        return AgentResult(list(result.output_keys), result.summary,
                           dict(result.operational_details))

    # -- the boundary ------------------------------------------------------
    def _execute(self, envelope, view) -> IsolatedRun:
        request = {
            "op": "start",
            "spec": self.spec.to_dict(),
            "envelope": envelope.to_dict(),
            "grant": {
                "read_keys": list(envelope.input_keys),
                "write_key": self._write_key(envelope),
                # Presence is part of the grant, not a separate lookup: an
                # isolated stage must not be able to probe for keys it was
                # never granted by asking whether they exist.
                "present_keys": [k for k in envelope.input_keys if view.has(k)],
            },
        }

        proc = subprocess.Popen(
            [self.python, "-m", "agent_network_demo._isolated_worker"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8",
            cwd=_REPO_ROOT,
        )
        try:
            return self._converse(proc, request, view)
        finally:
            if proc.poll() is None:  # pragma: no cover - timeout path
                proc.kill()
            proc.wait(timeout=5)

    def _converse(self, proc, request, view) -> IsolatedRun:
        self._write(proc, request)
        while True:
            line = proc.stdout.readline()
            if not line:
                stderr = proc.stderr.read()
                raise IsolationError(
                    f"isolated stage produced no result: {stderr.strip()[:400]}"
                )
            message = self._parse(line, proc)
            op = message.get("op")

            if op == "read":
                self._write(proc, self._resolve(message.get("key", ""), view))
                continue
            if op == "result":
                return IsolatedRun(
                    artifacts=message.get("artifacts") or {},
                    events=message.get("events") or [],
                    read_keys=message.get("read_keys") or [],
                    output_keys=message.get("output_keys") or [],
                    summary=message.get("summary", ""),
                    operational_details=message.get("operational_details") or {},
                )
            if op == "error":
                raise self._stage_error(message)
            raise IsolationError(f"unknown message from the isolated stage: {op!r}")

    def _resolve(self, key: str, view) -> Dict[str, Any]:
        """Answer one read request. This is the enforcement point.

        Resolution goes through the same ``StoreView`` an in-process stage
        would hold, so the grant check, the hash verification on read and the
        read log are the ones already tested by cases 01 and 02.
        """
        try:
            return {"ok": True, "value": view.get(key)}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _write(proc, payload: Dict[str, Any]) -> None:
        proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        proc.stdin.flush()

    @staticmethod
    def _parse(line: str, proc) -> Dict[str, Any]:
        try:
            return json.loads(line)
        except json.JSONDecodeError as exc:
            raise IsolationError(
                f"malformed message from the isolated stage: {line.strip()[:200]!r}"
            ) from exc

    @staticmethod
    def _write_key(envelope) -> str:
        from agent_network_demo.contracts import write_key_for
        return write_key_for(envelope.output_contract)

    @staticmethod
    def _stage_error(message: Dict[str, Any]) -> Exception:
        """Re-raise the child's failure on the parent side.

        A ContractError in the child is the stage breaking its contract, which
        is ordinary Level 1 containment and must reach the runner as such —
        not disguised as an infrastructure failure.
        """
        from agent_network_demo.contracts import ContractError
        text = message.get("error", "isolated stage failed")
        if text.startswith("ContractError:"):
            return ContractError(text.split(":", 1)[1].strip())
        return IsolationError(text)

    @staticmethod
    def _event_from(event: Dict[str, Any], run_id: str):
        """Rebuild the child's event. ``agent`` is deliberately dropped: the
        parent's EventLogView stamps the identity the routing table assigned,
        and a captured process does not get to name itself (case 04)."""
        from agent_network_demo.event_log import Event
        return Event(
            run_id=run_id, agent="", action=str(event.get("action", "")),
            input_keys=list(event.get("input_keys") or []),
            output_keys=list(event.get("output_keys") or []),
            status=str(event.get("status", "ok")),
            checks=event.get("checks") or {},
            message=str(event.get("message", "")),
        )
