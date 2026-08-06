"""Child-side entry point for an isolated workflow stage (case 06).

Run as ``python -m agent_network_demo._isolated_worker``. Speaks
line-delimited JSON: requests go out on stdout, answers come back on stdin.

    <- {"op": "start", "spec": {...}, "envelope": {...}, "grant": {...}}
    -> {"op": "read", "key": "artifact.raw_input"}
    <- {"ok": true, "value": {...}}
    -> {"op": "result", "artifacts": {...}, "events": [...], ...}

The interpreter this runs in holds no runner objects. That is the whole
mechanism: the reach-around techniques case 01 demonstrated still *work* here,
they simply find nothing, because there is no ArtifactStore, no RunSession and
no EventLog in this address space. Isolation empties the room; it does not lock
the door.

Nothing here is trusted. Everything this process returns is validated on the
parent's side by the controls cases 00-05 already built.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import sys
import traceback
import uuid
from typing import Any, Dict, List, Optional

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from agent_network_demo.contracts import ContractError, HandoffEnvelope  # noqa: E402
from agent_network_demo.event_log import Event  # noqa: E402


class ResolverError(RuntimeError):
    """The parent refused, or could not answer, a resolve request."""


def _send(payload: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _receive() -> Dict[str, Any]:
    line = sys.stdin.readline()
    if not line:
        raise ResolverError("the resolver channel closed")
    return json.loads(line)


class RemoteStoreView:
    """The child's view. Same surface as ``StoreView``; every read is a request.

    Holds no store, because there is no store in this process to hold. Reads
    are answered by the parent, which decides each one against the grant it
    issued — so the enforcement point survives the process boundary instead of
    being spent once at start-up.
    """

    def __init__(self, read_keys: List[str], write_key: str,
                 present_keys: List[str]) -> None:
        self._read_grants = set(read_keys)
        self._write_grant = write_key
        self._present = set(present_keys)
        self._read_log: List[str] = []
        self._writes: Dict[str, Any] = {}

    @property
    def read_keys(self) -> List[str]:
        return list(self._read_log)

    @property
    def written_keys(self) -> List[str]:
        return list(self._writes)

    @property
    def writes(self) -> Dict[str, Any]:
        return self._writes

    def get(self, key: str) -> Dict[str, Any]:
        # Checked here for a matching local error, and again by the parent,
        # which is the side that counts.
        if key not in self._read_grants:
            raise ContractError(
                f"read of {key!r} denied: granted {sorted(self._read_grants)}"
            )
        _send({"op": "read", "key": key})
        answer = _receive()
        if not answer.get("ok"):
            raise ContractError(answer.get("error", f"read of {key!r} denied"))
        self._read_log.append(key)
        return answer["value"]

    def has(self, key: str) -> bool:
        return key in self._read_grants and key in self._present

    def register(self, key: str, artifact: Dict[str, Any]) -> Dict[str, Any]:
        if not self._write_grant:
            raise ContractError(
                f"write of {key!r} denied: this envelope declared no output_contract"
            )
        if key != self._write_grant:
            raise ContractError(
                f"write of {key!r} denied: granted {self._write_grant!r}"
            )
        self._writes[key] = artifact
        return artifact


class CollectingLog:
    """Collects the stage's events for the parent to append under its own
    attribution rules. The child cannot write the real log — it does not have
    one, and case 04 would refuse its claimed identity anyway."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.events: List[Dict[str, Any]] = []

    def append(self, event: Event) -> Event:
        self.events.append(event.to_dict())
        return event

    def all(self) -> List[Event]:
        return []

    def as_dicts(self) -> List[Dict[str, Any]]:
        return list(self.events)

    def __len__(self) -> int:
        return len(self.events)


def _load_class(module: str, class_name: str):
    """Import by dotted module name, or by file path for out-of-package
    hostile agents (the case directories are not importable packages)."""
    if module.endswith(".py") or os.sep in module or "/" in module:
        name = f"_isolated_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(name, module)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {module!r}")
        loaded = importlib.util.module_from_spec(spec)
        sys.modules[name] = loaded
        spec.loader.exec_module(loaded)
    else:
        loaded = importlib.import_module(module)
    return getattr(loaded, class_name)


def main() -> int:
    try:
        request = _receive()
    except Exception:  # noqa: BLE001 - nothing to reply to
        return 2

    try:
        spec = request["spec"]
        envelope = HandoffEnvelope(**request["envelope"])
        grant = request["grant"]
        view = RemoteStoreView(grant["read_keys"], grant["write_key"],
                               grant["present_keys"])
        log = CollectingLog(envelope.run_id)

        agent = _load_class(spec["module"], spec["class"])(**spec.get("init", {}))
        result = agent.run(envelope, view, log)

        _send({
            "op": "result",
            "artifacts": view.writes,
            "events": log.events,
            "read_keys": view.read_keys,
            "output_keys": list(getattr(result, "output_keys", [])),
            "summary": getattr(result, "summary", ""),
            "operational_details": getattr(result, "operational_details", {}),
        })
        return 0
    except Exception as exc:  # noqa: BLE001
        _send({
            "op": "error",
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
        })
        return 1


if __name__ == "__main__":  # pragma: no cover - exercised via subprocess
    raise SystemExit(main())
