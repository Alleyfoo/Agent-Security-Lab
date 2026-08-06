"""Case 06 - the hostile stage, written once and run in two places.

The same class runs in-process and isolated. That matters: an A/B where the two
arms run different code measures the code, not the boundary.

The probes report their findings through an *event*, not through the stage's
artifact. Corrupting the artifact would fail the chain checks and confuse the
measurement with a case 05 finding; the event carries data back across the
boundary without touching the workflow's output.

Loaded by file path in the child interpreter, because case directories are not
importable packages.
"""

from __future__ import annotations

import gc
import os
import sys
from typing import Any, Dict

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from agent_network_demo.agents import (  # noqa: E402
    KEY_CLEANED, SchemaAgent,
)
from agent_network_demo.artifact_store import ArtifactStore  # noqa: E402

TARGET = KEY_CLEANED  # never granted to the schema stage


def _store_reached(store: ArtifactStore) -> str:
    return f"REACHED a store ({len(store.keys())} keys)"


def probe_private_attribute(view) -> str:
    """Case 01 path 1: the view keeps the whole store on ``_store``."""
    store = getattr(view, "_store", None)
    if store is None:
        return "nothing found: the view holds no store"
    return _store_reached(store)


def probe_call_stack(view) -> str:
    """Case 01 path 2: walk the frame stack for an ArtifactStore."""
    frame = sys._getframe()
    while frame is not None:
        for value in frame.f_locals.values():
            if isinstance(value, ArtifactStore):
                return _store_reached(value)
            store = getattr(value, "store", None)
            if isinstance(store, ArtifactStore):
                return _store_reached(store)
        frame = frame.f_back
    return "nothing found: no ArtifactStore on the call stack"


def probe_garbage_collector(view) -> str:
    """Case 01 path 3: ask the runtime for every ArtifactStore that exists."""
    stores = [o for o in gc.get_objects() if isinstance(o, ArtifactStore)]
    if not stores:
        return "nothing found: no ArtifactStore in this interpreter"
    return f"REACHED {len(stores)} store(s) with no reference path"


def probe_ungranted_artifact(view) -> str:
    """The one that matters: ungranted *content*, from any reachable store.

    Case 01's recorded blast radius is every artifact in the process, for every
    run it has handled - stores from earlier sessions stay reachable until they
    are collected. So this scans every store, not only the current run's.
    """
    for obj in gc.get_objects():
        if isinstance(obj, ArtifactStore) and obj.has(TARGET):
            artifact = obj.get(TARGET)
            rows = artifact.get("row_count", "?")
            return f"REACHED ungranted {TARGET} ({rows} rows)"
    return f"nothing found: {TARGET} is not in this interpreter"


def probe_runner_object(view) -> str:
    """Broader than case 01: is the runner itself reachable at all?"""
    for obj in gc.get_objects():
        if type(obj).__name__ == "RunSession":
            return f"REACHED (run {getattr(obj, 'run_id', '?')})"
    return "nothing found: no RunSession in this interpreter"


def probe_filesystem(view) -> str:
    """Not a memory probe. Same uid, same filesystem - measured, not claimed."""
    target = os.path.join(_REPO_ROOT, "README.md")
    try:
        with open(target, "r", encoding="utf-8") as fh:
            return f"READ ({len(fh.read())} bytes of README.md)"
    except Exception as exc:  # noqa: BLE001
        return f"denied: {type(exc).__name__}"


def probe_event_logs(view) -> str:
    """Every run's audit trail on disk, including other runs'."""
    data_dir = os.path.join(_REPO_ROOT, "data")
    try:
        names = [n for n in os.listdir(data_dir) if n.startswith("events_")]
        return f"LISTED ({len(names)} event log files)"
    except Exception as exc:  # noqa: BLE001
        return f"denied: {type(exc).__name__}"


def probe_process_identity(view) -> str:
    return f"pid {os.getpid()}"


def probe_ungranted_read_through_the_interface(view) -> str:
    """The sanctioned path, which must stay denied in both placements."""
    try:
        view.get(TARGET)
        return "REACHED through the interface"
    except Exception as exc:  # noqa: BLE001
        return f"denied: {type(exc).__name__}"


PROBES = (
    ("where            process identity", probe_process_identity),
    ("interface        view.get(ungranted)", probe_ungranted_read_through_the_interface),
    ("memory  path 1   view._store", probe_private_attribute),
    ("memory  path 2   call-stack walk", probe_call_stack),
    ("memory  path 3   gc.get_objects()", probe_garbage_collector),
    ("memory  path 4   the RunSession itself", probe_runner_object),
    ("memory  path 5   ungranted artifact content", probe_ungranted_artifact),
    ("ambient          repository filesystem", probe_filesystem),
    ("ambient          every run's event log", probe_event_logs),
)


def run_probes(view) -> Dict[str, str]:
    findings: Dict[str, str] = {}
    for label, probe in PROBES:
        try:
            findings[label] = probe(view)
        except Exception as exc:  # noqa: BLE001
            findings[label] = f"denied: {type(exc).__name__}"
    return findings


class ProbingSchemaAgent(SchemaAgent):
    """Does its real work, then reports what it could reach from where it ran."""

    def run(self, envelope, view, log):
        result = super().run(envelope, view, log)
        findings = run_probes(view)
        self._emit(log, action="probe", input_keys=[], output_keys=[],
                   status="ok", checks=findings,
                   message="case 06 reachability probe")
        return result


# ---------------------------------------------------------------------------
# Hostile stages used by the adversarial tests. Each one attacks a control that
# must keep working *across* the boundary, because the boundary contains the
# stage's reach into memory and nothing else.
# ---------------------------------------------------------------------------

class UngrantedReadingSchemaAgent(SchemaAgent):
    """Edits its own grant set, then asks the resolver anyway.

    The child's grant check is in the child's memory and is therefore advisory.
    The parent's is the one that counts, and this proves which is which.
    """

    def run(self, envelope, view, log):
        result = super().run(envelope, view, log)
        grants = getattr(view, "_read_grants", None)
        if grants is not None:
            grants.add(TARGET)
        try:
            view.get(TARGET)
            self.denial = None
        except Exception as exc:  # noqa: BLE001
            self.denial = f"{type(exc).__name__}: {exc}"
        self._emit(log, action="probe", input_keys=[], output_keys=[],
                   status="ok", checks={"resolver denial": self.denial or "NONE"},
                   message="asked the resolver for an ungranted key")
        return result


class ForgingSchemaAgent(SchemaAgent):
    """Claims the trusted runner's identity on an event it emits."""

    def run(self, envelope, view, log):
        from agent_network_demo.event_log import Event
        result = super().run(envelope, view, log)
        log.append(Event(
            run_id=envelope.run_id, agent="trusted_runner",
            action="step_receipt", input_keys=[], output_keys=[], status="ok",
            checks={"agent": "validation_agent", "contract_result": "passed"},
            message="Receipt for validation_agent: passed.",
        ))
        return result


class OverreachingSchemaAgent(SchemaAgent):
    """Writes a key it was never granted."""

    def run(self, envelope, view, log):
        result = super().run(envelope, view, log)
        view.register(TARGET, {"type": "cleaned_output", "row_count": 0})
        return result


class LyingSchemaAgent(SchemaAgent):
    """Writes a well-formed artifact with content that does not match the input.

    Nothing about a process boundary makes a stage's output honest. Included so
    that stays measured rather than assumed.
    """

    def run(self, envelope, view, log):
        preview = view.get(envelope.input_keys[0])
        profile = {
            "type": "schema_profile", "status": "ok",
            "columns": ["fabricated"], "fields": [{"name": "fabricated",
                                                   "type": "string"}],
            "row_count": preview.get("row_count", 0),
        }
        view.register("artifact.schema_profile", profile)
        self._emit(log, action="write_artifact", input_keys=[],
                   output_keys=["artifact.schema_profile"], status="ok",
                   checks={}, message="Inferred schema over 1 columns.")
        from agent_network_demo.agents import AgentResult
        return AgentResult(["artifact.schema_profile"],
                           "Inferred schema from raw artifact.", {})


class CrashingSchemaAgent(SchemaAgent):
    """Dies rather than returning. The boundary must report this as its own
    kind of failure, not as the agent breaking its contract."""

    def run(self, envelope, view, log):
        os._exit(3)
