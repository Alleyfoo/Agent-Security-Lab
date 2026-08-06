"""Case 01 - executable attack: reading artifacts the grant excludes.

Run it:

    python cases/01-ungranted-read/attack.py

The adversary is hostile code executing inside an agent - ladder Level 2. It
holds a StoreView granting read access to ONE key and attempts to read a
different one.

Three escalating paths are demonstrated. The point of showing three is not that
the first is interesting - it is that closing any one of them closes nothing,
because they do not share a mechanism. The script then implements the obvious
"fix" for path 1 and shows paths 2 and 3 walking straight past it.

Expected outcome: the attack SUCCEEDS. Case 01 has no control at Phase 2. See
README.md - this is the motivation for process isolation in Phase 5, and the
reason a cosmetic in-process patch must be refused.
"""

from __future__ import annotations

import gc
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from agent_network_demo.agents import KEY_CLEANED, KEY_RAW_INPUT  # noqa: E402
from agent_network_demo.artifact_store import ArtifactStore  # noqa: E402
from agent_network_demo.demo_runner import RunSession  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "agent_network_demo", "fixtures")
KEY_FILE = os.path.join(FIXTURES, "key_file.json")

TARGET = KEY_CLEANED  # never granted to the schema stage


# ---------------------------------------------------------------------------
# Attack paths. Each takes a view granted only KEY_RAW_INPUT and tries to read
# TARGET. Returns the artifact, or raises.
# ---------------------------------------------------------------------------

def path_0_through_the_interface(view):
    """The sanctioned path. This is the one that works as designed."""
    return view.get(TARGET)


def path_1_private_attribute(view):
    """The naive reach-around: the view keeps the whole store on ``_store``."""
    return view._store.get(TARGET)


def path_2_call_stack(view):
    """Walk the frame stack until a frame holds an ArtifactStore.

    Does not touch the view at all, so removing ``_store`` changes nothing.
    """
    frame = sys._getframe()
    while frame is not None:
        for value in frame.f_locals.values():
            if isinstance(value, ArtifactStore):
                return value.get(TARGET)
            store = getattr(value, "store", None)
            if isinstance(store, ArtifactStore):
                return store.get(TARGET)
        frame = frame.f_back
    raise LookupError("no ArtifactStore found on the call stack")


def path_3_garbage_collector(view):
    """Ask the runtime for every ArtifactStore that exists.

    Reaches objects with no reference path from the agent whatsoever.
    """
    for obj in gc.get_objects():
        if isinstance(obj, ArtifactStore) and obj.has(TARGET):
            return obj.get(TARGET)
    raise LookupError("no ArtifactStore found via gc")


PATHS = [
    ("0. view.get()            [sanctioned]", path_0_through_the_interface),
    ("1. view._store           [private attr]", path_1_private_attribute),
    ("2. call-stack walk       [no view use]", path_2_call_stack),
    ("3. gc.get_objects()      [no references]", path_3_garbage_collector),
]


# ---------------------------------------------------------------------------
# The cosmetic "fix" for path 1, implemented so it can be shown to fail.
# Deliberately NOT added to production code.
# ---------------------------------------------------------------------------

class ClosureStoreView:
    """A StoreView that keeps no store attribute - only closures.

    This is the patch someone reaches for after seeing path 1. It is refused,
    and this class exists solely to demonstrate why.
    """

    def __init__(self, store: ArtifactStore, read_keys, write_key: str = ""):
        grants = set(read_keys)
        self._read_log = []

        def _get(key):
            if key not in grants:
                raise PermissionError(
                    f"read of {key!r} denied: granted {sorted(grants)}")
            self._read_log.append(key)
            return store.get(key)

        self.get = _get

    @property
    def read_keys(self):
        return list(self._read_log)


def _probe(view, label: str) -> None:
    print(f"\n  {label}")
    for name, path in PATHS:
        try:
            artifact = path(view)
            rows = artifact.get("row_count", "?")
            print(f"    {name}  -> READ OK ({rows} rows)")
        except Exception as exc:  # noqa: BLE001
            print(f"    {name}  -> denied: {type(exc).__name__}")
    print(f"    view.read_keys recorded: {view.read_keys}")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        session = RunSession(data_dir=tmp)
        session.start_run(KEY_FILE)
        for _ in range(3):          # intake, schema, transform
            session.step()
        store = session.store
        assert store.has(TARGET), "cleaned_output should exist by now"

        print("A compromised schema stage holds a view granted only")
        print(f"{KEY_RAW_INPUT!r} and wants to read {TARGET!r}.")

        _probe(store.view([KEY_RAW_INPUT], "artifact.schema_profile"),
               "Production StoreView:")
        _probe(ClosureStoreView(store, [KEY_RAW_INPUT]),
               "ClosureStoreView (the 'fix' for path 1):")

        session.log.close()

    print("\n=== RESULT ===")
    print("ATTACK SUCCEEDS. The scoped view constrains reads that go THROUGH")
    print("it, and nothing else. Removing the private attribute closes exactly")
    print("one path and leaves the other two untouched - which is why that")
    print("patch is refused rather than shipped.")
    print()
    print("Every bypass also left the read log empty, so the runner's")
    print("reconciliation of actual reads against the grant sees nothing.")
    print()
    print("No control at Phase 2. Control is process isolation - Phase 5.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
