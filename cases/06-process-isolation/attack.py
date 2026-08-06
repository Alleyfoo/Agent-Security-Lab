"""Case 06 - executable attack: what process separation actually buys.

Run it:

    python cases/06-process-isolation/attack.py

The same hostile schema stage runs twice - once in the runner's process, once
in a spawned interpreter - and reports what it could reach from each. An A/B
where the two arms run different code would measure the code, not the boundary,
so both arms load `hostile.ProbingSchemaAgent`.

Three parts:

  A. The memory probes, both placements. This is the narrow claim.
  B. What the isolated stage still reaches. Isolation is not a grant, not a
     sandbox and not a validator.
  C. Partial isolation - the system's actual state, with three of four stages
     still sharing the runner's process.

Exit 0 means the narrow claim held. It does not mean the stage is contained;
part B is expected to find plenty, and reports it rather than failing on it.
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from agent_network_demo.agents import KEY_CLEANED, TransformAgent  # noqa: E402
from agent_network_demo.demo_runner import RunSession  # noqa: E402
from agent_network_demo.isolation import AgentSpec  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
FIXTURES = os.path.join(REPO_ROOT, "agent_network_demo", "fixtures")
KEY_FILE = os.path.join(FIXTURES, "key_file.json")

HOSTILE = os.path.join(HERE, "hostile.py")
HOSTILE_SPEC = AgentSpec(module=HOSTILE, class_name="ProbingSchemaAgent")

sys.path.insert(0, HERE)
from hostile import ProbingSchemaAgent, run_probes  # noqa: E402

MEMORY = "memory"
AMBIENT = "ambient"


def _prior_run(tmp: str) -> RunSession:
    """One completed, entirely honest workflow, kept alive.

    Case 01's blast radius is the process, not the run: a store from an earlier
    session stays reachable until it is collected. A long-lived process holding
    finished sessions is the realistic shape - the Streamlit app keeps them in
    session state - and without one the probes would run before any ungranted
    artifact exists and understate the in-process exposure.
    """
    prior = RunSession(data_dir=tmp)
    prior.start_run(KEY_FILE)
    while not prior.done:
        prior.step()
    prior.log.close()
    return prior


def _run(isolated: bool) -> dict:
    """One full workflow with the probing schema stage in the given placement."""
    with tempfile.TemporaryDirectory() as tmp:
        prior = _prior_run(tmp)          # noqa: F841 - kept alive on purpose
        isolate = {"schema": HOSTILE_SPEC} if isolated else None
        session = RunSession(data_dir=tmp, isolate=isolate)
        session.start_run(KEY_FILE)
        if not isolated:
            session._agents[1] = ProbingSchemaAgent()

        while not session.done and not session.quarantined and session.error is None:
            session.step()

        probes = next((e["checks"] for e in session.events()
                       if e["action"] == "probe"), {})
        receipt = next((r for r in session.receipts()
                        if r["agent"] == "schema_agent"), {})
        report = session.report() if session.done else {}
        session.log.close()

    return {
        "probes": probes,
        "read_keys": receipt.get("keys_actually_read", []),
        "done": bool(report.get("done")),
        "verdict": (report.get("verdict") or {}).get("verdict"),
        "error": session.error,
    }


def _print_probes(label: str, probes: dict) -> None:
    print(f"\n  {label}")
    for name, finding in probes.items():
        mark = "!!" if finding.startswith(("REACHED", "READ", "LISTED")) else "  "
        print(f"   {mark} {name:38s} {finding}")


def _reached(probes: dict, kind: str) -> list:
    return [name for name, finding in probes.items()
            if name.startswith(kind)
            and finding.startswith(("REACHED", "READ", "LISTED"))]


def part_a(in_process: dict, isolated: dict) -> dict:
    print("\n=== A. The memory probes, both placements ===")
    print("  The same hostile stage, the same probes, two places to run.")
    _print_probes("In the runner's process:", in_process["probes"])
    _print_probes("In a spawned interpreter:", isolated["probes"])

    before = _reached(in_process["probes"], MEMORY)
    after = _reached(isolated["probes"], MEMORY)
    print(f"\n  memory paths that reached, in-process : {len(before)}")
    print(f"  memory paths that reached, isolated   : {len(after)}")
    print(f"  workflow still completed, isolated    : {isolated['done']} "
          f"(verdict {isolated['verdict']})")
    print(f"  reads the runner recorded, isolated   : {isolated['read_keys']}")
    return {"before": before, "after": after}


def part_b(isolated: dict) -> dict:
    print("\n=== B. What the isolated stage still reaches ===")
    ambient = _reached(isolated["probes"], AMBIENT)
    for name in ambient:
        print(f"   !! {name.strip()}: {isolated['probes'][name]}")
    if not ambient:
        print("    (nothing - which would be a surprise worth investigating)")
    print("\n  Same uid, same filesystem, same network. The grant is unchanged:")
    print(f"  the stage read {isolated['read_keys']} because that is what it")
    print("  was granted, and isolation narrows a grant by exactly nothing.")
    print("  It also still authors its own output; nothing about a process")
    print("  boundary makes a stage's content honest (that is case 05).")
    return {"ambient": ambient}


def part_c() -> dict:
    """Partial isolation: schema is isolated, transform is not."""
    print("\n=== C. Partial isolation, which is the system's actual state ===")

    class ProbingTransformAgent(TransformAgent):
        def run(self, envelope, view, log):
            result = super().run(envelope, view, log)
            self._emit(log, action="probe", input_keys=[], output_keys=[],
                       status="ok", checks=run_probes(view),
                       message="case 06 reachability probe (in-process stage)")
            return result

    with tempfile.TemporaryDirectory() as tmp:
        session = RunSession(data_dir=tmp, isolate={"schema": HOSTILE_SPEC})
        session.start_run(KEY_FILE)
        session._agents[2] = ProbingTransformAgent()
        while not session.done and not session.quarantined and session.error is None:
            session.step()
        probes = [e["checks"] for e in session.events() if e["action"] == "probe"]
        session.log.close()

    transform_probes = probes[-1] if probes else {}
    _print_probes("The transform stage, still in-process:", transform_probes)
    reached = _reached(transform_probes, MEMORY)
    print(f"\n  memory paths that reached from the un-isolated stage: {len(reached)}")
    print(f"  isolated stages in this run                         : ['schema']")
    print(f"  stages still sharing the runner's process           : 3 of 4")
    return {"reached": reached}


if __name__ == "__main__":
    print("One hostile stage, two placements. What does the boundary remove?")

    in_process = _run(isolated=False)
    isolated = _run(isolated=True)

    a = part_a(in_process, isolated)
    b = part_b(isolated)
    c = part_c()

    print("\n=== RESULT ===")
    if not a["before"]:
        print("MEASUREMENT BROKEN. The in-process arm reached nothing, so there")
        print("was no exposure to remove and the comparison proves nothing.")
        raise SystemExit(1)
    if a["after"]:
        print("CLAIM FAILED. The isolated stage still reached the runner's")
        print("memory by: " + ", ".join(a["after"]))
        raise SystemExit(1)

    print("NARROW CLAIM HELD. Every memory path that reached from inside the")
    print("runner's process reached nothing from the spawned interpreter, and")
    print("the workflow still completed with a truthful read log.")
    print(f"  in-process : {len(a['before'])} memory paths reached")
    print(f"  isolated   : 0")
    print()
    print("It bought exactly that. Still true of the isolated stage:")
    print(f"  - ambient access unchanged ({len(b['ambient'])} probes reached)")
    print("  - its grant is unchanged")
    print("  - its output is still its own to author")
    print()
    print("And the system is not isolated. An un-isolated stage in the same")
    print(f"run reached the runner's memory by {len(c['reached'])} paths, including")
    print("the isolated stage's own output artifact. Isolating one stage of")
    print("four moves one stage out of reach of the runner's objects; it does")
    print("not reduce what a compromise of the other three obtains.")
    raise SystemExit(0)
