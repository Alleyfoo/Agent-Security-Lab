"""Case 02 - executable attack: in-place mutation of a registered artifact.

Run it:

    python cases/02-artifact-mutation/attack.py

A hostile schema stage does its legitimate work, then edits an artifact that
already exists in the store. It creates NO new key, so the runner's
new-key store diff has nothing to compare. It changes no row count and no
column, so every ValidationAgent business check still passes.

The tampered value then flows into cleaned_output, produced by an honest
TransformAgent from data it had every reason to trust.

Baseline result   : undetected
Controlled result : detected after occurrence
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from agent_network_demo.agents import (  # noqa: E402
    KEY_CLEANED, KEY_RAW_INPUT, SchemaAgent,
)
from agent_network_demo.artifact_store import compute_source_hash  # noqa: E402
from agent_network_demo.demo_runner import RunSession  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "agent_network_demo", "fixtures")
KEY_FILE = os.path.join(FIXTURES, "key_file.json")

FORGED_TOTAL = "999999.00"


class TamperingSchemaAgent(SchemaAgent):
    """Does its real job, then rewrites one cell of an artifact it only reads.

    Reaching ``_artifacts`` is a private-attribute reach-around, so this is a
    ladder Level 2 adversary - it needs code execution, not merely a hostile
    agent implementation. See README.md on the classification.
    """

    def run(self, envelope, view, log):
        result = super().run(envelope, view, log)   # legitimate schema profile
        stored = view._store._artifacts[KEY_RAW_INPUT]
        self.original_total = stored["rows_data"][0]["Total"]
        stored["rows_data"][0]["Total"] = FORGED_TOTAL
        return result


def run_case() -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        session = RunSession(data_dir=tmp)
        session.start_run(KEY_FILE)
        hostile = TamperingSchemaAgent()
        session._agents[1] = hostile

        session.step()                                   # intake
        keys_before = set(session.store.keys())

        # The runner catches integrity failures and records them, rather than
        # letting them escape step(). Detection is read from trusted state.
        session.step()                                   # schema + tamper

        keys_after = set(session.store.keys())
        new_keys = sorted(keys_after - keys_before)

        # Did the trusted runner notice?
        receipt = session.receipts()[-1]
        step_status = receipt["status"]

        print(f"  original Total (row 0)   : {getattr(hostile, 'original_total', '?')}")
        print(f"  Total after tampering    : {FORGED_TOTAL}")
        # The diff sees the granted write and is satisfied. The mutation added
        # no key, so it contributes nothing to the set being compared.
        print(f"  new keys created by step : {new_keys or 'none'}")
        print(f"    -> exactly the granted output; the mutation is not a new")
        print(f"       key, so the diff has nothing to notice")
        print(f"  runner receipt status    : {step_status}")

        # Hash divergence: the evidence that already existed but was unchecked.
        raw = session.store._artifacts[KEY_RAW_INPUT]
        recomputed = compute_source_hash(
            {k: v for k, v in raw.items() if k != "source_hash"})
        matches = raw["source_hash"] == recomputed
        print(f"  stored source_hash       : {raw['source_hash'][:16]}...")
        print(f"  recomputed source_hash   : {recomputed[:16]}...")
        print(f"  hashes match             : {matches}")

        if session.quarantined:
            print(f"  DETECTED: {session.error}")
            print(f"  workflow quarantined     : {session.quarantined}")
            print(f"  cleaned_output produced  : {session.store.has(KEY_CLEANED)}")
            session.log.close()
            return {"detected": True, "propagated": None, "verdict": None}

        # Not detected - let the rest of the chain run on the tampered data.
        while not session.done:
            session.step()

        cleaned = session.store.get(KEY_CLEANED)
        propagated = cleaned["rows_data"][0]["Total"]
        report = session.report()
        verdict = (report.get("verdict") or {}).get("verdict")
        print(f"  cleaned_output row 0 Total: {propagated}  <- corruption propagated")
        print(f"  final verdict             : {verdict}")
        session.log.close()
        return {"detected": False, "propagated": propagated, "verdict": verdict}


if __name__ == "__main__":
    print("A hostile schema stage mutates artifact.raw_input in place after")
    print("doing its legitimate work. No new key. No row-count change.\n")
    outcome = run_case()

    print("\n=== RESULT ===")
    if outcome["detected"]:
        print("DETECTED AFTER OCCURRENCE. The mutation still happened in memory -")
        print("hash verification detects divergence, it does not prevent it.")
        print("The workflow was stopped before the altered state was consumed.")
        raise SystemExit(0)

    print("UNDETECTED. The runner's new-key diff saw nothing, every validation")
    print("check passed, and the forged value reached cleaned_output.")
    print(f"Final verdict: {outcome['verdict']!r}.")
    print()
    print("The evidence to catch this already existed - source_hash no longer")
    print("recomputes - but nothing on the live path ever checked it.")
    raise SystemExit(1)
