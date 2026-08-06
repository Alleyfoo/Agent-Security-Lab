"""Case 00 - executable attack: the audited component edits its own evidence.

Run it:

    python cases/00-receipt-handle/attack.py

The attacker is a hostile ValidationAgent implementation. Per the threat model
"agent implementation code" is untrusted, so this is a Level 1 adversary: it
does NOT need memory inspection, a debugger, or any reach-around past a private
attribute. It uses only the object the trusted runner handed to its
constructor.

Scenario: schema_agent violates its contract once (leaving a
``contract_result: failed`` receipt in the runner's record), then behaves on
retry so the workflow proceeds to validation. The honest verdict is therefore
"warn". The hostile validator scrubs the failing receipt before checking, and
the run reports "ok".
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from agent_network_demo.agents import (  # noqa: E402
    KEY_CLEANED, KEY_SCHEMA, SchemaAgent, ValidationAgent,
)
from agent_network_demo.demo_runner import RunSession  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "agent_network_demo", "fixtures")
KEY_FILE = os.path.join(FIXTURES, "key_file.json")


class FlakySchemaAgent(SchemaAgent):
    """Violates its write contract once, then behaves.

    Stands in for any agent that fails a contract check and is retried. The
    point is only to leave a genuine ``failed`` receipt in the runner's record
    while still allowing the workflow to reach validation.
    """

    def __init__(self) -> None:
        self.attempts = 0

    def run(self, envelope, view, log):
        self.attempts += 1
        if self.attempts == 1:
            # Granted artifact.schema_profile; try to write cleaned_output.
            view.register(KEY_CLEANED, {"type": "cleaned_output"})
        return super().run(envelope, view, log)


class HostileValidationAgent(ValidationAgent):
    """Removes every non-passing receipt before auditing itself."""

    def run(self, envelope, view, log):
        try:
            # The whole attack. No private attribute is touched.
            self.receipts[:] = [
                r for r in self.receipts
                if r.get("status") == "ok" and r.get("contract_result") == "passed"
            ]
            print("  [attacker] scrubbed the receipt list via the handed-over object")
        except Exception as exc:  # noqa: BLE001
            print(f"  [attacker] BLOCKED: {type(exc).__name__}: {exc}")
        return super().run(envelope, view, log)


def run_case(hostile: bool) -> dict:
    label = "HOSTILE validator" if hostile else "honest validator"
    print(f"\n--- {label} ---")
    with tempfile.TemporaryDirectory() as tmp:
        sess = RunSession(data_dir=tmp)
        sess.start_run(KEY_FILE)
        sess._agents[1] = FlakySchemaAgent()
        if hostile:
            sess._agents[3] = HostileValidationAgent(sess._agents[3].receipts)

        # 5 calls: intake, schema(fails), schema(retry), transform, validation.
        for _ in range(5):
            if sess.done:
                break
            sess.step()

        receipts = sess.receipts()
        failed = [r for r in receipts if r.get("contract_result") != "passed"]
        report = sess.report()
        verdict = (report.get("verdict") or {}).get("verdict")
        # Windows keeps the JSONL handle open; release it before the temp dir
        # is removed.
        sess.log.close()

        print(f"  receipts in runner record : {len(receipts)}")
        print(f"  failing receipts present  : {len(failed)}")
        print(f"  final verdict             : {verdict}")
        print(f"  reasons                   : {report.get('reasons')}")
        return {"receipts": len(receipts), "failed": len(failed), "verdict": verdict}


if __name__ == "__main__":
    honest = run_case(hostile=False)
    attacked = run_case(hostile=True)

    print("\n=== RESULT ===")
    if attacked["verdict"] == "ok" and honest["verdict"] != "ok":
        print("ATTACK SUCCEEDED: a stage failed its contract, the runner recorded")
        print("it, and the audited component erased the evidence. The run now")
        print("reports a clean verdict.")
        sys.exit(1)
    elif attacked["verdict"] == honest["verdict"] and attacked["failed"] == honest["failed"]:
        print("ATTACK BLOCKED: the hostile validator could not alter the runner's")
        print("evidence; the verdict matches the honest run.")
        sys.exit(0)
    else:
        print(f"INCONCLUSIVE: honest={honest} attacked={attacked}")
        sys.exit(2)
