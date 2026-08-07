"""Case 12 - three models, one workflow, one attacker.

Run it:

    python cases/12-three-models/attack.py

Three architectures get the same business operation and the same adversary:

    A  authority follows the subject           (identity + permissions)
    B  authority follows the configured step   (workflow automation)
    C  authority derived for one transformation (object / reference / skill)

Attacker, identical in every arm: **may alter persisted configuration or
workflow records; may not modify executable code or the administrative trust
root.** Case 08's attacker, generalized so it means the same thing three times.

Named capability, the same one cases 08 and 10 used so the numbers stay
comparable: obtain a read of `artifact.key_material` at the schema step.

Measured: where authority is stored, whether it is standing or task-specific,
the minimum number of stored edits that obtains the capability, the scope of
one successful edit, and what it survives.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile

CASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CASE_DIR)
sys.path.insert(0, os.path.dirname(os.path.dirname(CASE_DIR)))

from case12_common import (  # noqa: E402
    ATTACK_STAGE, SCOPE_ORDER, TARGET, ArmResult, Measurement, fresh_store,
)


def _load(name: str):
    """The case directory is not an importable package."""
    spec = importlib.util.spec_from_file_location(
        f"case12_{name}", os.path.join(CASE_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case12_{name}"] = module
    spec.loader.exec_module(module)
    return module


arm_a = _load("arm_a")
arm_b = _load("arm_b")
arm_c = _load("arm_c")


# ---------------------------------------------------------------------------
# Equivalence first. An arm that cannot do the same work is not a fair arm and
# its numbers are void - the precondition case 10 established when it built map
# maintenance before attacking the map.
# ---------------------------------------------------------------------------

def run_clean(arm, store_dir: str) -> ArmResult:
    store = fresh_store()
    if arm is arm_c:
        arm.reset(store_dir)
    else:
        arm.reset()
    grants = arm.run_workflow(store)
    produced = [k for k in store.keys()
                if k not in ("artifact.source_payload", TARGET)]
    return ArmResult(name=arm.NAME, authority_kind=arm.AUTHORITY_KIND,
                     surfaces=arm.surfaces(), grants=grants, produced=produced)


def check_equivalence(results) -> bool:
    produced = {tuple(r.produced) for r in results}
    schema_reads = {tuple(sorted(r.grants[ATTACK_STAGE].read_keys))
                    for r in results}
    ok = len(produced) == 1 and len(schema_reads) == 1
    print("\n--- Equivalence: same work, same schema-step grant ---")
    for r in results:
        print(f"  {r.name}")
        print(f"      produced      {r.produced}")
        print(f"      schema reads  "
              f"{sorted(r.grants[ATTACK_STAGE].read_keys)}")
    print(f"\n  functionally equivalent: {ok}")
    if not ok:
        print("  !! the comparison is VOID until the arms do the same work")
    return ok


# ---------------------------------------------------------------------------
# The attack, one surface (or combination) at a time.
# ---------------------------------------------------------------------------

def measure_arm_a() -> ArmResult:
    result = run_clean(arm_a, "")
    for surface in arm_a.surfaces():
        arm_a.reset()
        detail = arm_a.MUTATIONS[surface](TARGET)
        obtained = arm_a.resolve(ATTACK_STAGE).permits_read(TARGET)
        result.cells.append(Measurement(
            arm=arm_a.NAME, surface=surface, obtained=obtained,
            edits=arm_a.EDITS[surface], scope=arm_a.SCOPES[surface],
            detection=arm_a.DETECTION[surface],
            persists=arm_a.PERSISTENCE[surface], note=detail))
    arm_a.reset()
    return result


def measure_arm_b() -> ArmResult:
    result = run_clean(arm_b, "")
    for label, steps in arm_b.COMBINATIONS.items():
        arm_b.reset()
        details = [arm_b.MUTATIONS[s](TARGET) for s in steps]
        try:
            obtained = arm_b.resolve(ATTACK_STAGE).permits_read(TARGET)
        except Exception as exc:                          # noqa: BLE001
            obtained = False
            details.append(f"REFUSED: {exc}")
        result.cells.append(Measurement(
            arm=arm_b.NAME, surface=label, obtained=obtained,
            edits=len(steps), scope=arm_b.SCOPES[label],
            detection=arm_b.DETECTION[label],
            persists=arm_b.PERSISTENCE[label], note="; ".join(details)))
    arm_b.reset()
    return result


def measure_arm_c(store_dir: str) -> ArmResult:
    result = run_clean(arm_c, os.path.join(store_dir, "clean"))
    for index, surface in enumerate(arm_c.surfaces()):
        arm_c.reset(os.path.join(store_dir, f"s{index}"))
        detail = arm_c.MUTATIONS[surface](TARGET)
        try:
            obtained = arm_c.resolve(ATTACK_STAGE).permits_read(TARGET)
        except Exception as exc:                          # noqa: BLE001
            obtained = False
            detail = f"{detail} -> REFUSED: {exc}"
        result.cells.append(Measurement(
            arm=arm_c.NAME, surface=surface, obtained=obtained,
            edits=arm_c.EDITS[surface], scope=arm_c.SCOPES[surface],
            detection=arm_c.DETECTION[surface],
            persists=arm_c.PERSISTENCE[surface], note=detail))
    return result


def _show(result: ArmResult) -> None:
    print(f"\n  {result.name}")
    print(f"      authority is {result.authority_kind}")
    print(f"      stored authority-bearing records: {len(result.surfaces)}")
    for cell in result.cells:
        mark = "!!" if cell.obtained else "  "
        verdict = "OBTAINED" if cell.obtained else "no"
        print(f"   {mark} {cell.surface:38s} {cell.edits} edit(s)  "
              f"{verdict:9s}")
        print(f"        {cell.note}")


if __name__ == "__main__":
    print("Three places to attach authority, one workflow, one attacker.")

    with tempfile.TemporaryDirectory() as tmp:
        a = measure_arm_a()
        b = measure_arm_b()
        c = measure_arm_c(tmp)
        results = [a, b, c]

        equivalent = check_equivalence(results)

        print("\n--- Minimum stored change to obtain the named capability ---")
        for r in results:
            _show(r)

        print("\n=== RESULT ===")
        print(f"{'arm':>4s}  {'authority':<12s} {'records':>7s} "
              f"{'min tamper set':>14s}  widest scope at that cost")
        for label, r in zip("ABC", results):
            kind = r.authority_kind.split(" - ")[0]
            mts = r.minimum_tamper_set
            # The widest scope reachable *at minimum cost* - the conservative
            # reading. Arm C's cheapest edits differ by two full steps of the
            # scale, and reporting the narrower one would flatter it.
            cheapest = [x for x in r.cells if x.obtained and x.edits == mts]
            scope = max((x.scope for x in cheapest),
                        key=SCOPE_ORDER.index) if cheapest else "-"
            print(f"{label:>4s}  {kind:<12s} {len(r.surfaces):>7d} "
                  f"{(str(mts) if mts else 'not obtained'):>14s}  {scope}")

        print()
        if b.minimum_tamper_set and a.minimum_tamper_set and \
                b.minimum_tamper_set > a.minimum_tamper_set:
            print("The pre-registered hypothesis - minimum tamper set 1 in all")
            print("three arms - is REFUTED. The configured-workflow arm needs")
            print(f"{b.minimum_tamper_set} edits, because what a step names and")
            print("what its credential may reach are separate records and both")
            print("must permit.")
        print()
        print("Equivalence held:", equivalent)
    raise SystemExit(0)
