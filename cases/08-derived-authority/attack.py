"""Case 08 - the comparative measurement.

Run it:

    python cases/08-derived-authority/attack.py

Two authority models, one legitimate task, two named unauthorized
capabilities. For each arm, every stored authority-bearing record is attacked
**independently**, with the smallest single edit that could obtain the target.
Combinations are tried only where no single edit succeeds.

The minimum tamper set is a measurement here, not an acceptance condition. Any
of the four conclusions in README.md is a permitted outcome, including "no
meaningful advantage".

Exit code is 0 whatever the comparison finds. A comparison has no pass/fail;
it fails only if the harness itself is broken.
"""

from __future__ import annotations

import itertools
import os
import sys
import tempfile
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

import arm_a  # noqa: E402
import arm_b  # noqa: E402
from common import AuthorizationError  # noqa: E402

# The legitimate task: infer a schema from the ingested table, at the step
# immediately after intake. Both arms face exactly this.
STAGE = "schema"
GRANTED = "artifact.raw_input"

# Present at this workflow position, in both arms.
PRESENT_KEYS = [GRANTED, "artifact.key_material"]

# The two named unauthorized capabilities.
C1 = ("C1 future artifact", "artifact.cleaned_output")
C2 = ("C2 existing unrelated", "artifact.key_material")
CAPABILITIES = [C1, C2]


@dataclass
class Outcome:
    arm: str
    surfaces: str
    capability: str
    obtained: bool
    grant: str
    detail: str


def _fresh_object(store_dir: str) -> arm_b.WorkObject:
    """The same artifacts arm A's store holds at this position."""
    obj = arm_b.WorkObject(
        object_id="obj_812", object_type="orders_table", state="ingested",
        artifacts={arm_b.T_TABLE_PREVIEW: GRANTED,
                   arm_b.T_KEY_MATERIAL: "artifact.key_material"},
    )
    arm_b.save_object(obj, store_dir)
    return obj


def _try_arm_a(mutations: List[str], target: str) -> Outcome:
    arm_a.reset()
    details = [arm_a.MUTATIONS[s](target) for s in mutations]
    try:
        grant = arm_a.resolve(STAGE, PRESENT_KEYS)
        obtained = grant.permits_read(target)
        described = grant.describe()
    except AuthorizationError as exc:
        obtained, described = False, f"refused: {exc}"
    return Outcome(arm_a.NAME, " + ".join(mutations) or "none",
                   target, obtained, described, "; ".join(details) or "-")


def _try_arm_b(mutations: List[str], target: str, store_dir: str) -> Outcome:
    arm_b.reset()
    obj = _fresh_object(store_dir)
    details = [arm_b.MUTATIONS[s](obj, target) for s in mutations]
    # Persist the tampering. The attacker alters records before execution, so
    # an edit that never reached the store would not be the attack this case
    # defines - and the reload below would silently discard it.
    arm_b.save_object(obj, store_dir)

    # The queue item is generated from the object *after* any pre-execution
    # tampering, which is what this case's attacker is allowed to do. Naming
    # the queue record as a surface then means rewriting the item itself.
    try:
        proposed = arm_b.required_skill(obj)
    except AuthorizationError as exc:
        return Outcome(arm_b.NAME, " + ".join(mutations), target, False,
                       f"refused: {exc}", "; ".join(details))
    if "ready-work or queue record" in mutations:
        proposed = "validate_chain"
    item = arm_b.QueueItem(object_id=obj.object_id, skill=proposed)

    # Reloaded from disk, so a persisted edit is what actually gets evaluated.
    reloaded = arm_b.load_object(obj.object_id, store_dir)
    try:
        grant = arm_b.resolve(item, reloaded)
        obtained = grant.permits_read(target)
        described = grant.describe()
    except AuthorizationError as exc:
        obtained, described = False, f"refused: {exc}"
    return Outcome(arm_b.NAME, " + ".join(mutations), target, obtained,
                   described, "; ".join(details))


def _baseline(store_dir: str) -> None:
    print("\n=== The legitimate task, untampered ===")
    a = _try_arm_a([], GRANTED)
    print(f"  arm A  {a.grant}")
    b = _try_arm_b([], GRANTED, store_dir)
    print(f"  arm B  {b.grant}")
    for label, outcome in (("A", a), ("B", b)):
        assert outcome.obtained, (
            f"arm {label} cannot perform the legitimate task; the comparison "
            "is void"
        )
    for name, target in CAPABILITIES:
        for label, fn in (("A", lambda t: _try_arm_a([], t)),
                          ("B", lambda t: _try_arm_b([], t, store_dir))):
            assert not fn(target).obtained, (
                f"arm {label} grants {target} with no tampering at all"
            )
    print("  both arms perform the task, and neither grants either target"
          " untampered.")


def _single_mutations(store_dir: str) -> List[Outcome]:
    print("\n=== Single mutations, each surface independently ===")
    results: List[Outcome] = []
    for arm, surfaces, runner in (
        (arm_a.NAME, arm_a.surfaces(), lambda m, t: _try_arm_a(m, t)),
        (arm_b.NAME, arm_b.surfaces(), lambda m, t: _try_arm_b(m, t, store_dir)),
    ):
        print(f"\n  {arm}   ({len(surfaces)} stored authority-bearing record"
              f"{'s' if len(surfaces) != 1 else ''})")
        for surface in surfaces:
            for name, target in CAPABILITIES:
                outcome = runner([surface], target)
                results.append(outcome)
                mark = "!!" if outcome.obtained else "  "
                print(f"   {mark} {surface:30s} {name:24s} "
                      f"{'OBTAINED' if outcome.obtained else 'no'}")
                if outcome.obtained:
                    print(f"        grant: {outcome.grant}")
    return results


def _combinations(store_dir: str, results: List[Outcome]) -> List[Outcome]:
    print("\n=== Combinations, only where no single edit succeeded ===")
    extra: List[Outcome] = []
    for arm, surfaces, runner in (
        (arm_a.NAME, arm_a.surfaces(), lambda m, t: _try_arm_a(m, t)),
        (arm_b.NAME, arm_b.surfaces(), lambda m, t: _try_arm_b(m, t, store_dir)),
    ):
        for name, target in CAPABILITIES:
            if any(o.obtained and o.arm == arm and o.capability == target
                   for o in results):
                continue
            found = False
            for pair in itertools.combinations(surfaces, 2):
                outcome = runner(list(pair), target)
                extra.append(outcome)
                if outcome.obtained:
                    print(f"   !! {arm}")
                    print(f"      {name} obtained by {outcome.surfaces}")
                    print(f"      grant: {outcome.grant}")
                    found = True
                    break
            if not found:
                print(f"      {arm}: {name} not obtained by any pair either")
    return extra


def _minimum_tamper_set(arm: str, target: str, all_results: List[Outcome]):
    hits = [o for o in all_results
            if o.arm == arm and o.capability == target and o.obtained]
    if not hits:
        return None, None
    best = min(hits, key=lambda o: len(o.surfaces.split(" + ")))
    return len(best.surfaces.split(" + ")), best


def _report(all_results: List[Outcome]) -> None:
    print("\n=== Minimum tamper set ===")
    for arm in (arm_a.NAME, arm_b.NAME):
        print(f"\n  {arm}")
        for name, target in CAPABILITIES:
            size, best = _minimum_tamper_set(arm, target, all_results)
            if size is None:
                print(f"    {name:24s} not obtained (single or pair)")
                continue
            scopes = arm_a.SCOPES if arm == arm_a.NAME else arm_b.SCOPES
            detection = arm_a.DETECTION if arm == arm_a.NAME else arm_b.DETECTION
            surface = best.surfaces.split(" + ")[0]
            print(f"    {name:24s} {size}  via {best.surfaces}")
            print(f"      authority : {best.grant}")
            print(f"      scope     : {scopes[surface]}")
            print(f"      detected  : {detection[surface]}")


if __name__ == "__main__":
    print("Stored per-stage grant versus grant derived at use time.")
    print("The minimum tamper set is measured here, not prescribed.")

    with tempfile.TemporaryDirectory() as tmp:
        _baseline(tmp)
        results = _single_mutations(tmp)
        results += _combinations(tmp, results)
        _report(results)

    print("\nA comparison has no pass/fail. See the case README for which of")
    print("the four permitted conclusions the numbers support.")
    raise SystemExit(0)
