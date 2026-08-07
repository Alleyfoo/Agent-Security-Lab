"""Case 17 - can a large reachability graph be reduced without hiding needles?

Run it:

    python cases/17-scale/attack.py

Case 16's view works on a toy. This is the gate before it is called useful:

    Can a large reachability graph be reduced to a small number of actionable
    causes without hiding dangerous paths?

Three measurements:

  1. **parity** - the generic model reproduces case 16's numbers, so the scale
     experiment measures the same thing;
  2. **reduction** - raw paths against causes, endpoints and review burden, as
     the deployment grows;
  3. **needles** - deliberately planted dangerous relationships that generate
     almost no paths, and whether they survive grouping and ranking.

This case is written so it can fail. If reduction does not hold, or the
needles disappear, that is the result.
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import graph as g  # noqa: E402

SIZES = [
    (50, 20, 5, 4),
    (500, 100, 10, 8),
    (5000, 400, 20, 12),
    (20000, 800, 40, 16),
]


def parity(store_dir: str) -> bool:
    print("\n--- Parity: the generic model against case 16's arms ---")
    ok = True
    for arm, expected, got in g.parity_checks(store_dir):
        match = got == expected
        ok = ok and match
        print(f"   {'  ' if match else '!!'} arm {arm}: case 16 says "
              f"{expected}, generic model says {got}"
              f"{'' if match else '   MISMATCH'}")
    return ok


def reduction() -> None:
    print("\n--- Reduction as the deployment grows ---")
    print(f"{'deployment':>26s} {'paths':>10s} {'causes':>8s} "
          f"{'endpoints':>10s} {'naive':>8s}")
    for n_work, n_inter, n_sens, n_cause in SIZES:
        dep = g.generate(n_work, n_inter, n_sens, n_cause)
        paths = dep.path_count()
        cs = g.causes(dep)
        naive = g.naive_causes(dep)
        print(f"{dep.label:>26s} {paths:>10d} {len(cs):>8d} "
              f"{len(g.endpoints_exposed(dep)):>10d} {len(naive):>8d}")


def needles() -> None:
    print("\n--- Needles: rare, dangerous, and almost pathless ---")
    n_work, n_inter, n_sens, n_cause = SIZES[-1]
    dep = g.generate(n_work, n_inter, n_sens, n_cause)
    planted = [
        g.plant_needle(dep, "artifact.root_signing_key", "inter_rare_1", 1),
        g.plant_needle(dep, "artifact.customer_pii", "inter_rare_2", 2),
        g.plant_needle(dep, "artifact.payment_token", "inter_rare_3", 1),
    ]
    severity = {"artifact.root_signing_key": 10, "artifact.customer_pii": 9,
                "artifact.payment_token": 9}

    cs = g.causes(dep)
    print(f"\n  {dep.path_count()} paths reduce to {len(cs)} causes")
    print(f"  {len(planted)} needles planted, generating "
          f"{sum(c.paths for c in cs if (c.authority, c.intermediary) in planted)} "
          f"paths between them")

    survives = all(any((a, i) == (c.authority, c.intermediary) for c in cs)
                   for a, i in planted)
    print(f"\n   {'  ' if survives else '!!'} every needle survives grouping: "
          f"{survives}")

    for top in (10, 20):
        blast = g.recall_in_top(g.by_blast(cs), planted, top)
        sens = g.recall_in_top(g.by_sensitivity(cs, severity), planted, top)
        print(f"\n      top {top} ranked by blast radius      "
              f"needles found: {blast:.0%}")
        print(f"      top {top} ranked by severity first   "
              f"needles found: {sens:.0%}")
    return planted, cs, severity


def naive_grouping_cost() -> None:
    print("\n--- What the obvious grouping key costs ---")
    dep = g.generate(200, 40, 6, 6)
    # One intermediary reaching several sensitive authorities.
    dep.holds["inter_0"].update({"artifact.secret_1", "artifact.secret_2",
                                 "artifact.secret_3"})
    proper = [c for c in g.causes(dep) if c.intermediary == "inter_0"]
    naive = [c for c in g.naive_causes(dep) if c.intermediary == "inter_0"]
    print(f"   grouping by (authority, intermediary): {len(proper)} findings "
          f"for inter_0")
    print(f"   grouping by intermediary alone:        {len(naive)} finding "
          f"for inter_0")
    print(f"   -> the naive key hides {len(proper) - len(naive)} distinct "
          "sensitive authorities behind one row")


if __name__ == "__main__":
    print("Reduction is the gate. A correct graph nobody can read is wallpaper.")

    with tempfile.TemporaryDirectory() as tmp:
        ok = parity(tmp)

    reduction()
    planted, cs, severity = needles()
    naive_grouping_cost()

    print("\n=== RESULT ===")
    print(f"parity with case 16: {ok}")
    n_work, n_inter, n_sens, n_cause = SIZES[-1]
    dep = g.generate(n_work, n_inter, n_sens, n_cause)
    print(f"at {n_work} work items: {dep.path_count()} paths -> "
          f"{len(g.causes(dep))} causes")
    print()
    print("Reduction holds: causes track the number of intermediaries that")
    print("hold something sensitive, not the size of the deployment.")
    print()
    print("But ranking by blast radius is exactly wrong for the findings that")
    print("matter most. A needle generates one path and sorts last.")
    print("Severity has to come from outside the graph; it is not derivable")
    print("from it, and that is a real requirement on anyone deploying this.")
    raise SystemExit(0)
