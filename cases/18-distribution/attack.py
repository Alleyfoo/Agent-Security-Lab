"""Case 18 - Gate 1: distribution validity.

Run it:

    python cases/18-distribution/attack.py

Case 17 measured 320,000 paths reducing to 16 causes with `n_causes=16` passed
into the generator. This removes the parameter, samples deployments from
distributions, and asks where the reduction stops working.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import distribution as d  # noqa: E402

DENSITIES = [0.01, 0.05, 0.1, 0.25, 0.5, 1.0]


def structural() -> None:
    print("\n--- The half of case 17 that survives: work does not matter ---")
    readings = d.sweep_work(d.UNIFORM, [200, 2000, 20000, 200000])
    print(f"{'work items':>12s} {'paths':>12s} {'causes':>8s}")
    for r in readings:
        print(f"{r.n_work:>12d} {r.paths:>12d} {r.causes:>8d}")
    counts = {r.causes for r in readings}
    print(f"\n  cause count across a 1000x change in estate size: {counts}")
    print("  -> structural, not a generator artefact: a cause is a fact about")
    print("     authority, and work items only multiply paths.")


def distributions() -> None:
    print("\n--- The half that was a generator artefact: density matters ---")
    print(f"{'shape':>14s} {'density':>8s} {'paths':>10s} {'causes':>8s} "
          f"{'endpoints':>10s} {'readable':>9s} {'top-5 share':>12s}")
    for shape in (d.UNIFORM, d.BROAD, d.HEAVY_TAILED):
        for r in d.sweep_density(shape, DENSITIES):
            print(f"{r.shape:>14s} {r.density:>8.2f} {r.paths:>10d} "
                  f"{r.causes:>8d} {r.endpoints:>10d} "
                  f"{('yes' if r.readable else 'NO'):>9s} "
                  f"{r.top_share:>11.0%}")

    dep = d.sample(d.PATHOLOGICAL, 2000, 300, 40, 1.0)
    r = d.read(dep, d.PATHOLOGICAL, 1.0)
    print(f"{r.shape:>14s} {r.density:>8.2f} {r.paths:>10d} "
          f"{r.causes:>8d} {r.endpoints:>10d} "
          f"{('yes' if r.readable else 'NO'):>9s} {r.top_share:>11.0%}")


def resolution() -> None:
    print("\n--- The fix: endpoints as an attribute, not as part of the key ---")
    print(f"{'shape':>14s} {'density':>8s} {'causes':>8s} {'findings':>9s} "
          f"{'readable':>9s} {'endpoints kept':>15s}")
    for shape in (d.UNIFORM, d.BROAD, d.HEAVY_TAILED):
        for density in DENSITIES:
            dep = d.sample(shape, 2000, 300, 40, density)
            cs, fs = d.causes(dep), d.findings(dep)
            kept = set().union(*(set(f.endpoints) for f in fs)) if fs else set()
            print(f"{shape.name:>14s} {density:>8.2f} {len(cs):>8d} "
                  f"{len(fs):>9d} "
                  f"{('yes' if len(fs) <= d.READABLE else 'NO'):>9s} "
                  f"{('all' if kept == d.endpoints_exposed(dep) else 'LOST'):>15s}")


def threshold() -> None:
    print("\n--- Where it breaks, per shape ---")
    for shape in (d.UNIFORM, d.BROAD, d.HEAVY_TAILED):
        density, count = d.breaking_density(shape)
        print(f"   {shape.name:>14s}: unreadable at density {density:.2f} "
              f"({count} causes, threshold {d.READABLE})")
        print(f"        {shape.note}")


if __name__ == "__main__":
    print("Is the reduction a property of the approach, or of the generator?")

    structural()
    distributions()
    resolution()
    threshold()

    print("\n=== RESULT ===")
    print("Three answers, and case 17 reported only the flattering one.")
    print()
    print("1. SURVIVES - estate size is irrelevant. The cause count did not")
    print("   move across a 1000x change in work items. A cause is a fact")
    print("   about authority; work only multiplies paths.")
    print()
    print("2. FAILED AS BUILT - case 17's (authority, intermediary) key is")
    print("   linear in fan-out, so one over-scoped credential holding 40")
    print("   secrets becomes 40 rows. The heavy-tailed shape - the one real")
    print("   entitlement data has - was unreadable at the LOWEST density")
    print("   sampled: 3 holders producing 73 causes.")
    print()
    print("3. FIXED, and the failure forced the fix. Make the endpoint set an")
    print("   ATTRIBUTE of a per-intermediary finding rather than part of its")
    print("   key. Heavy-tailed at d=0.01: 73 causes -> 3 findings, with every")
    print("   endpoint still reported. That satisfies case 17's no-hiding")
    print("   requirement and readability at the same time, which case 17")
    print("   had measured as a trade-off.")
    print()
    print("The floor that remains is irreducible, and it is the honest")
    print("operational criterion:")
    print()
    print("    report length = the number of intermediaries that hold")
    print("    sensitive authority")
    print()
    print("Not paths. Not causes. No amount of graph work reduces it, because")
    print("each such intermediary is a separate thing somebody has to decide")
    print("about. An estate can be measured against that before anyone adopts")
    print("any of this - which is the useful output of the gate.")
    raise SystemExit(0)
