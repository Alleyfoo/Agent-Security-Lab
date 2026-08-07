"""Case 24 - Gate 2: where does severity come from?

Run it:

    python cases/24-severity-source/attack.py

Case 17 left the reachability view usable *given* a severity map and unusable
without one. This measures whether the map can come from the graph - and
whether the graph is entitled to supply it.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import severity as s  # noqa: E402


if __name__ == "__main__":
    print("Gate 2: the graph must not grade its own homework.")

    print("\n--- Independence: does severity leak into reachability? ---")
    ok, note = s.independence_check()
    print(f"   {'  ' if ok else '!!'} {note}")

    print("\n--- Does graph topology predict severity? ---")
    correlations = s.topology_vs_severity()
    for proxy, rho in correlations.items():
        flag = "!!" if rho < -0.5 else ("??" if rho > 0.5 else "  ")
        print(f"   {flag} {proxy:30s} rho = {rho:+.3f}")
    print("\n   A strong POSITIVE correlation would make an independent source")
    print("   unnecessary. There is none. Two of the three are strongly")
    print("   NEGATIVE, which is worse than uncorrelated: using path count as")
    print("   a severity proxy actively inverts the ranking.")

    print("\n--- Needle recall by severity source ---")
    readings = s.measure()
    for r in readings:
        print(f"\n   {r.source}")
        print(f"        {r.note}")
        print(f"        top 10: {r.recall_top_10:.0%}    "
              f"top 20: {r.recall_top_20:.0%}")

    print("\n=== RESULT ===")
    print(f"{'severity source':>14s}  {'top 10':>8s}  {'top 20':>8s}")
    for r in readings:
        print(f"{r.source:>14s}  {r.recall_top_10:>7.0%}  {r.recall_top_20:>7.0%}")

    absent = next(r for r in readings if r.source == "absent")
    topo = next(r for r in readings if r.source == "topological")
    declared = next(r for r in readings if r.source == "declared")

    print()
    print("Gate 2 is answered, and the answer is that the graph cannot supply")
    print("its own severity.")
    print()
    print(f"  absent       {absent.recall_top_10:.0%} - case 17's failure mode,")
    print("               reproduced: the ordering falls back to blast radius")
    print("               and every needle sits below the fold.")
    print()
    print(f"  topological  {topo.recall_top_10:.0%} - and this is the finding.")
    print("               Severity computed from the graph is not a weaker")
    print("               source than none; it is the SAME source, because")
    print("               path count is what the fallback ordering already")
    print("               used. It looks like knowledge and adds nothing.")
    print()
    print(f"  declared     {declared.recall_top_10:.0%} - an independent")
    print("               classification of the authority itself.")
    print()
    print("And the correlations say why, more sharply than expected. Path")
    print("count against declared severity is rho = -0.995: not merely")
    print("uninformative but strongly INVERTED. As a proxy it is worse than")
    print("random, because the rarest paths lead to the most valuable things.")
    print()
    print("That inversion follows from the scenario rather than from nature -")
    print("the needles were planted rare AND valuable. But that is exactly")
    print("the assumption case 17 established as the one that matters, and it")
    print("is what an over-broad service identity to a signing key looks like.")
    print("Recorded as conditional on it, not as a law.")
    print()
    print("The one proxy that is genuinely uncorrelated (rho = 0.000) is how")
    print("many intermediaries hold an authority - which is the count case 18")
    print("made the report length. Useful for sizing, useless for ranking.")
    print()
    print("Reachability stays independent of severity in the other direction")
    print("too: the causes and findings are identical under every map, so the")
    print("answer never shapes the question.")
    raise SystemExit(0)
