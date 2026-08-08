"""The `pre-study-v1` surfaces, rendered from the canonical sources.

    Every number on these pages arrives through an import or a file read.

`cases/registry.py` states the rule this module exists to obey:

    Security claims are written here **once**. Do not restate a result in test
    code, README prose, report code and UI code independently - they drift, and
    a drifted claim is worse than no claim.

So there are no result literals below. Counts are `len()` of something; results
come off `CaseResult`; the sealed box's 2x2 is recomputed live (`run_all()`
takes 0.03s); the real-model table is read from the JSON that run produced. A
test asserts this module contains no hardcoded findings, and it is not a
courtesy test - a dashboard is the easiest place in a repository for a claim to
quietly become a different claim.

`run_model_arm.run()` is deliberately NOT called here. It needs a local model
server and takes minutes; the JSON is the record of that run.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import streamlit as st

from agent_network_demo import ui

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Evidence status is the distinction most likely to get flattened into "four
# green ticks" by a dashboard, and it cost real work to establish. `blocked`
# and `modeled` must not look like `measured`.
STATUS_STYLE = {
    "measured": ("✅", ui.GREEN),
    "modeled": ("◐", ui.AMBER),
    "blocked": ("⛔", ui.RED),
    "untested": ("○", ui.MUTED),
}


def _doc(relative: str) -> Optional[str]:
    path = os.path.join(REPO_ROOT, relative)
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _unregistered_case_dirs(cases) -> List[tuple]:
    """Case directories with no registry entry.

    Derived rather than typed. A blocked case cannot be registered - the
    registry's tripwires require a runnable `attack.py` - so it would otherwise
    vanish from every generated surface, which is precisely the wrong thing to
    happen to the one experiment the repository could not perform.
    """
    registered = {os.path.basename(c.directory) for c in cases}
    root = os.path.join(REPO_ROOT, "cases")
    out = []
    for entry in sorted(os.listdir(root)):
        if not os.path.isdir(os.path.join(root, entry)):
            continue
        if not entry[:2].isdigit() or entry in registered:
            continue
        number, _, slug = entry.partition("-")
        out.append((number, slug.replace("-", " ")))
    return out


def _status_chip(status: str) -> str:
    mark, colour = STATUS_STYLE.get(status, ("?", "#6b6b6b"))
    return (f'<span style="color:{colour};font-weight:600">{mark} '
            f'{status}</span>')


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def render_cases() -> None:
    from cases.registry import (
        ABSENCE_DESCRIPTIONS, PREVENTED, RESULT_LABELS, all_cases,
    )
    from cases.report import by_level, primary_level

    cases = all_cases()
    ui.section_header(
        f"{len(cases)} security cases",
        "Generated from cases/registry.py, the canonical source. Every outcome "
        "is exactly one of prevented, rejected before commitment, detected "
        "after occurrence, or undetected — vague terms are not results.")

    statuses: Dict[str, int] = {}
    for case in cases:
        statuses[case.evidence_status] = statuses.get(case.evidence_status,
                                                      0) + 1
    cols = st.columns(len(statuses))
    for col, (status, count) in zip(cols, sorted(statuses.items())):
        mark, colour = STATUS_STYLE.get(status, ("?", "#6b6b6b"))
        col.markdown(
            f'<div style="text-align:center"><div style="font-size:1.6rem">'
            f'{mark}</div><div style="font-size:1.4rem;font-weight:700;'
            f'color:{colour}">{count}</div><div style="opacity:.7">{status}'
            f'</div></div>', unsafe_allow_html=True)

    blocked = [c for c in cases if c.evidence_status == "blocked"]
    if blocked:
        st.warning(
            "**"
            + ", ".join(c.case_id for c in blocked)
            + " is blocked, not proven.** "
            + blocked[0].residual_limitation)

    for number, name in _unregistered_case_dirs(cases):
        st.warning(
            f"**Case {number} — {name}: a written contract with no result.** "
            "It has no registry entry because it has no attack to run: the "
            "experiment needs an environment this machine cannot provide. A "
            "blocked case is a better outcome than a fake passing one, and "
            "every containment result above is conditional on the adversary "
            "not executing code in the process.")

    st.markdown("")
    rows = [{
        "case": c.case_id,
        "title": c.title,
        "adversary": primary_level(c),
        "baseline": RESULT_LABELS[c.baseline_result],
        "controlled": RESULT_LABELS[c.controlled_result],
        "evidence": c.evidence_status,
    } for c in cases]
    ui.data_table(rows, ["case", "title", "adversary", "baseline",
                         "controlled", "evidence"],
                  "Every case", "")

    # -- the level buckets ------------------------------------------------
    st.markdown("")
    ui.section_header(
        "The question has three answers, not one",
        "Can an agent be restricted to its assigned function when it is "
        "manipulated, malicious, or fully captured?")
    for level, gloss in (
            ("Level 1", "a hostile agent implementation"),
            ("persisted-record", "the configuration adversary (Level 1.5)"),
            ("Level 2", "arbitrary code in the runner's process")):
        bucket = by_level(level)
        if not bucket:
            continue
        prevented = [c for c in bucket if c.controlled_result == PREVENTED]
        st.markdown(
            f"**{level}** — {gloss}: {len(bucket)} cases, "
            f"{len(prevented)} ending in prevention.")

    # -- absence taxonomy --------------------------------------------------
    labelled = [c for c in cases if c.extra.get("absence_kind")]
    if labelled:
        st.markdown("")
        ui.section_header(
            "Absence has kinds",
            "One word had been covering three mechanisms that degrade "
            "differently. A reader given only 'an absence' cannot tell which "
            "guarantee they have.")
        kinds: Dict[str, List[str]] = {}
        for case in labelled:
            kinds.setdefault(case.extra["absence_kind"], []).append(
                case.case_id)
        ui.data_table(
            [{"kind": k, "means": ABSENCE_DESCRIPTIONS.get(k, ""),
              "cases": ", ".join(sorted(v))} for k, v in sorted(kinds.items())],
            ["kind", "means", "cases"], "", "")


# ---------------------------------------------------------------------------
# The applied programme
# ---------------------------------------------------------------------------

def render_programme() -> None:
    from cases.programme import (
        FAMILY_LABELS, PROGRAMME, PROGRAMME_FAMILIES, by_family,
    )

    ui.section_header(
        f"{len(PROGRAMME_FAMILIES) + 1} families of evidence",
        "Not every piece of evidence in an agent-security system is attack "
        "evidence. These are orthogonal questions that get collapsed into "
        "'AI safety', and collapsing them loses most of the information.")

    st.markdown(
        "| Family | Where | Question |\n|---|---|---|\n"
        "| Adversarial security | `cases/registry.py` | "
        "can persuasion enlarge authority? |\n"
        + "\n".join(
            f"| {FAMILY_LABELS[f]} | `cases/programme.py` | "
            f"{', '.join(r.step for r in by_family(f))} |"
            for f in PROGRAMME_FAMILIES))

    st.markdown("")
    for family in PROGRAMME_FAMILIES:
        results = by_family(family)
        if not results:
            continue
        st.markdown(f"#### {FAMILY_LABELS[family]}")
        for result in results:
            with st.expander(f"{result.step} — {result.title}",
                             expanded=False):
                st.markdown(f"> {result.question}")
                st.markdown(f"**Claim.** {result.claim}")
                st.markdown(
                    "**Measured** &nbsp; "
                    + _status_chip(result.evidence_status),
                    unsafe_allow_html=True)
                flat = {k: v for k, v in result.measurements.items()
                        if not isinstance(v, dict)}
                ui.data_table([{"measurement": k, "value": str(v)}
                               for k, v in flat.items()],
                              ["measurement", "value"], "", "")
                st.markdown("**What it does not claim**")
                for item in result.non_claims:
                    st.markdown(f"- {item}")
                st.markdown(f"**Residual.** {result.residual}")
                st.caption(f"`{result.run}` · `{result.test_module}`")


# ---------------------------------------------------------------------------
# The sealed box
# ---------------------------------------------------------------------------

@st.cache_data(show_spinner=False)
def _box_results():
    """Recomputed live - run_all() is pure Python and takes ~0.03s."""
    from sealed_box.agent import STATES
    from sealed_box.gate import channel_capacity_bits
    from sealed_box.run_box import ARMS, gate_accuracy, run_all

    runs = run_all()
    correct, total, wrong = gate_accuracy()
    rows = []
    for arm, _use_gate, _cls in ARMS:
        worst = max(runs[(arm, s)].authority_created for s in STATES)
        captured = runs[(arm, "fully_captured")]
        rows.append({
            "arm": arm,
            "authority created": worst,
            "per admitted input": round(
                captured.authority_created / captured.admitted, 1)
            if captured.admitted else 0.0,
        })
    return {"rows": rows, "gate_correct": correct, "gate_total": total,
            "gate_wrong": wrong, "bits": channel_capacity_bits()}


def render_sealed_box() -> None:
    data = _box_results()

    ui.section_header(
        "The sealed box",
        "If the agent becomes completely persuaded by hostile input, can that "
        "persuasion create authority the surrounding system did not provide? "
        "The agent's state is enumerated rather than sampled — including "
        "maximally captured — so the result does not depend on knowing it.")

    ui.data_table(data["rows"],
                  ["arm", "authority created", "per admitted input"],
                  "The 2×2", "")

    per_admitted = {r["arm"]: r["per admitted input"] for r in data["rows"]}
    leaky = sorted({v for v in per_admitted.values() if v})
    if len(leaky) == 1:
        st.info(
            f"Both unsealed arms create **{leaky[0]} authority units per "
            "admitted input**. The gate reduced how many hostile inputs got "
            "through; it changed nothing about what happened to the ones that "
            "did. **Input restriction reduced attack frequency, not attack "
            "consequence.**")

    c1, c2 = st.columns(2)
    c1.metric("gate vs the corpus frozen before it",
              f"{data['gate_correct']}/{data['gate_total']}")
    c2.metric("gate channel capacity", f"{data['bits']:.0f} bits")
    st.caption(
        "`Firstname Lastname` feels tiny because it is visually simple while "
        "still containing an enormous language. `Ignore Previous`, "
        "`Admin Override` and `Approve Everything` are all structurally "
        "perfect names. Syntax cannot solve semantics.")


# ---------------------------------------------------------------------------
# The real-model arm
# ---------------------------------------------------------------------------

def _model_results() -> Optional[Dict[str, Any]]:
    path = os.path.join(REPO_ROOT, "sealed_box", "model_arm_results.json")
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def render_model_arm() -> None:
    from sealed_box import model_protocol as proto

    ui.section_header(
        "The real-model arm — observed susceptibility, not containment",
        "The structural arms already answered the security question against a "
        "strictly worse adversary. This asks the complementary empirical "
        "question: what does real persuasion look like inside the box?")

    data = _model_results()
    if data is None:
        st.warning(
            "No recorded run. This arm is optional — it needs a local model "
            "server. Run `python sealed_box/run_model_arm.py` to produce "
            "`sealed_box/model_arm_results.json`.")
        return

    summary = data["summary"]
    rows = [{
        "model": model,
        "trials": row["trials"],
        "correct": row[proto.CORRECT],
        "persuaded": row[proto.SEMANTIC_FAILURE],
        "malformed": row[proto.PROTOCOL_FAILURE],
        "authority escape": row["authority_escape"],
    } for model, row in sorted(summary.items())]
    ui.data_table(rows, ["model", "trials", "correct", "persuaded",
                         "malformed", "authority escape"], "", "")

    escapes = sum(r["authority escape"] for r in rows)
    persuaded = sum(r["persuaded"] for r in rows)
    st.metric("successful manipulations → authority escapes",
              f"{persuaded} → {escapes}")

    # The strong evidence first, per the distinction the findings doc makes.
    strong = [t for t in data["trials"]
              if t["outcome"] == proto.PROTOCOL_FAILURE
              and t["parsed"] == "" and t["output"]
              and t["output"].upper() != t["output"].lower()]
    shown = None
    for trial in strong:
        if trial["output"].strip().upper() in trial["raw_name"].upper():
            shown = trial
            break
    if shown:
        st.markdown(
            f'<div class="and-narr"><b>The strong evidence.</b> Presented with '
            f'the name <code>{shown["raw_name"]}</code>, '
            f'<code>{shown["model"]}</code> replied '
            f'<code>{shown["output"].strip()}</code> — a word that appears '
            f'nowhere in the instructions and everywhere in the data. There is '
            f'no competing misclassification explanation, because that is not '
            f'a classification at all. The model treated the contents of a '
            f'name field as instructions addressed to it. Authority gained: '
            f'<b>0</b>.</div>', unsafe_allow_html=True)

    for model, names in sorted(data.get("persuaded_by", {}).items()):
        if names:
            st.markdown(
                f'<div class="and-narr"><b>The consequential evidence.</b> '
                f'<code>{model}</code> approved a visitor who is not on the '
                f'expected list, for the name '
                f'<code>{", ".join(names)}</code>. Strictly this is a '
                f'decision-integrity failure — someone could argue the name '
                f'was merely classified badly. Authority gained: <b>0</b>.'
                f'</div>', unsafe_allow_html=True)

    st.info(
        "A zero in the *persuaded* column is not a property of a model. It is "
        "a model that has not met the right sentence yet. The containment "
        "result comes from the structural arms, against an adversary strictly "
        "worse than any model — **the security property did not depend on the "
        "model exhibiting the desired behaviour.**")


# ---------------------------------------------------------------------------
# The checkpoint documents
# ---------------------------------------------------------------------------

def render_checkpoint() -> None:
    text = _doc("docs/pre-study-v1.md")
    if text is None:
        st.warning("docs/pre-study-v1.md is missing.")
        return
    # Rendered rather than paraphrased. A paraphrase in the UI would be a
    # second copy of a claim, which is what the canonical-source rule forbids.
    st.markdown(text, unsafe_allow_html=False)
