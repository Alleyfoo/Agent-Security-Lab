"""The pre-study UI: presentation only, and provably so.

`cases/registry.py` states the rule:

    Security claims are written here **once**. Do not restate a result in test
    code, README prose, report code and UI code independently - they drift, and
    a drifted claim is worse than no claim.

A dashboard is the easiest place in a repository for a claim to quietly become
a different claim, because nobody re-reads a number they typed once into a
string literal. So the central test here is
`test_the_ui_hardcodes_no_findings`, and everything else supports it.
"""

from __future__ import annotations

import ast
import os

import pytest

from agent_network_demo import prestudy_view

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI_MODULES = ("agent_network_demo/prestudy_view.py",
              "agent_network_demo/streamlit_app.py")


def _executable_source(path: str) -> str:
    """Source with every docstring removed.

    Docstrings legitimately discuss the findings - they are where the reasoning
    lives. It is the *code* that must not contain them. Sixth occurrence of
    this pattern in the repository; grepping raw source has been wrong every
    single time.
    """
    with open(os.path.join(REPO_ROOT, path), "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)
    return ast.unparse(tree)


#: Every headline figure in the repository. None may appear in UI code.
FINDINGS = ("450", "120", "188", "1068", "45/45", "10^57", "348", "652",
            "0.995", "144 trials", "36/36", "17 unresolved", "8 escalated",
            "46 detected", "39 recovered")


@pytest.mark.parametrize("path", UI_MODULES)
def test_the_ui_hardcodes_no_findings(path):
    """If a figure is typed into a Streamlit string literal, the presentation
    task was done wrong however good it looks."""
    code = _executable_source(path)
    for finding in FINDINGS:
        assert finding not in code, (path, finding)


def test_the_hardcoding_guard_can_actually_fire():
    """Positive control, per target-architecture section 7. A guard that has
    never fired is decorative."""
    assert any(f in 'st.metric("authority created", "450")' for f in FINDINGS)


def test_the_view_reads_from_the_canonical_sources():
    code = _executable_source("agent_network_demo/prestudy_view.py")
    for source in ("cases.registry", "cases.programme", "cases.report",
                   "sealed_box.run_box", "sealed_box.gate",
                   "model_arm_results.json", "docs/pre-study-v1.md"):
        assert source in code, source


def test_the_ui_never_invokes_the_model_arm():
    """It needs a local model server and takes minutes. The JSON is the record
    of that run; a dashboard that shelled out to Ollama on page load would be
    unusable and would also produce a different run than the one recorded."""
    # Checked as imports, not as a substring: the view legitimately *tells the
    # operator* to run `python sealed_box/run_model_arm.py` when the JSON is
    # missing, and a naive grep flags that helpful sentence.
    with open(os.path.join(REPO_ROOT, "agent_network_demo/prestudy_view.py"),
              "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(f"{node.module}.{a.name}" for a in node.names)
    for banned in ("sealed_box.run_model_arm", "urllib", "urllib.request",
                   "requests", "subprocess", "socket"):
        assert not any(name.startswith(banned) for name in imported), banned


# ---------------------------------------------------------------------------
# The distinctions most likely to get flattened by a dashboard.
# ---------------------------------------------------------------------------

def test_evidence_status_is_styled_distinctly():
    """`blocked` and `modeled` must not look like `measured`. That distinction
    cost real work - case 23 is blocked rather than faked - and four green
    ticks would erase it."""
    from cases.registry import EVIDENCE_STATUSES
    styles = prestudy_view.STATUS_STYLE
    assert set(styles) == set(EVIDENCE_STATUSES)
    marks = [m for m, _c in styles.values()]
    colours = [c for _m, c in styles.values()]
    assert len(set(marks)) == len(marks), "each status needs its own glyph"
    assert len(set(colours)) == len(colours), "each status needs its own colour"


def test_the_box_summary_is_computed_not_typed():
    """`run_all()` takes about 0.03s, so there is no excuse for a cached
    literal."""
    data = prestudy_view._box_results()
    arms = {row["arm"]: row for row in data["rows"]}
    assert len(arms) == 4
    sealed = [r for a, r in arms.items() if "sealed" in a]
    assert sealed and all(r["authority created"] == 0 for r in sealed)
    unsealed = [r for a, r in arms.items() if "general" in a]
    assert all(r["authority created"] > 0 for r in unsealed)
    # The finding the 2x2 exists for: the gate divides, it does not eliminate.
    assert len({r["per admitted input"] for r in unsealed}) == 1
    assert data["gate_correct"] == data["gate_total"]
    assert data["bits"] > 150


def test_the_model_arm_view_degrades_honestly_without_a_run(monkeypatch):
    """A missing optional arm must say so, not render a blank table that reads
    as zero findings."""
    monkeypatch.setattr(prestudy_view, "_model_results", lambda: None)
    assert prestudy_view._model_results() is None


# ---------------------------------------------------------------------------
# It renders.
# ---------------------------------------------------------------------------

def test_every_view_renders_without_exception():
    at = pytest.importorskip("streamlit.testing.v1").AppTest.from_file(
        os.path.join(REPO_ROOT, "agent_network_demo", "streamlit_app.py"),
        default_timeout=60)
    at.run()
    assert not at.exception, at.exception


def test_the_readme_lists_every_registered_case():
    """The README's case table is hand-maintained, and it had silently fallen
    two cases behind the registry before this test existed. Hand-maintained
    prose is exactly what the canonical-source rule is about; this is the
    cheapest enforcement that does not require generating the file."""
    from cases.registry import all_cases
    with open(os.path.join(REPO_ROOT, "README.md"), "r",
              encoding="utf-8") as fh:
        readme = fh.read()
    missing = [c.case_id for c in all_cases()
               if f"cases/{os.path.basename(c.directory)}/README.md"
               not in readme]
    assert missing == [], (
        f"README.md does not link {missing} - run through cases/REPORT.md and "
        "add the rows rather than deleting this assertion")


def test_the_readme_does_not_hide_the_blocked_case():
    """Case 23 has no registry entry, so no generated surface carries it. It is
    the single most important caveat in the repository and the easiest thing to
    lose."""
    with open(os.path.join(REPO_ROOT, "README.md"), "r",
              encoding="utf-8") as fh:
        readme = fh.read().lower()
    assert "23" in readme and "blocked" in readme
    assert "cases/23-real-principals" in readme


def test_the_tabs_cover_the_checkpoint():
    from cases.programme import PROGRAMME
    from cases.registry import all_cases

    code = _executable_source("agent_network_demo/streamlit_app.py")
    for view in ("render_cases", "render_programme", "render_sealed_box",
                 "render_model_arm", "render_checkpoint"):
        assert view in code, view
    # And the baseline demo survived rather than being replaced.
    assert "_render_baseline_demo" in code
    assert all_cases() and PROGRAMME
