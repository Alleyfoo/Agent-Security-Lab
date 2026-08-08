"""`docs/design-philosophy.md` is a frozen pre-study document.

The note itself says "do not retrofit this with terminology learned later", and
this repository's whole thesis is that a rule written as a sentence asking
nicely is not a control. So the rule is enforced the same way every other rule
here is: structurally.

A prediction rewritten after the result is not a prediction. The value of that
document is entirely that it was written *before* formal study, and the only
way a later reader can trust that is if the text demonstrably has not moved.

**If this test fails**, do not update the digest to make it pass. Either revert
the edit, or - if the note genuinely needs to change - add a dated appendix in a
separate file that cites the original and says what turned out to be wrong. Then
this test still passes, because the frozen body did not move.
"""

from __future__ import annotations

import hashlib
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTE = os.path.join(REPO_ROOT, "docs", "design-philosophy.md")

# sha256 of the note with line endings normalised to \n.
FROZEN_DIGEST = "62a4dea8379b8317b04d5135b2db94c95e815b0f3887a41d06fe3b7dee57da7b"


def _body() -> str:
    with open(NOTE, "r", encoding="utf-8") as fh:
        return fh.read().replace("\r\n", "\n")


def test_the_pre_study_note_has_not_been_edited():
    digest = hashlib.sha256(_body().encode("utf-8")).hexdigest()
    assert digest == FROZEN_DIGEST, (
        "docs/design-philosophy.md changed. This is a FROZEN pre-study "
        "document and its value is that it was written before formal study. "
        "Do not update this digest - revert the edit, or add a dated appendix "
        "in a separate file that cites the original and records what turned "
        "out to be wrong."
    )


def test_the_note_still_declares_itself_frozen():
    """The banner is what tells a human reader the same thing the digest tells
    the test suite."""
    text = _body()
    assert "**Status: FROZEN, pre-study.**" in text
    assert "Do not retrofit this note with terminology learned later." in text


def test_the_note_does_not_yet_use_post_study_vocabulary():
    """A cheap tripwire for the specific failure the note is guarding against.

    None of these words appear in the pre-study text. If one shows up, either
    the note was retrofitted with borrowed terminology, or somebody rewrote it
    for style and quietly upgraded the vocabulary while they were there. Both
    destroy what the document is for.
    """
    text = _body().lower()
    borrowed = ("stride", "dread", "kill chain", "mitre", "att&ck",
                "confused deputy", "capability-based security",
                "reference monitor", "bell-lapadula", "biba",
                "defense in depth", "zero trust", "threat model")
    found = [term for term in borrowed if term in text]
    assert not found, (
        f"post-study vocabulary appeared in the frozen note: {found}. "
        "Compare against the note; do not edit the note into agreement."
    )
