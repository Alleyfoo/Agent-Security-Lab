# Adversarial tests

One test module per case, named `test_case_NN_<slug>.py`.

Each module must contain, at minimum:

* a test that demonstrates the **attack succeeding** against the code as it
  stood before the control (marked `xfail(strict=True)` once the control lands,
  so the suite fails loudly if the control silently regresses); and
* a test that demonstrates the **attack failing for a specific, observable
  reason** — assert on the denial reason, not merely that an exception was
  raised.

Tests here are allowed to reach past private attributes (`_store`,
`_artifacts`, `_receipts`). That is the point: they model an adversary who is
inside the process, and the reach-around is the thing under measurement.
