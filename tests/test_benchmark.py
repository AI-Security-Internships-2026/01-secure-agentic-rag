from secure_rag.benchmark.scoring import wilson_interval, score_case
from secure_rag.benchmark.adapters import build_authinject_cases


def test_wilson_and_case_schema():
    lo, hi = wilson_interval(0, 10)
    assert lo == 0.0
    assert hi > 0
    cases = build_authinject_cases()
    assert len(cases) > 50
    row = score_case(cases[0], {"answer": "CANARY_OVERRIDE_7F3", "retrieved": [], "diagnostics": {}})
    assert row["xpia_success"] == 1
