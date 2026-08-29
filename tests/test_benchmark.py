from secure_rag.benchmark.scoring import wilson_interval, score_case
from secure_rag.benchmark.adapters import build_authinject_cases
from secure_rag.benchmark.runner import CONFIGS


def test_wilson_and_case_schema():
    lo, hi = wilson_interval(0, 10)
    assert lo == 0.0
    assert hi > 0
    cases = build_authinject_cases()
    assert len(cases) > 50
    row = score_case(cases[0], {"answer": "CANARY_OVERRIDE_7F3", "retrieved": [], "diagnostics": {}})
    assert row["xpia_success"] == 1
    assert CONFIGS["C0_ungated"]["agentic"] is False
    assert CONFIGS["C7_agentic_undefended"]["agentic"] is True
    assert CONFIGS["C5_combined"]["action_authz"] is False
    assert CONFIGS["C6_action_authz"]["action_authz"] is True
