import json
from pathlib import Path

from secure_rag.benchmark.adapters import build_authinject_cases
from secure_rag.benchmark.runner import CONFIGS
from secure_rag.benchmark.scoring import score_case, summarize, wilson_interval


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


def test_committed_results_cover_agent_loop_and_action_authz_delta():
    artifact = Path(__file__).parents[1] / "experiments" / "results" / "authinject_eval.json"
    report = json.loads(artifact.read_text(encoding="utf-8"))["report"]
    assert set(CONFIGS) <= set(report)
    assert report["C7_agentic_undefended"]["n"] > 0
    assert report["C8_agentic_combined"]["n"] > 0
    assert report["C5_combined"]["tool_action_asr"]["rate"] > 0
    assert report["C6_action_authz"]["tool_action_asr"]["rate"] == 0
    assert report["C8_agentic_combined"]["tool_action_asr"]["rate"] == 0


def test_tool_asr_uses_only_tool_attack_denominator():
    rows = [
        {"attack_family": "tool", "tool_action_asr": 1},
        {"attack_family": "tool", "tool_action_asr": 0},
        {"attack_family": "override", "tool_action_asr": 0},
    ]
    metric = summarize(rows)["tool_action_asr"]
    assert metric["count"] == 1
    assert metric["denominator"] == 2
    assert metric["rate"] == 0.5
