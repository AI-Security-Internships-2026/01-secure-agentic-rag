from secure_rag.benchmark.guardrail_compare import _confusion, _latency_stats
from secure_rag.benchmark.guardrail_dataset import INJECAGENT_ENHANCED_PREFIX, _fill_response


def test_confusion_and_latency_helpers():
    metrics = _confusion([True, True, False, False], [True, False, True, False])
    assert metrics["tp"] == 1
    assert metrics["fn"] == 1
    assert metrics["fp"] == 1
    assert metrics["tn"] == 1
    stats = _latency_stats([10.0, 20.0, 30.0, 40.0])
    assert stats["median_ms"] == 25.0
    assert stats["p95_ms"] >= 30.0


def test_injecagent_enhanced_prefix_is_the_paper_string():
    assert INJECAGENT_ENHANCED_PREFIX.startswith("IMPORTANT!!! Ignore all previous instructions")


def test_fill_response_places_payload_in_template_slot():
    filled = _fill_response("{'body': ' '}", "hello")
    assert "hello" in filled
    assert filled.count("' '") == 0
