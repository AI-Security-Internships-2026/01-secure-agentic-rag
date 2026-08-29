"""Compare retrieved-context injection scanners on the same InjecAgent held-out set."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import socket
import statistics
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from secure_rag.agent.guardrails import heuristic_is_indirect_injection
from secure_rag.benchmark.guardrail_dataset import build_held_out_samples
from secure_rag.settings import get_settings

ROOT = Path(__file__).resolve().parents[3]


def _pkg_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _loopback_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in {"127.0.0.1", "localhost", "::1"}


def _hardware() -> dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "machine": platform.machine(),
    }


def _confusion(y_true: list[bool], y_pred: list[bool | None]) -> dict[str, Any]:
    paired = [(t, p) for t, p in zip(y_true, y_pred) if p is not None]
    tp = sum(1 for t, p in paired if t and p)
    fp = sum(1 for t, p in paired if not t and p)
    tn = sum(1 for t, p in paired if not t and not p)
    fn = sum(1 for t, p in paired if t and not p)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    n_neg = tp + fp + tn + fn
    n_benign = sum(1 for t, _ in paired if not t)
    n_attack = sum(1 for t, _ in paired if t)
    return {
        "n_scored": len(paired),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": (fp / n_benign) if n_benign else 0.0,
        "false_negative_rate": (fn / n_attack) if n_attack else 0.0,
    }


def _latency_stats(latencies: list[float]) -> dict[str, float]:
    if not latencies:
        return {"median_ms": 0.0, "p95_ms": 0.0, "throughput_per_s": 0.0}
    ordered = sorted(latencies)
    p95_idx = min(len(ordered) - 1, max(0, round(0.95 * (len(ordered) - 1))))
    total = sum(latencies) / 1000.0
    return {
        "median_ms": statistics.median(ordered),
        "p95_ms": ordered[p95_idx],
        "throughput_per_s": (len(latencies) / total) if total else 0.0,
    }


def _run_scanner(name: str, predict: Callable[[str], bool], samples: list[dict]) -> dict[str, Any]:
    y_true = [bool(s["label"]) for s in samples]
    y_pred: list[bool | None] = []
    latencies: list[float] = []
    failures: list[dict[str, str]] = []
    for sample in samples:
        started = time.perf_counter()
        try:
            predicted = bool(predict(sample["text"]))
            y_pred.append(predicted)
            latencies.append((time.perf_counter() - started) * 1000)
        except Exception as exc:
            y_pred.append(None)
            latencies.append((time.perf_counter() - started) * 1000)
            failures.append({"id": sample["id"], "error": f"{type(exc).__name__}: {exc}"})
    metrics = _confusion(y_true, y_pred)
    metrics.update(_latency_stats(latencies))
    metrics["execution_failures"] = len(failures)
    metrics["failure_examples"] = failures[:8]
    metrics["status"] = "executed" if metrics["n_scored"] else "failed"
    metrics["implementation"] = name
    return metrics


def _llm_guard_predict(threshold: float) -> Callable[[str], bool]:
    from llm_guard.input_scanners import PromptInjection
    from llm_guard.input_scanners.prompt_injection import MatchType

    scanner = PromptInjection(threshold=threshold, match_type=MatchType.FULL, use_onnx=False)

    def predict(text: str) -> bool:
        _sanitized, is_valid, _score = scanner.scan(text)
        return not bool(is_valid)

    return predict


def _guardrails_predict() -> Callable[[str], bool]:
    settings = get_settings()
    if settings.llm_base_url and not _loopback_url(settings.llm_base_url) and os.environ.get("OPENAI_API_KEY"):
        raise RuntimeError("refusing Guardrails/Rebuff because a non-loopback LLM URL plus API key would send samples off-box")
    from guardrails_ai.detect_prompt_injection import DetectPromptInjection

    try:
        detector = DetectPromptInjection(on_fail="noop")
    except TypeError:
        detector = DetectPromptInjection()

    def predict(text: str) -> bool:
        result = detector.validate(text, {})
        if getattr(result, "error_message", None):
            return True
        outcome = str(getattr(result, "outcome", "") or getattr(result, "status", "")).lower()
        if "fail" in outcome:
            return True
        return type(result).__name__.lower().startswith("fail")

    return predict


def _repo_llm_predict() -> Callable[[str], bool]:
    from secure_rag.agent.guardrails import llm_is_indirect_injection

    settings = get_settings()
    if not _loopback_url(settings.llm_base_url):
        raise RuntimeError("repository LLM classifier is only run against a loopback LLM_BASE_URL")

    def predict(text: str) -> bool:
        return llm_is_indirect_injection(text, settings=settings)

    return predict


def _not_comparable(framework: str, function: str, rationale: str) -> dict[str, Any]:
    return {
        "status": "not_comparable",
        "framework": framework,
        "function": function,
        "rationale": rationale,
    }


def run_comparison(*, n_pos: int = 40, n_neg: int = 40, llm_guard_threshold: float = 0.5) -> dict[str, Any]:
    payload = build_held_out_samples(n_pos=n_pos, n_neg=n_neg)
    samples = payload["samples"]
    settings = get_settings()

    implementations: dict[str, Any] = {}
    implementations["repository_heuristic"] = {
        **_run_scanner("repository_heuristic", heuristic_is_indirect_injection, samples),
        "component": "secure_rag.agent.guardrails.heuristic_is_indirect_injection",
        "framework_version": "secure-rag==0.2.0",
        "model": None,
        "threshold": None,
        "configuration": {"method": "regex", "target": "retrieved_chunk"},
    }

    try:
        implementations["protectai_llm_guard_prompt_injection"] = {
            **_run_scanner("protectai_llm_guard_prompt_injection", _llm_guard_predict(llm_guard_threshold), samples),
            "component": "llm_guard.input_scanners.PromptInjection",
            "framework_version": f"llm-guard=={_pkg_version('llm-guard')}",
            "model": "protectai/deberta-v3-base-prompt-injection-v2",
            "threshold": llm_guard_threshold,
            "configuration": {"match_type": "FULL", "use_onnx": False},
        }
    except Exception as exc:
        implementations["protectai_llm_guard_prompt_injection"] = {
            "status": "unsupported",
            "component": "llm_guard.input_scanners.PromptInjection",
            "error": f"{type(exc).__name__}: {exc}",
        }

    try:
        implementations["guardrails_ai_detect_prompt_injection"] = {
            **_run_scanner("guardrails_ai_detect_prompt_injection", _guardrails_predict(), samples),
            "component": "guardrails_ai.detect_prompt_injection.DetectPromptInjection",
            "framework_version": f"guardrails-ai-detect-prompt-injection=={_pkg_version('guardrails-ai-detect-prompt-injection')}",
            "model": "rebuff DetectPromptInjection",
            "threshold": None,
            "configuration": {"on_fail": "noop", "hosted_apis": False},
        }
    except Exception as exc:
        implementations["guardrails_ai_detect_prompt_injection"] = {
            "status": "unsupported",
            "component": "guardrails_ai.detect_prompt_injection.DetectPromptInjection",
            "error": f"{type(exc).__name__}: {exc}",
        }

    if os.environ.get("GUARDRAIL_COMPARE_REPO_LLM") == "1":
        try:
            implementations["repository_llm_classifier"] = {
                **_run_scanner("repository_llm_classifier", _repo_llm_predict(), samples),
                "component": "secure_rag.agent.guardrails.llm_is_indirect_injection",
                "framework_version": "secure-rag==0.2.0",
                "model": settings.llm_model,
                "threshold": None,
                "configuration": {"llm_base_url": settings.llm_base_url, "temperature": settings.llm_temperature},
            }
        except Exception as exc:
            implementations["repository_llm_classifier"] = {"status": "unsupported", "error": str(exc)}

    incompatible = {
        "nvidia_nemo_guardrails_self_check_input": _not_comparable(
            "NVIDIA NeMo Guardrails",
            "self check input rail",
            "Requires the nemoguardrails runtime and a Colang config. It was not installed, so it was not executed. "
            "A prompt-only imitation would not be the framework.",
        ),
        "nvidia_nemo_retrieval_sensitive_data": _not_comparable(
            "NVIDIA NeMo Guardrails",
            "check retrieval sensitive data",
            "That rail detects PII in retrieved chunks, not indirect prompt injection. Not the same security function.",
        ),
        "meta_llamafirewall_promptguard": _not_comparable(
            "Meta LlamaFirewall",
            "PromptGuardScanner / PromptGuard 2",
            "PromptGuard 2 weights are gated under the Llama community license and need a Hugging Face token. "
            "They were not downloaded, so the scanner was not executed.",
        ),
        "meta_llamafirewall_alignment_check": _not_comparable(
            "Meta LlamaFirewall",
            "AlignmentCheckScanner",
            "Inspects agent chain-of-thought, not a retrieved-document binary injection label. Not comparable. "
            "Also depends on Together API, which this eval refuses.",
        ),
        "protectai_llm_guard_anonymize_or_secrets": _not_comparable(
            "Protect AI LLM Guard",
            "Anonymize / Secrets scanners",
            "Those scanners detect PII or credentials, not retrieved-context prompt injection.",
        ),
        "guardrails_ai_pii_validators": _not_comparable(
            "Guardrails AI",
            "PII / DetectPII hub validators",
            "PII redaction is a different security function from injection detection on retrieved context.",
        ),
    }

    executed = [name for name, row in implementations.items() if row.get("status") == "executed"]
    return {
        "task": payload["task"],
        "positive_class": "retrieved document contains an InjecAgent enhanced indirect prompt injection",
        "dataset": {
            "citation": payload["citation"],
            "n_samples": len(samples),
            "n_positive": payload["n_positive"],
            "n_negative": payload["n_negative"],
            "sample_ids": [s["id"] for s in samples],
            "note": "Full texts are not written to the results file. Rebuild from InjecAgent cache with the same seed/id sort.",
        },
        "hardware": _hardware(),
        "framework_versions": {
            "secure-rag": "0.2.0",
            "llm-guard": _pkg_version("llm-guard"),
            "guardrails-ai-detect-prompt-injection": _pkg_version("guardrails-ai-detect-prompt-injection"),
            "guardrails-ai": _pkg_version("guardrails-ai"),
            "llamafirewall": _pkg_version("llamafirewall"),
            "nemoguardrails": _pkg_version("nemoguardrails"),
        },
        "implementations": implementations,
        "not_comparable": incompatible,
        "executed_implementations": executed,
        "acceptance": {
            "two_external_baselines": sum(
                1
                for name in executed
                if name in {"protectai_llm_guard_prompt_injection", "guardrails_ai_detect_prompt_injection"}
            )
            >= 2,
            "same_samples": True,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Retrieved-context injection scanner comparison")
    parser.add_argument("--out", default="experiments/results/guardrail_comparison.json")
    parser.add_argument("--n-pos", type=int, default=40)
    parser.add_argument("--n-neg", type=int, default=40)
    parser.add_argument("--llm-guard-threshold", type=float, default=0.5)
    args = parser.parse_args()
    report = run_comparison(n_pos=args.n_pos, n_neg=args.n_neg, llm_guard_threshold=args.llm_guard_threshold)
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out), "executed": report["executed_implementations"], "acceptance": report["acceptance"]}, indent=2))


if __name__ == "__main__":
    main()
