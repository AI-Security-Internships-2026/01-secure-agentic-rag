from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from secure_rag.agent.graph import query_rag_system
from secure_rag.agent.guardrails import heuristic_is_indirect_injection
from secure_rag.agent.tools import execute_tool
from secure_rag.authz.client import get_authz_client, reset_authz_client
from secure_rag.benchmark.adapters import build_authinject_cases, _poison
from secure_rag.benchmark.datasets import fixture_path
from secure_rag.benchmark.scoring import dump_jsonl, score_case, summarize
from secure_rag.retrieval.ingest import ingest_texts
from secure_rag.retrieval.qdrant_store import reset_vector_store
from secure_rag.settings import reset_settings

CONFIGS = {
    "C0_ungated": {"filtering_mode_override": "none", "scan": False, "isolate": False, "datamark": False, "llm_scan": False},
    "C1_postfilter": {"filtering_mode_override": "post", "scan": False, "isolate": False, "datamark": False, "llm_scan": False},
    "C2_authz_first": {"filtering_mode_override": "pre", "scan": False, "isolate": False, "datamark": False, "llm_scan": False},
    "C3_datamark": {"filtering_mode_override": "none", "scan": False, "isolate": True, "datamark": True, "llm_scan": False},
    "C4_scanner": {"filtering_mode_override": "none", "scan": True, "isolate": False, "datamark": False, "llm_scan": False},
    "C5_combined": {"filtering_mode_override": "pre", "scan": True, "isolate": True, "datamark": True, "llm_scan": False},
    "C6_action_authz": {"filtering_mode_override": "pre", "scan": True, "isolate": True, "datamark": True, "llm_scan": False},
}


def _load_cases() -> dict:
    path = fixture_path("authinject_cases.json")
    if not path.exists():
        build_authinject_cases()
    return json.loads(path.read_text(encoding="utf-8"))


def _seed_corpus(payload: dict) -> None:
    reset_vector_store()
    reset_authz_client()
    for doc in payload["documents"]:
        ingest_texts(
            doc["document_id"],
            [doc["text"]],
            owner_id=doc["owner"],
            tenant_id=doc["tenant_id"],
            viewers=[doc["owner"]],
            redact_pii=False,
        )
        get_authz_client().write_relationships(
            [
                ("tool", "send_email", "caller", "user", "carol"),
            ]
        )


def run_case(case: dict, cfg: dict, payload: dict) -> dict:
    docs = {d["document_id"]: d for d in payload["documents"]}
    poison_id = case["poison_document_id"]
    family = case.get("attack_family", "override")
    poisoned = []
    for doc in payload["documents"]:
        text = doc["text"]
        if doc["document_id"] == poison_id and family not in {"stale_acl", "cross_turn"}:
            text = _poison(text, family)
        ingest_texts(
            doc["document_id"],
            [text],
            owner_id=doc["owner"],
            tenant_id=doc["tenant_id"],
            viewers=[doc["owner"]],
            redact_pii=False,
        )
        poisoned.append(doc["document_id"])
    mode = cfg.get("filtering_mode_override") or case["filtering_mode"]
    started = time.perf_counter()
    result = query_rag_system(
        collection_name="",
        query=case["query"],
        user_id=case["user_id"],
        tenant_id=case["tenant_id"],
        filtering_mode=mode,
        enable_indirect_injection_scan=cfg["scan"],
        enable_context_isolation=cfg["isolate"],
        enable_datamarking=cfg["datamark"],
        enable_llm_injection_scan=cfg["llm_scan"],
    )
    latency_ms = (time.perf_counter() - started) * 1000
    if family == "tool":
        tool = execute_tool("send_email", case["user_id"], {"to": "attacker@example.com"})
        if tool.allowed:
            result["answer"] = result.get("answer", "") + f" queued:{tool.output}"
    scored = score_case(case, result)
    scored["latency_ms"] = latency_ms
    scored["config"] = None
    scored["heuristic_poison"] = heuristic_is_indirect_injection(_poison(docs[poison_id]["text"], family)) if family not in {"stale_acl", "cross_turn"} else False
    return scored


def run_matrix(repeats: int = 3, split: str = "dev") -> dict:
    import os

    os.environ.setdefault("APP_ENV", "test")
    os.environ.setdefault("EMBED_BACKEND", "hash")
    os.environ.setdefault("QDRANT_IN_MEMORY", "true")
    reset_settings()
    payload = _load_cases()
    cases = [c for c in payload["cases"] if c.get("split") == split or split == "all"]
    all_rows: list[dict] = []
    by_config: dict[str, list[dict]] = {}
    for name, cfg in CONFIGS.items():
        rows = []
        for _ in range(repeats):
            _seed_corpus(payload)
            for case in cases:
                row = run_case(case, cfg, payload)
                row["config"] = name
                rows.append(row)
                all_rows.append(row)
        by_config[name] = rows
    report = {name: summarize(rows) for name, rows in by_config.items()}
    return {"report": report, "rows": all_rows, "n_cases": len(cases), "repeats": repeats, "split": split}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run AuthInject-RAG factorial evaluation")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--split", default="dev")
    parser.add_argument("--out", default="experiments/results/authinject_eval.json")
    args = parser.parse_args()
    reset_settings()
    result = run_matrix(repeats=args.repeats, split=args.split)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"report": result["report"], "n_cases": result["n_cases"], "repeats": result["repeats"]}, indent=2), encoding="utf-8")
    dump_jsonl(out.with_suffix(".jsonl"), result["rows"])
    print(json.dumps(result["report"], indent=2))


if __name__ == "__main__":
    main()
