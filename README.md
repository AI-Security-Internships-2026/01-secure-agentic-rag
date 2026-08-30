# AuthInject-RAG

Authorization-first agentic RAG for **combined** cross-tenant leakage and indirect prompt injection.

CNIT/PNTLab Pisa · TECIP · Scuola Superiore Sant'Anna — AI Security Internship 2026

## Research questions

1. Does authorization-first retrieval prevent **structural exposure** of unauthorized chunks?
2. Do layered injection defenses stop **poisoned-but-authorized** content without collapsing utility?
3. What latency and LLM-call cost does combined enforcement add?

Novelty is the **joint** evaluation: authorization failure and indirect injection are measured separately and together. The original Week 8 20-case direct-context experiment is retained as a separate historical ASR track; it is not substituted for the joint benchmark.

## Roadmap traceability (August 2026)

| Milestone | Status | Evidence |
|---|---|---|
| Aug 9: retrieved-document injection threat + first mitigation | Complete | `docs/threat_model.md`, `src/secure_rag/agent/guardrails.py` |
| Aug 16: poisoned/clean set + ASR before/after | Complete, historical | `experiments/run_indirect_injection_eval.py`, `experiments/results/indirect_injection_eval.json` |
| Aug 23: agent loop × defense ablation | Wired as C7/C8; live measurement pending | `src/secure_rag/benchmark/runner.py`, `docs/indirect-injection-evaluation.md` |
| Aug 30: benchmark vs non-agentic baseline | Complete offline | C0–C8 in `experiments/results/authinject_eval.json` |

The Week 9 AuthInject scope **extends** the original retrieved-document threat
with cross-tenant authorization and tool-action boundaries. It does not replace
the original threat. Offline C7/C8 disable model-based rewrite/rerank steps;
the model-level agent-loop milestone requires the documented `--live` run.

## Architecture

Authenticated FastAPI → LangGraph agent → SpiceDB (ReBAC) + Qdrant (payload-filtered retrieval) → OpenAI-compatible DeepSeek → structured audit log.

Identity comes from JWT claims. There is no `admin` bypass. SpiceDB is mandatory outside `APP_ENV=test`.

## Local setup

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
copy .env.example .env
docker compose up -d postgres spicedb qdrant
```

Point generation at local DeepSeek:

```env
APP_ENV=development
LLM_BASE_URL=http://127.0.0.1:8000/v1
LLM_MODEL=deepseek-chat
EMBED_BACKEND=hash   # or gemini with GOOGLE_API_KEY
```

Run API and CLI:

```bash
uvicorn secure_rag.api.app:app --port 8080
secure-rag
```

Mint a development token (`/token` is disabled when `APP_ENV=production`):

```bash
curl -X POST http://127.0.0.1:8080/token -H "content-type: application/json" ^
  -d "{\"user_id\":\"alice\",\"tenant_id\":\"finance\"}"
```

## Tests and benchmark

```bash
pytest tests -q
python -m secure_rag.benchmark.adapters
python -m secure_rag.benchmark.runner --repeats 1 --split test --out experiments/results/authinject_eval.json
python -m secure_rag.benchmark.analyze experiments/results/authinject_eval.jsonl
python experiments/run_indirect_injection_eval.py  # model-dependent Week 8 track
# Live DeepSeek (generated answers, not extractive):
# python -m secure_rag.benchmark.runner --live --repeats 3 --split test --out experiments/results/authinject_eval_live.json
```

Live DeepSeek runs are a release job, not CI. CI uses `APP_ENV=test`, hash embeddings, and in-memory Qdrant.

## Kubernetes

Manifests live in `k8s/` and `helm/authinject-rag/`. Deploy only after Compose health checks pass. Supply secrets via `authinject-secrets` (`jwt-secret`, `spicedb-preshared-key`).
