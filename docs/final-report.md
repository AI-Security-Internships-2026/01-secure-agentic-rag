# Final Technical Report: AuthInject-RAG

**Student:** Taha Bin Hanif  
**Institution:** CNIT/PNTLab Pisa, TECIP, Scuola Superiore Sant'Anna  
**Date:** August 2026

## Abstract

This report presents AuthInject-RAG, an authorization-first agentic retrieval system evaluated under combined cross-tenant leakage and indirect prompt injection. Ungated similarity search exposed unauthorized chunks in 100% of held-out combined probes (n=20, Wilson 95% CI 0.84–1.00). Authorization-first Qdrant payload filters with SpiceDB reduced unauthorized context exposure to 0% (CI 0.00–0.16). Injection scanning alone stopped canary hijacks but did not prevent structural exposure. The combined configuration (authorization-first + heuristic scan + datamarking) reached 0% exposure and 0% canary ASR, with utility falling from 1.00 to 0.55 when poisoned authorized documents were discarded. These offline results use hash embeddings and a deterministic generator; live DeepSeek repeats remain the release measurement.

## 1. Introduction

Enterprise RAG conflates relevance with authorization. Agentic loops then treat retrieved text as instructions. This project implements a production-oriented stack (JWT API, SpiceDB, Qdrant, LangGraph, audit log) and a factorial benchmark that scores structural exposure and behavioral leakage separately.

## 2. Related work

See `docs/literature-review.md`. Closest prior art: OGX (authorization), AgentDojo/InjecAgent (indirect injection), AFR (retrieve-then-filter is unsafe). Joint evaluation is the contribution.

## 3. Methodology

System: FastAPI + JWT identity, SpiceDB ReBAC (document/chunk/tool), authorization-first Qdrant filters, provenance/taint, datamarking, heuristic injection scan, action-time tool checks, fail-closed SpiceDB.

Benchmark fixture: 92 cases (OGX-style tenants + InjecAgent/AgentDojo families). Locked `split=test` used here (n=20 per config, 1 offline repeat).

## 4. Implementation

Installable package `secure_rag` (`src/secure_rag/`). Compatibility shims preserve `src/main.py` and `data_functions.*`. Compose and Kubernetes assets in `docker-compose.yml`, `k8s/`, `helm/`.

## 5. Evaluation

Offline protocol: `APP_ENV=test`, hash embeddings, in-memory Qdrant, temperature-free extractive answers. Artifact: `experiments/results/authinject_eval.json`.

| Config | Exposure | AVR | XPIA ASR | Tool ASR | Utility | Combined fail |
|---|---:|---:|---:|---:|---:|---:|
| C0 ungated | 1.00 | 1.00 | 0.45 | 0.05 | 1.00 | 1.00 |
| C1 post-filter | 0.00 | 0.00 | 0.15 | 0.05 | 1.00 | 0.20 |
| C2 authz-first | 0.00 | 0.00 | 0.15 | 0.05 | 1.00 | 0.20 |
| C3 datamark only | 1.00 | 1.00 | 0.45 | 0.05 | 1.00 | 1.00 |
| C4 scanner only | 1.00 | 1.00 | 0.00 | 0.05 | 0.55 | 1.00 |
| C5 combined | 0.00 | 0.00 | 0.00 | 0.05 | 0.55 | 0.05 |
| C6 + action authz | 0.00 | 0.00 | 0.00 | 0.05 | 0.55 | 0.05 |

Wilson 95% intervals are in `experiments/results/authinject_tables.json`.

## 6. Results

Authorization-first retrieval is necessary for structural noninterference. Scanning is necessary for authorized poison. Datamarking without authorization does not stop exposure in this extractive setting. Remaining 5% combined failure is a permitted tool caller in the fixture, not a policy bypass.

## 7. Limitations

Offline generator concatenates retrieved text, so datamarking cannot hide canaries the way an aligned LLM might. Sample size on the locked test split is 20. Live DeepSeek, three repeats, and OGX/AgentDojo downloads are required before conference claims. The 20-case legacy JSON is a smoke suite only.

## 8. Future work

Adaptive paraphrases against the scanner, stale-ACL reconciliation latency, Kubernetes load tests, and SecAlign-style training if GPU budget allows.

## 9. Conclusion

Policy must constrain the candidate set before generation. Injection defenses address a different failure mode and cannot substitute for authorization. Combined enforcement is the configuration that jointly reduces exposure and canary ASR, at a measurable utility cost.
