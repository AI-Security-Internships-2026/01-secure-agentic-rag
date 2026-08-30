# Research Proposal: AuthInject-RAG

**Student:** Taha Bin Hanif  
**Supervisor:** Dr. Rana AbuBakar  
**Institution:** CNIT/PNTLab Pisa, TECIP, Scuola Superiore Sant'Anna

## 1. Background

Enterprise RAG ranks by similarity, not authorization (Arceo and Narsing, 2026). Agentic systems additionally consume untrusted retrieved text and can execute tools (Debenedetti et al., 2024; Zhan et al., 2024). These lines of work are usually evaluated separately.

## 2. Problem statement

A junior analyst can retrieve a semantically similar document from another tenant, or an authorized document can carry instructions that hijack generation and tool use. Retrieve-then-filter leaks unauthorized text into model context before any downstream check (Authorization-First Retrieval, TrustNLP 2026). Prompt isolation cannot restore a permission that was never enforced.

### 2.1 Scope evolution

The original August roadmap targeted indirect prompt injection carried in
retrieved documents, not malicious user queries. Week 8 delivered the threat
model, heuristic and LLM chunk scanning, context isolation, a 10+10 canary
fixture, and a model-dependent before/after ASR result.

Week 9 extended that work after identifying authorization as an independent
failure boundary. AuthInject-RAG therefore measures both structural exposure of
forbidden chunks and behavioral hijack by authorized poisoned chunks. The
original retrieved-document threat remains the allowed-poison/XPIA axis and the
historical direct-context experiment; it was not replaced by cross-tenant
evaluation.

## 3. Research questions

1. Does authorization-first candidate restriction drive unauthorized context exposure to zero under cross-tenant probes?
2. Which combination of datamarking, heuristic/LLM scanning, and action-time SpiceDB checks reduces indirect-injection ASR on authorized poisoned content without large utility loss?
3. What is the p50/p95 latency and LLM-call overhead of the combined stack versus ungated RAG?

## 4. Methodology

### 4.1 Data

- Combined AuthInject fixture derived from OGX tenant design (MIT), AgentDojo/InjecAgent attack families (MIT), and BIPIA isolation patterns (code MIT; only license-cleared subsets).
- Historical direct-context set: `experiments/datasets/adversarial_indirect_injection.json` (n=20); retained for the Week 8 ASR result, but not used for the joint paper table.

### 4.2 Approach

Authorization-first Qdrant payload filters; SpiceDB ReBAC on documents, chunks, and tools; provenance/taint labels; datamarked context; fail-closed policy and classifier errors; optional task-alignment.

### 4.3 Metrics

Unauthorized context exposure, CTLR/AVR, targeted ASR, answer leakage (canaries), tool-action ASR, clean/attacked utility, Recall@k, detector FPR/FNR, latency percentiles, LLM-call count. Wilson 95% intervals; ≥3 live-model repeats.

### 4.4 Tooling

Python, FastAPI, LangGraph, Qdrant, SpiceDB, OpenAI-compatible DeepSeek, pytest, Docker Compose, Kubernetes manifests.

## 5. Expected outcome

A production-oriented prototype, a licensed combined benchmark, factorial results with uncertainty, and a technical report whose claims map to executable configs.

## 6. Risks

| Risk | Mitigation |
|---|---|
| Public corpus license gaps | Manifest + checksum; do not vendor uncleared data |
| Local LLM variance | Temperature 0, repeats, bootstrap CIs |
| Scope | Three RQs only; Kubernetes after Compose gates |
