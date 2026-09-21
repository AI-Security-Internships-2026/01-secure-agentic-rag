# Evaluation Environment and Hardware Specification

```yaml
eval_date: "2026-10-03T12:00:00Z"
eval_host:
  os: "Ubuntu 22.04.4 LTS (Jammy Jellyfish)"
  kernel: "5.15.0-78-generic"
  cpu: "AMD EPYC 7742 64-Core Processor (20 vCPU allocated)"
  ram_gb: 64
  gpu: "N/A (all evaluation performed via remote API inference)"
llm_providers:
  groq_llama3.3_70b:
    endpoint: "https://api.groq.com/openai/v1"
    model: "llama-3.3-70b-versatile"
    rate_limit: "100 RPM / 30,000 TPM"
  groq_deepseek_r1_distill_qwen32b:
    endpoint: "https://api.groq.com/openai/v1"
    model: "deepseek-r1-distill-qwen-32b"
    rate_limit: "100 RPM / 30,000 TPM"
  azure_openai_gpt4omini_2024_07_18:
    endpoint: "https://authinject-eval.openai.azure.com"
    model: "gpt-4o-mini"
    api_version: "2024-07-01-preview"
    rate_limit: "1200 RPM / 200,000 TPM"
total_llm_calls: 24000
cost_usd: 38.45
wallclock_duration_seconds: 28450
pipeline_random_seed: 42
numpy_seed: 2026
hash_seed: "SECURE_RAG_HASH_SEED_2026_09"
```

## Software Components & Microservices
- **Qdrant Vector Database:** `qdrant/qdrant:v1.11.0` (HNSW indexing with scalar payload filtering)
- **SpiceDB Auth Engine:** `authzed/spicedb:v1.35.3` (In-memory datastore with ReBAC zed-tokens)
- **Application Engine:** `ghcr.io/ai-security-internships-2026/01-secure-agentic-rag:v0.3.0@sha256:7f9a1c8b3e2a4d5f6c7e8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d`
