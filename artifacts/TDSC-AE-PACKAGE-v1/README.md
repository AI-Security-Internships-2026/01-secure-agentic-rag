# IEEE TDSC Artifact Evaluation Package (v1.0)
**Paper Title:** Continuous Authorization over the Agentic-RAG Context Lifecycle  
**Primary Author:** Taha Bin Hanif (Scuola Superiore Sant'Anna / CNIT PNTLab Pisa)  
**Target Badges:** (1) Artifacts Available, (2) Artifacts Functional  
**Permanent Zenodo DOIs:**
- Code Release: [10.5281/zenodo.14022831](https://doi.org/10.5281/zenodo.14022831)
- Benchmark Dataset: [10.5281/zenodo.14022832](https://doi.org/10.5281/zenodo.14022832)
- Experiment Results: [10.5281/zenodo.14022833](https://doi.org/10.5281/zenodo.14022833)

---

## 1. System Requirements & Hardware
- **Operating System:** Linux x86_64 (e.g., Ubuntu 22.04 LTS) or macOS / Windows WSL2.
- **Hardware Resources:** Minimum 4 CPU cores, 16 GB RAM, 10 GB free disk space.
- **Dependencies:** Docker Engine $\ge 24.0$, Docker Compose v2, Python 3.11+, Git.
- **API Keys (for live evaluation only):**
  - `GROQ_API_KEY`: Groq API key for LLaMA-3.3-70B and DeepSeek-R1-Distill inference.
  - `AZURE_OPENAI_API_KEY`: Azure OpenAI API key for GPT-4o-Mini evaluation.
  - `GOOGLE_API_KEY`: (Optional) For live Gemini embedding evaluations.

---

## 2. Quickstart: 15-Minute Smoke Evaluation (Offline Mode)
For evaluators validating functionality without external API tokens:

```bash
# 1. Clone repository and verify GPG-signed tag
git clone https://github.com/AI-Security-Internships-2026/01-secure-agentic-rag.git
cd 01-secure-agentic-rag
git checkout v0.3.0

# 2. Launch containerized infrastructure
docker compose up -d postgres spicedb qdrant

# 3. Execute smoke reproduction script
bash artifacts/TDSC-AE-PACKAGE-v1/scripts/make-reproduce.sh --smoke
```

**Expected Runtime:** $\approx 3$--$5$ minutes. Validates determinism across all 12 configurations on a 20-case test subset using offline embeddings.

---

## 3. Full Benchmark Reproduction (Live Frontier LLMs)
To reproduce the exact numbers reported in Section VI of the paper (Tables IV--XIII):

```bash
# 1. Configure environment keys
export GROQ_API_KEY="your_groq_api_key_here"
export AZURE_OPENAI_API_KEY="your_azure_key_here"
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com"

# 2. Run full 160-case x 3-model x 5-repeat benchmark
bash artifacts/TDSC-AE-PACKAGE-v1/scripts/make-reproduce.sh --full
```

**Expected Runtime:** $\approx 4$--$6$ hours depending on provider rate limits.
Generates:
- `experiments/results/authinject_v2_live.jsonl`
- `experiments/results/authinject_tables.json`
- `experiments/results/gate-report.txt` (All 6 Quality Gates passing)
- Vector figures in `paper/figures/` matching paper byte-for-byte.
