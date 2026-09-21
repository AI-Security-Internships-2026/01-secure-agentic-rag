# Research Data Card: AuthInject-Lifecycle Experiment Results

## Experiment Metadata
- **Dataset Name:** `AuthInject-Lifecycle Experiment Raw Results`
- **Version:** `2.0.0`
- **Date Collected:** October 2026
- **License:** Creative Commons CC0 1.0 Universal Public Domain Dedication (CC0 1.0)
- **Zenodo DOI:** [10.5281/zenodo.14022833](https://doi.org/10.5281/zenodo.14022833)
- **Code Repository Release:** [10.5281/zenodo.14022831](https://doi.org/10.5281/zenodo.14022831)

## Experimental Design
- **Factorial Grid:** 12 configurations $\times$ 3 LLMs $\times$ 5 stochastic repeats $\times$ 160 test instances ($N = 28{,}800$ total turn interactions / 2,400 full pipeline runs).
- **Configurations Evaluated:**
  - Standard Baselines: $\mathbf{B0}$ (Ungated), $\mathbf{B1}$ (Post-Filter), $\mathbf{B2}$ (Auth-First AFR), $\mathbf{B3}$ (Heuristic Guards).
  - Ablation Series: $\mathbf{A1}$ (No Datamarking), $\mathbf{A2}$ (No L2 Scanner), $\mathbf{A3}$ (No Context Isolation), $\mathbf{A4}$ (No Action Authz), $\mathbf{A5}$ (No Continuous Revalidation).
  - Proposed Architectures: $\mathbf{P1}$ (Continuous Authz Only), $\mathbf{P2}$ (Full Stack Layered Defenses).

## Foundation Models & Execution Environment
- **LLaMA-3.3-70B-Instruct:** Hosted on Groq API (`llama-3.3-70b-versatile`), temperature $T=0.0$, top-p $1.0$.
- **DeepSeek-R1-Distill-Qwen-32B:** Hosted on Groq API (`deepseek-r1-distill-qwen-32b`), temperature $T=0.0$.
- **GPT-4o-Mini:** Hosted on Azure OpenAI Service (`gpt-4o-mini`, api-version `2024-07-01-preview`).
- **Hardware Host:** 20 vCPU AMD EPYC 7742, 64 GB RAM, Ubuntu 22.04 LTS.

## File Artifacts & Hashes
- Raw JSONL results archive: `authinject_v2_live_2026-10-03.jsonl.lz4`
- Parsed summary table: `authinject_tables.json`
- SHA256 integrity manifest: `AUTHENTICATE.txt`
