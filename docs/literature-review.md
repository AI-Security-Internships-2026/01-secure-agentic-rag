# Literature Review: Secure Agentic RAG for Cybersecurity Knowledge Bases

**Student:** _Taha Bin Hanif_
**Updated:** _12 June 2026_

---

## Instructions

For each paper or resource you read, complete one entry below.
Aim for at least **10 papers** by the end of Week 2.
Use Google Scholar, IEEE Xplore, ACM DL, arXiv, or USENIX Security.

---

## Paper Summary Template

### Paper 1 — [Multitenant Enterprise RAG Architecture]

| Field | Content |
|---|---|
| **Full title** | Securing the Agent: Vendor-Neutral, Multitenant Enterprise Retrieval and Tool Use |
| **Authors** | Arceo, F. J., & Narsing, V. P. |
| **Year** | 2026 |
| **Venue** | arXiv |
| **URL / DOI** | https://arxiv.org/abs/2605.05287 |
| **Method** | Layered isolation using policy-aware ingestion and server-side retrieval gating |
| **Dataset** | Internal synthetic enterprise benchmarks (cross-tenant leakage probes) |
| **Key result** | Proves ungated retrieval leaks cross-tenant data in 98–100% of probes; proposes OGX architecture for K8s |
| **Limitation** | Focuses on RAG retrieval gating; requires external policy engine integration for full coverage |
| **Relevance to our project** | Directly provides the architectural blueprint for your Kubernetes-native secure RAG pipeline. |


### Paper 2 — [Automated Prompt Injection Benchmarking]

| Field | Content |
|---|---|
| **Full title** | Assessing Automated Prompt Injection Attacks in Agentic Environments |
| **Authors** | Hofer, D., et al. |
| **Year** | 2026 |
| **Venue** | arXiv |
| **URL / DOI** | https://arxiv.org/pdf/2606.10525 |
| **Method** | Empirical evaluation of black-box (TAP) vs. white-box (GCG) injection methods on the AgentDojo framework |
| **Dataset** | AgentDojo (80 task pairs across banking, travel, and workspace domains) |
| **Key result** | Black-box optimization (TAP) significantly outperforms gradient-based methods; agents remain highly vulnerable |
| **Limitation** | Focuses on attack efficacy; defense-specific mitigation is secondary to the evaluation methodology |
| **Relevance to our project** | Essential for defining the "Prompt Injection Guardrails" component of your project’s security testing |


**Notes / Quotes:**
> _Paste important quotes or your personal notes here._

---

## Reference Table (Quick Overview)

| # | Title (short) | Authors | Year | Method | Dataset | Relevance |
|---|---|---|---|---|---|---|
| 1 | Securing the Agent | Arceo & Narsing | 2026 | Layered isolation / ABAC gating | Internal synthetic benchmarks | Architectural blueprint for K8s-native multitenancy |
| 2 | Automated Prompt Injection | Hofer, et al. | 2026 | Black-box (TAP) vs White-box (GCG) | AgentDojo (80 task pairs) | Methodology for testing prompt injection guardrails |


---

## Tools and Datasets Identified

| Name | Type | URL | Notes |
|---|---|---|---|
| | Dataset | | |
| kagent | Library / Tool | kagent.dev | A CNCF Sandbox project providing a Kubernetes-native runtime for AI agents. It uses Custom Resource Definitions (CRDs) to manage agent lifecycles, lifecycle observability (via OpenTelemetry), and policy-driven security, treating agents as first-class cloud-native workloads. |
| PlainID | Library / Tool | plainid.com | An enterprise-grade "Agentic Identity" platform that provides runtime, policy-based access control (PBAC). It secures the entire AI flow by enforcing guardrails across inputs, data retrieval (RAG), MCP tool usage, and outputs to ensure zero standing privileges. |


