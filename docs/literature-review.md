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



### Paper 3 — [RAG Access Control]

| Field | Content |
|---|---|
| **Full title** | Permission-Aware RAG: Identity and Access Management (IAM)-Based Access Filtering in Multi-Resource Environments |
| **Authors** | Jooyoung Jeong, Sang-goo Lee |
| **Year** | 2025 |
| **Venue** | IEEE |
| **URL / DOI** | https://ieeexplore.ieee.org/document/11224764 |
| **Method** | Introduces an IAM-based filtering mechanism for Retrieval-Augmented Generation systems. Documents are tagged with permissions, and retrieval is filtered according to the user's access rights before information reaches the LLM. |
| **Dataset** | Multi-resource enterprise knowledge bases containing documents with different access levels and permission requirements. |
| **Key result** | Successfully prevents unauthorized retrieval of sensitive information while maintaining answer quality. Demonstrates that traditional RAG systems can leak restricted data if retrieval is not permission-aware. |
| **Limitation** | Primarily designed for enterprise environments with predefined IAM policies; effectiveness depends on accurate permission metadata. |
| **Relevance to our project** | Directly supports the Secure Retrieval Layer of a Kubernetes-native RAG system by enforcing role-based access control before retrieval, reducing data leakage risks |


### Paper 4 — [LangChain / Agent Security]

| Field | Content |
|---|---|
| **Full title** | Poisoned LangChain: Jailbreak LLMs by LangChain |
| **Authors** | Ziqiu Wang, Jun Liu, Shengkai Zhang, Yang Yang |
| **Year** | 2025 |
| **Venue** | arXiv |
| **URL / DOI** | https://arxiv.org/abs/2406.18122   |
| **Method** | Investigates indirect prompt injection attacks against LangChain-based systems. The researchers poison external knowledge sources used by retrieval pipelines and evaluate whether malicious instructions can manipulate LLM behavior. |
| **Dataset** | LangChain-based RAG environments with intentionally poisoned external knowledge bases. |
| **Key result** | Demonstrates that malicious content embedded in retrieved documents can successfully jailbreak LLMs and bypass safety mechanisms, even when the original user prompt appears harmless. |
| **Limitation** | Focuses on attack effectiveness rather than providing a comprehensive defense framework; experiments are limited to specific LangChain retrieval scenarios. |
| **Relevance to our project** | Highly relevant for the Prompt-Injection Guardrails component. It provides concrete evidence that retrieved documents themselves can become attack vectors, justifying the need for document sanitization, prompt filtering, and retrieval validation before agent execution. |


### Paper 5 — [Tool Risk Mitigation for Agentic AI]

| Field | Content |
|---|---| 
| **Full title** | AgenTRIM: Tool Risk Mitigation for Agentic AI |
| **Authors** | Roy Betser, Shamik Bose, Amit Giloni, Chiara Picardi, Sindhu Padakandla, Roman Vainshtein |
| **Year** | 2026 |
| **Venue** | arXiv |
| **URL / DOI** | https://arxiv.org/abs/2601.12449 |
| **Method** | Introduces a security framework that applies the Principle of Least Privilege to LLM agents. The system reconstructs the agent's tool interface offline and dynamically restricts tool access at runtime through adaptive filtering and validation mechanisms. |
| **Dataset** | AgentDojo benchmark and additional tool-use attack scenarios involving prompt injection and tool misuse. |
| **Key result** | Significantly reduces attack success rates while preserving task performance. The framework effectively mitigates indirect prompt injection and unauthorized tool execution without modifying the agent's internal reasoning process |
| **Limitation** | Primarily focuses on tool-permission risks and tool misuse. It does not provide comprehensive protection against all forms of memory poisoning, retrieval attacks, or multi-agent propagation threats. |
| **Relevance to our project** | Directly supports the "Agent Execution Guardrails" component of a Kubernetes-Native Secure Agentic RAG system. The least-privilege approach can be applied to LangChain/LangGraph agents to restrict access to databases, APIs, vector stores, and Kubernetes resources, reducing the impact of prompt injection attacks. |

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


