# Dataset Card: AuthInject-Lifecycle v2.0 Benchmark

## Dataset Summary
- **Dataset Name:** `AuthInject-Lifecycle`
- **Version:** `2.0.0`
- **Release Date:** August 2026
- **Curators:** Taha Bin Hanif, Dr. Rana AbuBakar (NUST / CNIT PNTLab Pisa, Scuola Superiore Sant'Anna)
- **License:** Creative Commons Attribution 4.0 International (CC-BY 4.0)
- **Primary Language:** English (`en-US`)
- **Zenodo DOI:** [10.5281/zenodo.14022832](https://doi.org/10.5281/zenodo.14022832)

## Dataset Structure & Size
- **Total Test Cases:** 160 multi-turn test instances
- **Total Tokens:** 14.3k tokens
- **Attack Families Covered:** 7 distinct threat categories
  1. `direct_context` (16 cases)
  2. `multi_tenant` cross-tenant leakage (16 cases)
  3. `indirect_retrieved` injection (16 cases)
  4. `tool` hijacking via agent actions (24 cases)
  5. `agentic_memory` conversation injection (24 cases)
  6. `same_tenant_bait` disjoint-document semantic baiting (40 cases)
  7. `stale_acl` multi-turn policy revocation (24 cases)

## Annotation & Ground Truth
- **Human Annotation:** 8 cases double-annotated by two independent AI security researchers with an inter-annotator agreement Cohen's $\kappa = 0.714$.
- **Automated Structural Verification:** Ground truth document ACLs and canary payloads validated through deterministic parse assertions.

## Provenance & Sources
- Extends and adapts test paradigms from:
  - InjecAgent (ACL 2024) \cite{zhan2024injecagent}
  - AgentDojo (NeurIPS 2024) \cite{debenedetti2024agentdojo}
  - BIPIA (KDD 2025) \cite{yi2025benchmarking}
  - OGX Multi-Tenant Benchmark (Arceo et al. 2026) \cite{arceo2026framework}
- Incorporates 80 original test cases specifically targeting same-tenant semantic baiting and multi-turn stale ACL revocation.

## Limitations & Ethical Considerations
- All enterprise documents, employee identities, and injection canaries are synthetically generated.
- No real-world Personal Identifiable Information (PII) or proprietary corporate data is contained within the dataset.
