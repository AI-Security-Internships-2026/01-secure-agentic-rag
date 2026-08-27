# Literature Review: AuthInject-RAG

Updated: 24 August 2026

Verified sources (use these in the paper; do not cite unverifiable datasets as public):

1. Arceo & Narsing, *Securing the Agent*, ACM CAIS 2026. https://doi.org/10.1145/3786335.3813145 — relevance–authorization gap; OGX MIT artifact https://doi.org/10.5281/zenodo.19743797
2. Debenedetti et al., AgentDojo, NeurIPS 2024. https://arxiv.org/abs/2406.13352 — MIT, environment-state ASR
3. Zhan et al., InjecAgent, Findings ACL 2024. https://doi.org/10.18653/v1/2024.findings-acl.624 — MIT, 1054 IPI cases
4. Zhang et al., Agent Security Bench, ICLR 2025. https://arxiv.org/abs/2410.02644 — mixed attacks, NRP
5. Liang et al., SafeRAG, ACL 2025. https://doi.org/10.18653/v1/2025.acl-long.230 — RAG component attacks (dataset not assumed public)
6. Zou et al., PoisonedRAG, USENIX Security 2025 — retrieval + generation poisoning
7. Authorization-First Retrieval, TrustNLP 2026. https://doi.org/10.18653/v1/2026.trustnlp-main.15 — noninterference invariant; original corpus not verified public
8. Microsoft BIPIA, KDD 2025. https://github.com/microsoft/BIPIA — MIT code, mixed dataset licenses
9. CyberSecEval 2, arXiv:2404.13161 — direct injection / FRR; MIT artifacts
10. Task Shield, ACL 2025; MELON, ICML 2025; SecAlign, CCS 2025 — defenses (fine-tune vs test-time)

Citation caveats for earlier drafts: Permission-Aware RAG (IEEE 11224764) has no verified public dataset; Poisoned LangChain is a 2024 arXiv report without a clear redistributable license; AgenTRIM code was not verified as released; the local 10+10 ASR result is a smoke test.
