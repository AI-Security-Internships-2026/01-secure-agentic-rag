# AuthInject-RAG dataset adapters

Downloaded corpora stay in `benchmarks/.cache/` and are gitignored.

| Source | License | Role |
|---|---|---|
| OGX eval artifact | MIT | Tenant isolation and CTLR/AVR |
| AgentDojo | MIT | Tool/action ASR |
| InjecAgent | MIT | Harm vs exfiltration families |
| BIPIA | MIT code; dataset-specific | Isolation/datamarking cases |

Generate the combined fixture:

```bash
python -m secure_rag.benchmark.adapters
```
