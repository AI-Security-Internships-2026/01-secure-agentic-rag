# Indirect injection evaluation

Threat model: `docs/threat_model.md`.

The 10+10 canary set in `tests/fixtures/adversarial_indirect_injection.json` is a **heuristic smoke test** only.

Paper / internship numbers:

```bash
# Offline (extractive generator, hash embeddings). Used by CI.
python -m secure_rag.benchmark.adapters
python -m secure_rag.benchmark.runner --repeats 1 --split test --out experiments/results/authinject_eval.json

# Live DeepSeek / vLLM (answers come from the model, not from joining chunks)
python -m secure_rag.benchmark.runner --live --repeats 3 --split test --out experiments/results/authinject_eval_live.json

python -m secure_rag.benchmark.analyze experiments/results/authinject_eval.jsonl
```

Configs:

| Id | Role |
|----|------|
| C0 | Non-agentic ungated RAG (baseline) |
| C1–C2 | Post-filter vs authorization-first |
| C3–C4 | Isolation/datamark vs heuristic scanner |
| C5 | Combined defenses, still single-shot |
| C6 | C5 plus SpiceDB tool `execute` checks |
| C7 | Agentic loop, no defenses |
| C8 | Agentic loop plus combined defenses + action authz |

Stale-ACL cases grant then revoke `bob` on `legal-hold` before the query. Cross-turn cases run a broad first query and feed retrieved chunks into the second turn.
