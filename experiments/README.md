# Experiments

```bash
python -m secure_rag.benchmark.adapters
python -m secure_rag.benchmark.runner --repeats 1 --split test --out experiments/results/authinject_eval.json
python -m secure_rag.benchmark.analyze experiments/results/authinject_eval.jsonl
```

Live model (uses `.env` `LLM_BASE_URL` / `LLM_MODEL`; do not set `APP_ENV=test`):

```bash
python -m secure_rag.benchmark.runner --live --repeats 3 --split test --out experiments/results/authinject_eval_live.json
```

| File | Meaning |
|------|---------|
| `results/authinject_eval.json` | Summary rates per config |
| `results/authinject_eval.jsonl` | One scored row per case |
| `results/authinject_tables.json` | Tables rebuilt from the JSONL |

`C0` is the non-agentic baseline. `C7`/`C8` turn the rewrite/rerank loop on. `--live` scores generated model text; the default is extractive (CI).

Retrieved-context injection scanner comparison (InjecAgent, ACL 2024):

```bash
python -m secure_rag.benchmark.guardrail_compare --out experiments/results/guardrail_comparison.json
```

See `docs/guardrail-comparison.md`.
