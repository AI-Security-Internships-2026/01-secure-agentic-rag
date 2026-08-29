# Experiments

Current evaluation (the one used for the paper tables):

```bash
python -m secure_rag.benchmark.adapters
python -m secure_rag.benchmark.runner --repeats 1 --split test --out experiments/results/authinject_eval.json
python -m secure_rag.benchmark.analyze experiments/results/authinject_eval.jsonl
```

| File | Meaning |
|------|---------|
| `results/authinject_eval.json` | Summary rates per config |
| `results/authinject_eval.jsonl` | One scored row per case |
| `results/authinject_tables.json` | Tables rebuilt from the JSONL |

Heuristic smoke samples live in `tests/fixtures/adversarial_indirect_injection.json`.
