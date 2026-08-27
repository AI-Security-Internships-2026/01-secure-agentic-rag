# Indirect injection evaluation

The legacy 10+10 canary set in `experiments/datasets/adversarial_indirect_injection.json` is a **smoke test** only.

Paper claims must use:

```bash
python -m secure_rag.benchmark.runner --repeats 1 --split test --out experiments/results/authinject_eval.json
python -m secure_rag.benchmark.analyze experiments/results/authinject_eval.jsonl
```

That factorial measures unauthorized context exposure, AVR, XPIA ASR, tool ASR, and utility with Wilson intervals. Live DeepSeek runs should set `APP_ENV=development`, a working `LLM_BASE_URL`, and `--repeats 3`.
