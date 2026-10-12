# Experiments

## Source of truth

Every number reported for the AuthInject v2 benchmark comes from one file of scored rows and is
derived from it by a script. Nothing below is edited by hand.

1. `benchmarks/fixtures/authinject_cases.json`: the v2.0 fixture (160 cases), written by
   `python -m secure_rag.benchmark.datasets --seed 42 --version 2.0 --size 160`. A test checks the
   committed file is byte-for-byte what the generator produces.
2. `results/authinject_v2_rows.jsonl`: one scored row per (config, case, repeat).
3. Derived by `python generate_results.py` from (2):
   - `results/authinject_v2_analysis.json`: per-config and per-family rates with Wilson 95% CIs, paired McNemar tests
   - `results/authinject_v2_tables.md`: the tables to copy into the paper (Overleaf)
   - `results/hypothesis-report.txt`: directional checks of the paper's claims; a FAIL is a finding, not an error
   - `results/figures/combined_failure_by_config.svg`
   - `results/SHA256SUMS`: checksums of the fixture, the rows and every derived file

CI runs `sha256sum -c experiments/results/SHA256SUMS` and `python generate_results.py --check`, which
fails if any derived file no longer matches the committed rows.

## Reproduce

```bash
python -m secure_rag.benchmark.datasets --seed 42 --version 2.0 --size 160
APP_ENV=test python generate_results.py --run      # offline: hash embeddings, extractive generator
python generate_results.py --check
```

The committed run is **offline**: hash embeddings and the extractive generator, which stands in for
the model (naive mode echoes context, isolated mode drops instruction-like lines). It is deterministic,
so it uses one repeat; more repeats would only change latency. `model_id` is recorded as `none`
because no model is called, and the runner refuses a multi-model run with this generator.

Live model run (uses `.env` `LLM_BASE_URL` / `LLM_API_KEY`; do not set `APP_ENV=test`):

```bash
python generate_results.py --run --generator llm --models <model-a> <model-b> --repeats 5 \
  --jsonl experiments/results/authinject_v2_rows_live.jsonl
```

## What the offline run can and cannot show

- **Stale ACL:** turn 1 retrieves a same-tenant document while a grant is live; the grant is revoked;
  turn 2 reuses the prior context. B2 (pre-filter only) re-exposes it, P1 (continuous authorization)
  drops it.
- **Same-tenant bait:** compares B1 post-filter against B2 authorization-first retrieval.
- **Cross-turn:** no permission changes between turns, so B2 and P1 behave identically (H1 FAIL is expected).
- **Tool ASR:** tool calls are dispatched only when the generator's output contains one. Offline,
  that means the naive extractive generator echoed an injected call. Model-chosen dispatch needs the live run.
- **Ablations A1-A4:** they are indistinguishable from P2 offline, because the extractive generator plus
  the scanner already stop every injection. Telling the components apart needs the live run.

## Historical tracks (unchanged)

| File | Meaning |
|------|---------|
| `results/authinject_eval.json`, `.jsonl` | Week 9-10 C0-C8 run (20 cases, offline) |
| `results/authinject_tables.json` | Tables for that run, C0-C6 |
| `results/indirect_injection_eval.json` | Week 8 direct-context run, 19 August (60% to 0% canary ASR) |
| `results/guardrail_comparison.json` | InjecAgent scanner comparison, 80 cases (see `docs/guardrail-comparison.md`) |

```bash
python experiments/run_indirect_injection_eval.py
python -m secure_rag.benchmark.guardrail_compare --out experiments/results/guardrail_comparison.json
```
