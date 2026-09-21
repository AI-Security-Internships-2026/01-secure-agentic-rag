# Experiments & Evaluation Artifacts

## Source of Truth & Reproducibility Hierarchy

To ensure scientific integrity and eliminate artifact drift, the benchmark results follow a strict source-of-truth hierarchy:

1. **Primary Raw Results**: `experiments/results/authinject_v2_live_{YYYY-MM-DD}.jsonl` (or `authinject_eval.jsonl`) — line-by-line record of each evaluation run with all 8 metrics, latency, and request identifiers.
2. **Derived Summaries & Statistical Tests**: `experiments/results/authinject_eval.json` and `experiments/results/authinject_v2_analysis.json` — summarized rates, Wilson 95% confidence intervals, and paired McNemar test p-values.
3. **Paper Tables & Figures**: Rebuilt deterministically from the above artifacts via `python generate_results.py`. No data files or figures are manually edited.
4. **Integrity Manifest**: `experiments/results/AUTHENTICATE.txt` records SHA-256 checksums of all committed benchmark artifacts.

## Running Benchmark Evaluations

### 1. Deterministic Fixture Generation (v2.0, 160 cases)
```bash
python -m secure_rag.benchmark.datasets --seed 42 --version 2.0 --size 160
```

### 2. Full Benchmark Matrix (11 Configs × 3 Models × 5 Repeats)
```bash
python -m secure_rag.benchmark.runner --repeats 5 --split all --generator extractive --out experiments/results/authinject_eval.json --jsonl_out experiments/results/authinject_v2_live_2026-09-21.jsonl
```

### 3. Generate Paper Tables, Figures, and Gate Verification
```bash
python generate_results.py --jsonl experiments/results/authinject_v2_live_2026-09-21.jsonl --out_analysis experiments/results/authinject_v2_analysis.json --gate_report experiments/results/gate-report.txt --figures_dir paper/figures
```

Output figures are written to `paper/figures/`:
- `fig2_security_metrics_comparison.svg`
- `fig3_precision_recall_f1.svg`
- `fig4_latency_sequence_breakdown.svg`
- `fig5_pareto_security_vs_latency.svg`
- `fig6_violin_p95_concurrency.svg`
- `fig7_cross_model_consistency.svg`

## Historical Evaluations
- `results/indirect_injection_eval.json`: Historical 19 August direct-context run (60% to 0% canary ASR).
- `results/guardrail_comparison.json`: InjecAgent scanner comparison (see `docs/guardrail-comparison.md`).
