# Indirect injection evaluation

Threat model: `docs/threat_model.md`.

This repository intentionally retains **two complementary evaluation tracks**.
The authorization work added in Week 9 extends the Week 8 indirect-injection
scope; it does not replace it.

## Track A: retrieved document already in context (Week 8)

The 10-poisoned/10-clean fixture in
`tests/fixtures/adversarial_indirect_injection.json` uses benign user questions.
The attack exists only in the supplied document. This isolates the original
roadmap question:

> If a poisoned document has already been retrieved, does the generator obey
> the document-side instruction?

Run:

```bash
python -m pytest tests/test_indirect_injection.py
python experiments/run_indirect_injection_eval.py
```

The runner uses the current OpenAI-compatible `LLM_BASE_URL` and `LLM_MODEL`.
It compares a naive prompt against repository heuristic scanning, the configured
LLM chunk classifier, and context isolation. API failures are excluded from the
scored denominator and are reported as execution failures.

Historical artifact:
`experiments/results/indirect_injection_eval.json`, produced on 19 August 2026
with `openai/gpt-oss-20b` via Groq. It reports:

- unprotected canary ASR: 6/10 (60%);
- mitigated canary ASR: 0/10 (0%);
- clean keyword utility: 7/10 before and 6/10 after; and
- zero clean false blocks.

These are historical model-dependent results. A new execution overwrites the
artifact and may differ. See `docs/task-execution-summary.md` for per-case
details and limitations.

## Track B: combined authorization and injection failures (Week 9–10)

The AuthInject fixture asks an additional question: should the document have
crossed the tenant boundary in the first place? It separately scores structural
unauthorized exposure, answer leakage, canary success, tool action ASR, utility,
and their union.

```bash
# Deterministic offline protocol used by CI.
python -m secure_rag.benchmark.adapters
python -m secure_rag.benchmark.runner --repeats 1 --split test \
  --out experiments/results/authinject_eval.json
python -m secure_rag.benchmark.analyze experiments/results/authinject_eval.jsonl \
  --out experiments/results/authinject_tables.json

# Live DeepSeek/vLLM release measurement (not represented by the offline JSON).
python -m secure_rag.benchmark.runner --live --repeats 3 --split test \
  --out experiments/results/authinject_eval_live.json
```

| Id | Role |
|----|------|
| C0 | Non-agentic ungated RAG (baseline) |
| C1–C2 | Post-filter vs authorization-first |
| C3–C4 | Isolation/datamark vs heuristic scanner |
| C5 | Combined defenses, still single-shot |
| C6 | C5 plus SpiceDB tool `execute` checks |
| C7 | Agentic loop, no defenses |
| C8 | Agentic loop plus combined defenses and action authz |

C7/C8 satisfy the with/without-agent-loop ablation. In tool attack cases no
test user is granted `send_email`; positive permission behavior is tested
separately. Therefore C6/C8 must reduce unauthorized tool ASR to zero in the
locked offline artifact. Tool ASR uses only the three tool-attack rows as its
denominator; the other rates use all 20 rows.

Offline/test mode disables LLM input classification, reranking, and query
rewriting, so C7/C8 validate agent-loop configuration and routing but are
behaviorally degenerate with their corresponding non-agentic controls. A
model-level agent-loop comparison requires `--live`; the result JSON records
whether those steps were effective. Stale-ACL cases grant and revoke access
before query; cross-turn cases feed first-turn context into a second turn.
