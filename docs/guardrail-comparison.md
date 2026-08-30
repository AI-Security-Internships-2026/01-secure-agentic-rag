# Guardrail comparison: retrieved-context injection detection

## Exact task

Binary classification of **retrieved tool-response documents**:

> Does this untrusted document contain an **indirect prompt injection** aimed at the agent?

Positive class = InjecAgent **enhanced** attacker instruction (Zhan et al., Findings of ACL 2024, MIT) inserted into an InjecAgent user-tool response template.  
Negative class = the same templates filled with the paper’s own user instruction / thought text, **no** attacker instruction.

This is **retrieved-context validation**, not user-query jailbreak classification, not PII detection, and not tool-trace alignment.

The original Week 8 `experiments/run_guardrail_comparison.py` used copied
NeMo-style and Meta-style prompts while naming them as frameworks. That was not
a technically valid framework comparison. The command is retained as a
compatibility entry point, but it now invokes this maintained same-task
benchmark. The historical 60%→0% generation-hijack result is a different
experiment and remains reproducible through
`experiments/run_indirect_injection_eval.py`.

## Implementations

| Name | Component | Role |
|------|-----------|------|
| `repository_heuristic` | `heuristic_is_indirect_injection` | Current repo control |
| `protectai_llm_guard_prompt_injection` | Protect AI LLM Guard `PromptInjection` (same ProtectAI DeBERTa weights via `transformers` if `scan()` fails) | External baseline 1 |
| `guardrails_ai_detect_prompt_injection` | Guardrails AI `DetectPromptInjection` (Rebuff + Pinecone) | Not executed: requires a hosted Pinecone index |
| `huggingface_fmops_prompt_injection` | `fmops/distilbert-prompt-injection` via Hugging Face `pipeline` | Local substitute if Guardrails/Rebuff cannot run in the app venv |

Marked **not comparable** (not executed as equivalents):

- NeMo `self check input` — runtime not installed; a copied prompt is not the framework
- NeMo retrieval PII rail — different function
- LlamaFirewall PromptGuard 2 — gated model, not downloaded
- LlamaFirewall AlignmentCheck — agent CoT, plus Together API
- LLM Guard Anonymize/Secrets — PII/secrets, not injection
- Guardrails PII validators — different function

## Dataset

InjecAgent (`benchmarks/.cache/InjecAgent`, MIT). Do not commit the clone. Held-out sample **ids** are stored in the results JSON; texts are rebuilt from the cache.

## Reproduction

**1. Restore the application environment** (you installed comparison packages into `.venv` and downgraded LangChain):

```bash
cd ~/01-secure-agentic-rag
source .venv/bin/activate
pip install -e ".[dev]"
```

**2. Use a separate venv for this comparison** (recommended so the API keeps working):

```bash
python3 -m venv .venv-guardrails
source .venv-guardrails/bin/activate
pip install -U pip
pip install -e .
pip install "llm-guard==0.3.16" "guardrails-ai-detect-prompt-injection==0.1.0"
python -m guardrails_ai.detect_prompt_injection.post_install
mkdir -p benchmarks/.cache
test -d benchmarks/.cache/InjecAgent || git clone --depth 1 https://github.com/uiuc-kang-lab/InjecAgent.git benchmarks/.cache/InjecAgent
```

`DetectPromptInjection` requires a **Pinecone index** (Rebuff). That would send InjecAgent retrieved-context text off-box, so it is marked not comparable. The harness runs `fmops/distilbert-prompt-injection` locally as the second equivalent injection classifier.

If you already installed into `.venv` and just want the JSON now:

```bash
cd ~/01-secure-agentic-rag
source .venv/bin/activate
python -m secure_rag.benchmark.guardrail_compare --out experiments/results/guardrail_comparison.json
# Equivalent compatibility command:
python experiments/run_guardrail_comparison.py --out experiments/results/guardrail_comparison.json
```

First LLM Guard run downloads `protectai/deberta-v3-base-prompt-injection-v2` from Hugging Face to the local cache. Samples are classified on CPU/GPU locally.

Optional repository LLM classifier (loopback DeepSeek only):

```bash
GUARDRAIL_COMPARE_REPO_LLM=1 python -m secure_rag.benchmark.guardrail_compare --out experiments/results/guardrail_comparison.json
```

## Output

`experiments/results/guardrail_comparison.json`

Contains TP/FP/TN/FN, precision, recall, F1, FPR, FNR, median/P95 latency, throughput, execution failures, versions, hardware, and not-comparable entries.

Do not commit API keys. The results file stores sample **ids**, not full InjecAgent texts.
