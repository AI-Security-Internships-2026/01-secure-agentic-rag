# Guardrail Comparison Test

> Historical note: the script `experiments/run_guardrail_comparison.py` was removed. Live classification lives in `src/secure_rag/agent/guardrails.py` and Presidio in `src/secure_rag/retrieval/pii.py`. Paper numbers use `python -m secure_rag.benchmark.runner`. This page records an earlier Groq/laptop experiment.

## Purpose

That earlier script compared security checks for two tasks:

1. Prompt-injection classification.
2. PII and secret detection.

It operates on text samples directly. It does not use ChromaDB because it measures guardrail classification, not document retrieval, embedding quality, or ranking.

## Test data

The script contains two small labeled datasets. Each has 20 samples:

- Prompt injection: 10 benign queries and 10 malicious queries.
- PII: 10 benign texts and 10 texts containing PII or secrets.

Each sample has a Boolean `label`. `True` means the sample should be detected or blocked; `False` means it should be allowed.

## Prompt-injection predictors

### Repository control

`repo_predict_injection()` calls the repository `_injection_guardrail()` in `src/data_functions/query_engine.py`. The guardrail sends the text to the configured OpenAI-compatible chat model and expects a `SAFE` or `MALICIOUS` classification.

### NeMo-style self-check

`nemo_predict_injection()` uses a prompt modeled on a NeMo Guardrails self-check input rail. It asks the chat model whether the message should be blocked and interprets `yes` as malicious.

This is a prompt-pattern implementation in the experiment; it does not instantiate the full NVIDIA NeMo Guardrails runtime.

### Meta Llama Guard-style taxonomy

`meta_predict_injection()` supplies safety categories for prompt injection, system override, jailbreak, and secret extraction. It asks for `safe` or `unsafe` and interprets `unsafe` as malicious.

This is a taxonomy-style prompt pattern; it does not load a separate Meta Llama Guard or LlamaFirewall model.

## PII predictors

### Repository Presidio

`repo_predict_pii()` calls `_pii_input_guardrail()`. Microsoft Presidio analyzes the text and anonymizes detected entities. If the anonymized result differs from the original, the sample is marked as containing PII.

### Regex validator

`guardrails_ai_predict_pii()` applies local regular expressions for email addresses, phone numbers, credit cards, SSNs, API keys, passwords, and driver-license identifiers.

This is a lightweight validator pattern, not a full Guardrails AI service or external model.

Meta Llama Guard is marked as not comparable for PII because content moderation classification does not provide entity extraction and masking.

## Model and services

The LLM-based predictors use the shared `ChatOpenAI` client configured for an OpenAI-compatible endpoint. Groq is the default endpoint, and the model is selected by `LLM_MODEL` or `GROQ_MODEL`, with `openai/gpt-oss-20b` as the current default. Temperature is `0.0`.

The LLM is called once per sample for each LLM-based predictor. Presidio and regex validation run locally. ChromaDB, embeddings, SpiceDB, and document ingestion are outside this benchmark.

## Metric calculation

For each predictor, the script stores the true labels, predicted labels, and elapsed time. It then counts:

- `TP`: malicious sample correctly detected.
- `FP`: benign sample incorrectly blocked.
- `TN`: benign sample correctly allowed.
- `FN`: malicious sample missed.

It calculates:

$$
\text{Precision} = \frac{TP}{TP + FP}
$$

$$
\text{Recall} = \frac{TP}{TP + FN}
$$

$$
F1 = \frac{2 \times \text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}
$$

It also reports false-positive rate, false-negative rate, median latency, 95th-percentile latency, and throughput.

Latency is measured around each predictor call with `time.perf_counter()`. Network-backed LLM checks are therefore much slower than local regex checks.

## Results interpretation

The results are stored in `experiments/results/guardrail_comparison.json`. The benchmark showed that the NeMo-style prompt had the best prompt-injection F1 on this small dataset, while the repository and Meta-style prompts detected all attacks but also falsely blocked benign samples.

For PII, Presidio had higher recall, while the regex validator had no false positives but missed more cases. These results describe the tested implementations and dataset; they are not a definitive comparison of the complete external frameworks.

## Reproduce

```bash
python experiments/run_guardrail_comparison.py
```

The command requires the configured LLM endpoint for LLM-based checks and the repository's Presidio dependencies for the Presidio check.
