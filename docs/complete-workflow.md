# AuthInject-RAG: complete workflow

This file is a plain-language guide to the whole system. It explains what the app does, how the pieces fit together, how you run it, and where every kind of result is stored.

The project name is **AuthInject-RAG**. It is a question-answering system that reads your documents, but it is built so that:

1. A user can only see documents they are allowed to see.
2. Hidden instructions inside a document (prompt injection) are harder to follow.
3. Every important action is written to a log you can inspect later.

You do **not** need to remember every file. Use this document as the map.

---

## 1. What this system is (in one paragraph)

You upload text or a PDF. The app splits it into small pieces (chunks), hides personal data if you ask it to, turns each chunk into a number list (an embedding), stores the numbers in **Qdrant**, and stores “who may read this” in **SpiceDB**. When someone asks a question, they first prove who they are with a **JWT** (a signed token). The app looks up what they may read, searches only those chunks, checks the chunks for injection, asks a language model (your local DeepSeek) to write an answer, then writes an audit line to disk.

That is the whole product. Everything else is a detail of those steps.

---

## 2. Picture of the moving parts

```
You (browser, curl, or CLI)
        |
        |  JWT in the Authorization header
        v
FastAPI  (src/secure_rag/api/)
        |
        +-- /ingest  --> PII optional --> embeddings --> SpiceDB + Qdrant
        |
        +-- /query   --> LangGraph agent (src/secure_rag/agent/)
                              |
                              |  1. hide PII in the question
                              |  2. search Qdrant (only allowed docs if mode=pre)
                              |  3. scan chunks for injection
                              |  4. ask DeepSeek for an answer
                              |  5. hide PII in the answer + write audit log
                              v
                         JSON answer back to you

Sidecar services (Docker):
  Postgres  --> used only by SpiceDB
  SpiceDB   --> permission database (who can view which document)
  Qdrant    --> vector database (the chunks and their embeddings)

Your LLM (you start this yourself):
  vLLM / DeepSeek on a port such as 30000
```

---

## 3. Words used in this project

| Word | Simple meaning |
|------|----------------|
| **Tenant** | A group, like `finance` or `hr`. Users belong to a tenant. |
| **Document** | One logical file, identified by `document_id` (example: `finance-policy`). |
| **Chunk** | A small piece of a document. Search works on chunks, not whole files. |
| **Embedding** | A list of numbers that represent the meaning of a chunk so similar text can be found. |
| **JWT** | A signed string that says “I am user alice in tenant finance”. The API reads it. You cannot pick a username in the query body. |
| **SpiceDB** | A service that answers “may this user view this document?” |
| **Qdrant** | A service that stores embeddings and finds similar chunks. |
| **LangGraph** | The step-by-step agent: guard → retrieve → verify → generate → log. |
| **PII** | Personal data (email, phone, name, and similar). We hide it with Presidio. |
| **Indirect injection** | A document that tries to order the model around (“ignore previous instructions…”). |
| **Filtering mode** | How strictly we apply access control during search: `pre`, `post`, or `none`. |
| **Canary** | A fake secret string used in tests (example: `CANARY_FIN_A1`) so we can see if it leaked. |

---

## 4. Folders and modules

Python code lives under `src/`. The installable package is `secure_rag`.

### 4.1 `src/secure_rag/settings.py`

Reads `.env`. Every other module asks `get_settings()` for ports, model name, SpiceDB address, and feature flags. Settings are cached at process start. **If you change `.env`, restart uvicorn.**

### 4.2 `src/secure_rag/api/`

The HTTP server.

| File | Role |
|------|------|
| `app.py` | Builds FastAPI, request ids, rate limit. |
| `auth.py` | Creates and checks JWTs. Turns a token into a `Principal` (`user_id`, `tenant_id`). |
| `schemas.py` | Request bodies for `/token`, `/query`, `/ingest`. |
| `routes.py` | The endpoints listed in section 7. |

### 4.3 `src/secure_rag/authz/`

Access control.

| File | Role |
|------|------|
| `schema.zed` | The permission model: user, tenant, document, chunk, tool. |
| `client.py` | Talks to SpiceDB. In `APP_ENV=test` it uses an in-memory fake instead. Fail-closed: if SpiceDB is down outside tests, the request fails rather than allowing access. |

Who can **view** a document: owner, editor, listed viewer, **or** any member of the document’s tenant.

### 4.4 `src/secure_rag/retrieval/`

Documents in, chunks out.

| File | Role |
|------|------|
| `pii.py` | Splits text into chunks. Hides direct identifiers (email, phone, SSN, card, person name, and similar). It does **not** hide words like “Quarterly” as dates. |
| `embeddings.py` | `gemini` for Google embeddings, or `hash` for a local fake used in tests and offline VMs. |
| `qdrant_store.py` | Create collection, upsert points, search with payload filters (`document_id`, `tenant_id`). |
| `ingest.py` | Full ingest pipeline: optional PII → chunk → embed → write SpiceDB tuples → write Qdrant. If Qdrant fails after SpiceDB writes, it tries to undo. |

### 4.5 `src/secure_rag/agent/`

The question-answering brain.

| File | Role |
|------|------|
| `llm.py` | Talks to your OpenAI-compatible server (DeepSeek / vLLM). Strips `<think>...</think>` so R1-style models do not break the classifiers. |
| `guardrails.py` | Heuristic scan (regex for “ignore previous instructions” and similar). Optional LLM scan. Datamark wrappers around chunks. Label parser for `SAFE` / `MALICIOUS`. |
| `tools.py` | Fake tools (`send_email`, `lookup_secret`). SpiceDB must allow `execute` before they run. Used in the research benchmark, not in the normal `/query` path. |
| `graph.py` | The LangGraph workflow. `query_rag_system()` is what `/query` and the CLI call. |

### 4.6 `src/secure_rag/audit/`

| File | Role |
|------|------|
| `events.py` | Appends one JSON object per line to `AUDIT_LOG_PATH` (default `logs/audit.jsonl`). |
| `otel.py` | Optional OpenTelemetry tracing hooks. |

### 4.7 `src/secure_rag/benchmark/`

Research evaluation, not the live API.

| File | Role |
|------|------|
| `datasets.py` | Paths to `benchmarks/` fixtures and a download cache. |
| `adapters.py` | Builds the AuthInject-RAG attack cases. |
| `runner.py` | Runs many configs × cases and scores them. |
| `scoring.py` | Marks leakage, injection success, utility, Wilson 95% intervals. |
| `analyze.py` | Reads the JSONL of raw rows and writes a summary table JSON. |

### 4.8 Compatibility shims (old import paths)

These exist so older scripts still import:

- `src/main.py` → CLI
- `src/data_functions/` → old load/query names
- `src/database/` → old SpiceDB / Chroma names, now Qdrant

Prefer `secure_rag.*` for new work.

### 4.9 Everything else in the repo

| Path | Role |
|------|------|
| `.env` / `.env.example` | Your local config. Never commit real secrets. |
| `docker-compose.yml` | Postgres, SpiceDB, Qdrant, optional API container. |
| `tests/` | Automated tests. Run with `pytest`. |
| `docs/` | Research write-ups plus this workflow. |
| `experiments/` | Older experiment scripts and **result files** you generate. |
| `benchmarks/fixtures/` | Built attack cases (`authinject_cases.json`). |
| `k8s/` and `helm/` | Deploy to Kubernetes later. Not needed on a single VM. |
| `pyproject.toml` | Package name, version, dependencies, CLI entry points. |

---

## 5. How ingest works (step by step)

This is what happens on `POST /ingest` (and on CLI “ingest PDF”).

1. FastAPI checks the JWT. The owner is **the person in the token**, not a field you send.
2. Each input string is optionally passed through Presidio (`redact_pii`, default true).
3. Text is split into overlapping word chunks.
4. Each chunk is embedded (`EMBED_BACKEND`: `gemini` or `hash`).
5. SpiceDB is told:
   - this user owns the document
   - the document belongs to this tenant
   - the owner (and extra `viewers`) are members of that tenant
   - each chunk belongs to the parent document
6. Qdrant stores one point per chunk: vector + payload (`chunk_id`, `document_id`, `tenant_id`, text, provenance hash, taint flag).
7. An audit event `ingest.completed` is written.
8. The HTTP response is a small JSON object (document id, chunk count, provenance). It is **not** stored as a separate “ingest results file”. The lasting copies are Qdrant + SpiceDB + the audit line.

If you ingest the same `document_id` again, the new chunks replace the old ones for that document in the vector store.

---

## 6. How a query works (step by step)

This is what happens on `POST /query`.

### Step A — Identity

The token is decoded. `user_id` and `tenant_id` come from the token only.

### Step B — Input guard (`guard_input`)

- The question is anonymized (PII hidden).
- Outside `APP_ENV=test`, a classifier asks the LLM: reply `SAFE` or `MALICIOUS`.
- `MALICIOUS` stops the request.
- If the label cannot be read and `LLM_FAIL_CLOSED=true`, the request also stops.

### Step C — Retrieve (`retrieve`)

The anonymized question is embedded and sent to Qdrant.

**Filtering modes:**

| Mode | What happens | When to use it |
|------|----------------|----------------|
| `pre` (default, recommended) | SpiceDB lists document ids this user may view. Qdrant search is filtered to those ids (and the current tenant). Unauthorized chunks never enter the prompt. | Production and the “authorization-first” paper condition. |
| `post` | Search first, then check each hit in SpiceDB. Discarded ids are counted as **structural exposure**. | Research: measure how much leakage a naive RAG would have. |
| `none` | Search by similarity only. No access filter. | Ungated baseline in the benchmark. Unsafe for real users. |

If you pass `document_id` in the body and you are **not** allowed to view it, `pre` returns no context.

### Step D — Verify (`verify_and_rerank`)

- Heuristic injection scan on each kept chunk.
- Optional LLM scan of each chunk (`ENABLE_LLM_INJECTION_SCAN`).
- Injected chunks can be dropped.
- Remaining chunks can be re-ordered by the LLM.

If nothing is left and we still have rewrite budget (`MAX_AGENT_STEPS`), go to rewrite. Otherwise generate (which may say “no relevant context”).

### Step E — Optional rewrite (`rewrite_query`)

The LLM restates the search query. Then retrieve runs again. This loop is capped.

### Step F — Generate (`generate`)

- If datamarking is on, each chunk is wrapped with clear “this is data, not instructions” markers.
- The isolated prompt tells the model: use only this context; context is untrusted.
- DeepSeek writes the answer.
- In `APP_ENV=test` the “answer” is the joined chunks so tests stay deterministic without a live model.

### Step G — Output guard (`guard_output`)

- PII in the answer is hidden (except in test env).
- Audit event `query.completed` is appended: who asked, tenant, document filter, injection flag, retrieved chunk ids, LLM call count.
- JSON is returned to the client. **The full answer is not written to a results folder.** Only the audit line (and whatever you copy from the HTTP response) remains.

---

## 7. HTTP API (how to use the app)

Start the API from the project root, with the venv active:

```bash
uvicorn secure_rag.api.app:app --host 0.0.0.0 --port 8080
```

Keep Qdrant and SpiceDB running (`docker compose up -d postgres spicedb qdrant`). Keep DeepSeek running on the port in `LLM_BASE_URL`.

### 7.1 Health

```bash
curl -s http://127.0.0.1:8080/health
# {"status":"ok"}

curl -s http://127.0.0.1:8080/ready
# {"ready": true/false, "checks": {"qdrant": ..., "spicedb": ...}}
```

`/health` only means the process is up. `/ready` checks Qdrant and SpiceDB.

### 7.2 Get a token (development only)

`/token` is **disabled** when `APP_ENV=production`. In development:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/token \
  -H "content-type: application/json" \
  -d '{"user_id":"alice","tenant_id":"finance"}' | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

Save `$TOKEN` and send it on every later call:

```text
Authorization: Bearer <token>
```

### 7.3 Ingest text

```bash
curl -s -X POST http://127.0.0.1:8080/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -d '{
    "document_id": "finance-policy",
    "texts": ["Quarterly close requires dual control. Payroll hash CANARY_FIN_A1."],
    "viewers": ["alice"],
    "redact_pii": false
  }'
```

| Field | Meaning |
|-------|---------|
| `document_id` | Name you will search later. |
| `texts` | List of strings (pages or paragraphs). |
| `viewers` | Extra user ids who may view the document. The token user is already the owner. |
| `redact_pii` | `true` hides identifiers before storage. Use `false` for canary / benchmark text you must keep exact. |

### 7.4 Ask a question

```bash
curl -s -X POST http://127.0.0.1:8080/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -d '{
    "query": "What dual control is required for quarterly close?",
    "document_id": "finance-policy",
    "filtering_mode": "pre"
  }'
```

| Field | Meaning |
|-------|---------|
| `query` | The question in plain language. |
| `document_id` | Optional. Empty = search all documents this user may view. |
| `n_results` | How many chunks to keep (default 5). |
| `filtering_mode` | `pre`, `post`, or `none`. |
| `enable_indirect_injection_scan` | Heuristic (and LLM if enabled in settings) scan. |
| `enable_context_isolation` | Use the stricter generator prompt. |

**Response fields:**

| Field | Meaning |
|-------|---------|
| `answer` | Text from the model (or an error / security message). |
| `contexts` | Chunk texts that were used. |
| `retrieved` | Chunk ids, document ids, scores. |
| `anonymized_query` | The question after PII hiding (this is what was searched and sent to the LLM). |
| `diagnostics` | Counts: allowed documents, discarded chunks, injection flags, and so on. |

### 7.5 List documents you can see

```bash
curl -s http://127.0.0.1:8080/permissions \
  -H "Authorization: Bearer $TOKEN"
```

---

## 8. Interactive CLI

```bash
python src/main.py
# or
secure-rag
```

It asks for username and tenant, mints a local token, then:

1. query  
2. ingest PDF  
3. list docs  
4. change filtering mode  
5. exit  

Use this on a VM when you do not want to type curl. The same code path as the API is used for query and ingest.

---

## 9. First-time setup (local PC or VM)

### 9.1 One-time

```bash
cd ~/01-secure-agentic-rag   # or your Windows project path
python -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1

pip install -e ".[dev]"
python -m spacy download en_core_web_sm

cp .env.example .env    # Windows: copy .env.example .env
```

Edit `.env`. The values that usually matter on a VM with local DeepSeek:

```env
APP_ENV=development
LLM_BASE_URL=http://127.0.0.1:30000/v1
LLM_MODEL=deepseek-ai/DeepSeek-R1-Distill-Llama-8B
LLM_API_KEY=EMPTY
EMBED_BACKEND=hash
SPICEDB_ENDPOINT=localhost:50051
SPICEDB_PRESHARED_KEY=foobar
QDRANT_URL=http://localhost:6333
JWT_SECRET=change-me-to-a-long-random-secret
```

`LLM_MODEL` must be **exactly** the id your server lists at `/v1/models`. If you use Gemini embeddings instead of hash, set `EMBED_BACKEND=gemini` and `GOOGLE_API_KEY`.

Always run Python commands with the venv active. `ModuleNotFoundError: secure_rag` means you used system Python.

### 9.2 Start data services

```bash
docker compose up -d postgres spicedb qdrant
docker compose ps
```

You do **not** have to start the `api` container if you run uvicorn on the host. If you do start the `api` service, it listens on host port **8080** and talks to SpiceDB/Qdrant by Docker DNS names.

### 9.3 Start DeepSeek, then the API

Confirm the model:

```bash
curl -sS http://127.0.0.1:30000/v1/models
```

Then:

```bash
source .venv/bin/activate
uvicorn secure_rag.api.app:app --host 0.0.0.0 --port 8080
```

Do not point `LLM_BASE_URL` at 8080. That is the RAG API. The model has its own port.

### 9.4 Tests (no live model required)

```bash
pytest tests -q
```

Tests force `APP_ENV=test`, hash embeddings, and in-memory Qdrant.

---

## 10. Where everything is stored

Nothing important lives only in RAM after a successful ingest (except when `QDRANT_IN_MEMORY=true`).

### 10.1 Document text and vectors — Qdrant

- Docker volume: `qdrant_data` (see `docker-compose.yml`).
- HTTP UI/API: `http://localhost:6333`.
- Collection name: `QDRANT_COLLECTION` (default `authinject_chunks`).
- Each point payload includes `text`, `document_id`, `tenant_id`, `chunk_id`.

This is the searchable corpus. If you wipe the Qdrant volume, you must ingest again.

### 10.2 Who may read what — SpiceDB + Postgres

- SpiceDB gRPC: `localhost:50051`.
- SpiceDB stores tuples in Postgres (`postgres_data` volume).
- Schema file in git: `src/secure_rag/authz/schema.zed`.
- The live schema is loaded by the app client on connect.

This is **not** the document text. It is only relations (owner, viewer, tenant member, chunk parent).

### 10.3 Identity — JWT, not a user database

There is no user table. `/token` signs a JWT with `JWT_SECRET`. Production is expected to replace this with a real identity provider. If you lose the secret, old tokens stop working.

### 10.4 Live query answers — HTTP only + audit line

A successful `/query` returns JSON to the caller. The durable copy is one line in the audit file (see next section). We do **not** write answers into Qdrant.

### 10.5 Audit log — `logs/audit.jsonl`

Controlled by `AUDIT_LOG_PATH`. Default: `logs/audit.jsonl`.

Each line is one JSON object, for example:

- `ingest.completed`
- `query.completed`

Typical fields: time (`ts`), event name, `user_id`, `tenant_id`, `document_id`, filtering mode, injection flag, retrieved chunk ids, `llm_calls`.

This file grows forever until you rotate or delete it. It is the operational history of the running app.

### 10.6 Research benchmark results — `experiments/results/`

When you run the factorial evaluation:

```bash
python -m secure_rag.benchmark.adapters
python -m secure_rag.benchmark.runner --repeats 1 --split test --out experiments/results/authinject_eval.json
python -m secure_rag.benchmark.analyze experiments/results/authinject_eval.jsonl
```

| File | What it contains |
|------|------------------|
| `experiments/results/authinject_eval.json` | Summary rates per config (C0–C6), case count, repeats. |
| `experiments/results/authinject_eval.jsonl` | One JSON object per case run (raw scores, answer preview, latency). |
| `experiments/results/authinject_tables.json` | Recomputed tables from the JSONL (from `analyze`). |

Configs in the runner:

| Config | Idea |
|-------|------|
| C0_ungated | No auth filter, no injection defenses |
| C1_postfilter | Check permissions after retrieval |
| C2_authz_first | `pre` filter only |
| C3_datamark | Datamark + isolation, no auth filter |
| C4_scanner | Heuristic injection scan only |
| C5_combined | `pre` + scan + isolation + datamark |
| C6_action_authz | Combined plus tool permission checks in the tool path |

The runner sets `APP_ENV=test` unless you already set it. That means **no live DeepSeek** unless you change that. For paper-quality numbers with your VM model, you run a live job separately and still write JSON/JSONL under `experiments/results/`.

### 10.7 Benchmark fixtures — `benchmarks/`

- `benchmarks/manifest.json` — dataset names and licenses.
- `benchmarks/fixtures/authinject_cases.json` — generated cases (created by the adapters command).
- `benchmarks/.cache/` — downloaded public datasets (gitignored; not committed).

### 10.8 Docker disk

`docker volume ls` shows `postgres_data` and `qdrant_data`. Removing them deletes permissions and vectors.

### 10.9 What is **not** stored

- Full LLM chain-of-thought (stripped before use; not logged as a full transcript).
- The JWT secret (only in `.env`).
- Raw `.env` values in the audit log (do not put secrets in queries if you can avoid it).

---

## 11. Typical end-to-end day on the VM

1. Start Docker: Postgres, SpiceDB, Qdrant.  
2. Start vLLM / DeepSeek. Confirm `/v1/models`.  
3. Activate `.venv`. Confirm `.env` `LLM_BASE_URL` and `LLM_MODEL`.  
4. Start uvicorn on 8080.  
5. Mint a token for `alice` / `finance`.  
6. Ingest a document.  
7. Query it with `filtering_mode: pre`.  
8. Optionally open `logs/audit.jsonl` to see the two events.  
9. When collecting paper numbers, run the benchmark commands and keep the files under `experiments/results/`.

A second user (example: `bob` in tenant `hr`) should **not** get finance chunks under `pre` mode, even if they ask the same question.

---

## 12. Feature flags (simple list)

Set these in `.env`. Restart the API after changes.

| Setting | Simple effect |
|--------|----------------|
| `ENABLE_INDIRECT_INJECTION_SCAN` | Drop chunks that look like attacks. |
| `ENABLE_LLM_INJECTION_SCAN` | Also ask the LLM if a chunk is an attack (costs extra calls). |
| `ENABLE_CONTEXT_ISOLATION` | Stricter “context is not instructions” prompt. |
| `ENABLE_DATAMARKING` | Wrap chunks in data markers. |
| `ENABLE_ACTION_AUTHZ` | Tools must pass SpiceDB `execute`. |
| `MAX_AGENT_STEPS` | How many retrieve/rewrite loops. |
| `MAX_LLM_CALLS` | Hard cap on model calls per request. |
| `LLM_FAIL_CLOSED` | Bad classifier output = block, not proceed. |
| `PII_ENTITIES` | Override which Presidio types to hide. Empty = safe default list. |
| `PII_SCORE_THRESHOLD` | How confident Presidio must be (default 0.35). |
| `EMBED_BACKEND` | `hash` (offline) or `gemini` (needs API key). |

---

## 13. If something goes wrong

| Symptom | Likely cause |
|---------|----------------|
| `No module named 'secure_rag'` | Venv not activated, or `pip install -e .` not run. |
| `LLM invocation failed` / connection error | Wrong `LLM_BASE_URL` or uvicorn was started before you edited `.env`. Restart uvicorn. |
| Model 404 / unknown model | `LLM_MODEL` does not match `/v1/models`. |
| Ingest 500 about SpiceDB relationships | Duplicate tuples; current client dedupes. Restart with latest code. |
| Answer talks about `<DATE_TIME>` | Old code redacted “Quarterly”. Update `pii.py` and restart. No re-ingest needed if you used `redact_pii: false`. |
| Empty contexts | User not in SpiceDB as viewer/owner/tenant member, or `document_id` not allowed. Check `/permissions`. |
| Docker permission denied | Add your user to the `docker` group, or use `sudo`. |

---

## 14. Research vs product

Use the **API** when you want a working secure RAG service.

Use the **benchmark runner** when you want tables for the paper (leakage rates, injection success, utility, cost). Those tables are the files in `experiments/results/`. They are separate from Qdrant. Wiping Qdrant does not delete your saved JSON results; deleting `experiments/results/` does.

---

## 15. One-page cheat sheet

```text
Install:     pip install -e ".[dev]"
Services:    docker compose up -d postgres spicedb qdrant
LLM:         your vLLM on LLM_BASE_URL
API:         uvicorn secure_rag.api.app:app --port 8080
Token:       POST /token
Ingest:      POST /ingest
Ask:         POST /query
Who can see: GET /permissions
Audit:       logs/audit.jsonl
Vectors:     Qdrant :6333
Permissions: SpiceDB :50051 (Postgres behind it)
Paper runs:  experiments/results/*.json and *.jsonl
Tests:       pytest tests -q
```

That is the complete workflow of this repository.
