# Demo guide

Everything runs through one script, `./run.sh`. The main demo needs no Docker, no LLM and no API keys.

## 1. Once, before the demo (about 5 minutes)

```bash
cd ~/Desktop/Projects/01-secure-agentic-rag
git switch feat/unified-demo
./run.sh setup
./run.sh check
```

`check` should end with `141 passed`, every checksum `OK`, and `Derived results match the committed scored rows.`

## 2. The demo: one command

```bash
./run.sh demo
```

Press Enter to move to the next step. The run ends with `26/26 checks passed`, so the audience can see that every claim was checked. It is one story: Alice and Bob work in the finance tenant, Dave owns the payroll, and Carol is in the HR tenant.

| Step | What the screen shows | What to say |
|---|---|---|
| 1. Identity | Alice's JWT and its claims | Who is asking comes from a signed token, never from the request body. |
| 2. Ingestion, PII, ownership | Uploaded text next to stored text, with the name, email and phone replaced; Bob's overwrite refused | PII is removed before anything is stored, and SpiceDB records who owns and who may read each document. |
| 3. Isolation | Alice, Bob and Carol ask the same question | Only Alice gets the answer. PII is also removed from questions. |
| 4. Filtering modes | `none` leaks the payroll secret, `post` hides it but still searched it, `pre` never touches it | This is why the filter has to run inside the vector index (Authorization First Retrieval). |
| 5. Injection detector | Four sample lines, then a poisoned vendor FAQ with defenses off and on | Hidden instructions are dropped before the model reads them, and each hit is logged. |
| 6. Continuous authorization | Access revoked after turn 1; AFR alone reuses the old chunk, our system drops it | Our main contribution: memory is checked again before every answer. |
| 7. Tool guard | A hidden `send_email` call runs without the guard and is denied with it | The model can propose a tool call, but SpiceDB decides whether it runs. |
| 8. Fail closed | SpiceDB is made unreachable; query, tool call and upload are all refused | When the permission service is down, nothing gets through. |
| 9. REST API | The same checks through the FastAPI endpoints | No token gives 401; Bob's overwrite gives 403. |
| 10. Audit log | Event counts, the chain verifies, an edited copy fails at the edited line | Every decision is in a log that shows any edit. |

Useful variations:

```bash
./run.sh demo --list          # the 10 steps
./run.sh demo --steps 4,6,7   # repeat only some steps
./run.sh demo --no-pause      # run straight through
```

## 3. The playground: upload your own files and query them live

```bash
./run.sh ui
```

Open http://127.0.0.1:8501. It starts empty; nothing is preloaded. Everything you click runs the real pipeline: Presidio, SpiceDB checks, Qdrant search, the injection detector, the tool guard and the audit log.

| Panel | What you can do |
|---|---|
| Acting as | Switch between alice, bob, dave (finance) and carol (hr), or type any user and tenant. Each switch mints a new JWT. |
| Upload a document | Pick a PDF, TXT or MD file, or paste text, or start from a sample. Set viewers and choose whether to remove PII. The result shows the uploaded text next to what was stored. |
| Documents in the index | Every document with its owner, viewers and whether you may read it. Owners can share, revoke (bumps the policy version) and delete. |
| Ask | Pick pre, post or none; switch the injection detector, context isolation, datamarking, tool guard and continuous authorization on or off; turn on chat memory for multi turn questions. The answer shows which chunks reached the model and which were forbidden. |
| Compare none, post, pre | Runs the same question in all three modes side by side. |
| Tool permissions | Grant or remove send_email for the current user and watch the tool guard follow SpiceDB. |
| Simulate SpiceDB outage | Every query, upload and tool call is refused while it is on. |
| Audit log | Updates live; Verify chain replays the HMAC chain. |

The left panel has a short "Try this story" list that walks through every defense in about five minutes. `./run.sh ui --services` runs the same page against SpiceDB and Qdrant in Docker. The playground exposes research modes, so it refuses to start with `APP_ENV=production`.

## 4. Optional: the REST API live (two terminals)

Terminal 1:

```bash
./run.sh api
```

Open http://127.0.0.1:8080/docs to show the endpoints.

Terminal 2:

```bash
./run.sh curl-demo
```

This runs the same story with real HTTP calls: uploads with PII, Bob and Carol blocked, the three filtering modes, the poisoned FAQ caught, Bob's overwrite refused with 403, and a request without a token refused with 401. Then verify the audit log the API wrote:

```bash
./run.sh audit logs/api-audit.jsonl
```

Stop the API with Ctrl+C. Its data lives in memory, so it starts empty each time.

## 5. Optional: the results

```bash
./run.sh results     # committed tables, hypothesis checks, detector comparison, Week 8 track
./run.sh benchmark   # re-runs all 160 cases on 11 configurations in under a minute, then restores the committed files
```

## 6. Optional: real SpiceDB and Qdrant (needs Docker)

```bash
./run.sh demo-services
./run.sh stop
```

This starts Postgres, SpiceDB and Qdrant with docker compose and runs the same demo against them (23 checks; the REST step is skipped because the API's agent loop needs an LLM). A warning that the Qdrant client and server versions differ is harmless.

## 7. Optional: the interactive menu

```bash
./run.sh cli
```

Log in as any user and tenant, ingest a PDF (option 2), query it (option 1), list your documents (option 3) and switch between `pre`, `post` and `none` (option 4). Offline it starts empty.

## 8. Only with a running LLM

If the model server in `.env` is up, the same commands work with real generation:

```bash
./run.sh demo --mode live
./run.sh api --live
```

Avoid this for the demo itself: answers then depend on the model.

## Every way to run the project

| Before | Now |
|---|---|
| `secure-rag` CLI | `./run.sh cli` |
| upload and query in a browser | `./run.sh ui` |
| `uvicorn` or `secure-rag-api` | `./run.sh api` |
| `docker compose up` | `./run.sh services`, `./run.sh stop` |
| `pytest` | `./run.sh check` |
| benchmark runner and analysis | `./run.sh benchmark`, `./run.sh results` |
| Week 8 track and detector comparison | `./run.sh results` (committed numbers; rerunning needs an LLM or a separate venv) |
| curl walkthrough | `./run.sh curl-demo` |
| audit verification | `./run.sh audit` |
| Kubernetes and Helm | manifests in `k8s/` and `helm/authinject-rag/`; not part of the local demo |

## Facts to get right when presenting

* The test suite has 141 tests.
* The benchmark has 160 cases and 11 configurations (B0 to B3, P1 and P2, A1 to A5).
* The ungated mode is called `research_baseline_none` in the API and `none` in the CLI. The API refuses it, and `post`, when `APP_ENV=production`.
* The REST API does not take chat memory, so stale access is shown in demo step 6, not with curl.
* There is no separate anomaly detector. Suspicious content is caught by the prompt injection detector (regex rules, plus an LLM classifier when a model is configured).
* All numbers come from the offline run. The live run on several models is still to do.

## If something goes wrong

| Problem | Fix |
|---|---|
| `No .venv yet` | `./run.sh setup` |
| `Command 'python' not found` | Use `./run.sh`; it calls `.venv/bin/python` itself |
| Port 8080 is busy | `API_PORT=8090 ./run.sh api`, then `API_PORT=8090 ./run.sh curl-demo` |
| Port 8501 is busy | `UI_PORT=8502 ./run.sh ui` |
| Docker image download times out | Run `./run.sh services` again; finished layers are kept |
| `The API is not running` from curl-demo | Start `./run.sh api` in another terminal first |
