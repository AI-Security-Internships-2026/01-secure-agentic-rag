# Weekly Progress Log: Secure Agentic RAG for Cybersecurity Knowledge Bases

**Student:** _Taha Bin Hanif_
**GitHub username:** _TahaHanif2424_

---

## How to Use This File

Add a new section every Friday before opening your weekly Pull Request.
Be honest — problems and blockers are normal and help your supervisor support you.

---

## Week 1

**Branch:** `your-name-week-01`
**PR link:** _[Add link after opening PR]_

### Completed this week
- [x] Read README and proposal
- [x] Set up local environment (Python venv, dependencies)
- [x] Ran `src/main.py` successfully
- [x] Wrote personal introduction (below)
- [x] Identified 5 related papers / tools / datasets

### Personal Introduction
I am Taha Bin Hanif a final year Computer Science student from NUST. My experties are Web Development, Agentic AI, RAG, DevOps. I have worked in couple of organization as a Full Stack Developer. Currently I'm more into agentic AI and DevOps. I am exploring these fields more and hope to get enough knowledge of these. In this internship, I will try to learn RAG and Agentic in more depth and will try to bring the concepts of cyber security in Agentic AI and RAG system so maintain secutiry and trust of the user.

### Problems / Blockers
Reading papers were a problem for me. I wasn't sure about what to read. And as a UG student it is very hard for us to focus and read research papaers. This was a step that took longer than i thought. But with consistency it was resolved and i was able to read those papers.

### Next week plan
- Read the 5 papers identified this week
- Complete `docs/proposal.md` draft
- Set up dataset download / preprocessing pipeline

---

## Week 2

**Branch:** `taha-week-02`
**PR link:** _[Add link after opening PR]_

### Completed this week
- Wrote personal introduction, updated checkboxes, and updated README title per Week 1 feedback.
- Completed proposal.md Section 3 (Research Questions) and Section 4 (Proposed Methodology).
- Added three new research papers on RAG access control and agent security to literature-review.md.
- Built a PDF ingestion pipeline (LlamaIndex + SentenceSplitter + Gemini Embedding API) with local fallback.
- Implemented persistent ChromaDB database client and query utilities.
- Implemented query retrieval and answering engine using Groq API.
- Implemented interactive CLI interface (src/main.py) which automatically embeds datasets/system design.pdf if ChromaDB is empty, and allows user Q&A.
- Untracked database and binary PDF files from Git repository and added them to `.gitignore`.

### Problems / Blockers
- Binary files like `chroma.sqlite3` and `system design.pdf` were previously committed and tracked, which bypassed the `.gitignore` rules. This was resolved by running `git rm --cached` on these paths.

### Next week plan
- Begin implementation of secure agentic reasoning and evaluation using security controls. (Completed)
- Conduct initial evaluation of security threats against the RAG system. (Completed)

---

## Week 3

**Branch:** `taha-week-03`
**PR link:** _[Add link after opening PR]_

### Completed this week
- Configured SpiceDB client library (`authzed`) for Fine-Grained Authorization / ReBAC.
- Built a unified SpiceDB client ([spicedb_client.py](file:///c:/Users/tahah/OneDrive/Desktop/01-secure-agentic-rag/src/database/spicedb_client.py)) supporting live gRPC connections and an in-memory `SpiceDBSimulator` fallback engine.
- Implemented automatic SpiceDB schema verification and writing (`user`, `document`, `chunk` DSL definitions) upon client connection initialization.
- Integrated read-after-write consistency (`fully_consistent=True`) to eliminate eventual consistency replication latency in tests and interactive lookups.
- Enhanced text chunking ingestion in [load_document.py](file:///c:/Users/tahah/OneDrive/Desktop/01-secure-agentic-rag/src/data_functions/load_document.py) to write `document_id` and `chunk_id` to ChromaDB metadata and write relationship tuples to SpiceDB on ingestion.
- Implemented **Pre-filtering** (via `LookupResources`) and **Post-filtering** (via `CheckPermission`) RAG context authorization paths in [query_engine.py](file:///c:/Users/tahah/OneDrive/Desktop/01-secure-agentic-rag/src/data_functions/query_engine.py).
- Configured Docker Compose deployment ([docker-compose.yml](file:///c:/Users/tahah/OneDrive/Desktop/01-secure-agentic-rag/docker-compose.yml)) containing PostgreSQL backend database, transient auto-migrations setup (`spicedb-migrate`), and the SpiceDB server daemon.
- Created interactive CLI user switching (`\user`), filtering mode changes (`\mode`), and simulator scanner (`\spicedb`) commands inside [main.py](file:///c:/Users/tahah/OneDrive/Desktop/01-secure-agentic-rag/src/main.py) with permission metrics printouts.
- Built and ran a comprehensive test suite ([test_spicedb.py](file:///c:/Users/tahah/OneDrive/Desktop/01-secure-agentic-rag/tests/test_spicedb.py)) verifying access boundary correctness and database queries.

### Problems / Blockers
- Ran into initial SpiceDB connection errors due to the container running without the `serve` command and executing help by default. Resolved by updating the docker-compose commands and introducing a `spicedb-migrate` container to run schema migrations before the server starts.
- Encountered eventual consistency latency issues in test check permissions which was resolved by enforcing full consistency on read requests.

### Next week plan
- Integrate PII detection and masking.
- Implement comprehensive LLM guardrails (prompt injection, hallucination).
- Refactor the querying pipeline using LangChain.

---

## Week 4

**Branch:** `taha-week-04`
**PR link:** _[Add link after opening PR]_

### Completed this week
- Implemented Microsoft Presidio to automatically detect and mask PII (e.g., email addresses, phone numbers) to secure queries before they are sent to the embedding and LLM APIs.
- Re-architected the query processing pipeline in `query_engine.py` using LangChain Expression Language (LCEL).
- Developed and integrated 4 robust security guardrails into the new LCEL pipeline:
  1. **Input PII Guardrail** (Presidio-based query masking)
  2. **Prompt Injection Guardrail** (LLM-based detection of malicious instructions/jailbreaks)
  3. **Output Relevance Guardrail** (LLM-based validation to detect and block hallucinations)
  4. **Output PII Guardrail** (Presidio-based final output scrubbing)
- Updated `application_flow.md` to formally document the new LCEL Security Guardrails Pipeline.

### Problems / Blockers
- Encountered a runtime error (`Argument 'string' has incorrect type (expected str, got TextAccessor)`) when passing LangChain's `StrOutputParser` output to the Presidio Analyzer. Resolved this by explicitly casting the LCEL chain outputs to native Python `str` types before passing them to the spacy-based Presidio engines.

### Next week plan
- Finalize evaluation of the prototype on benchmark datasets.
- Write and format the final technical report.

---

## Week 5

**Branch:** `taha-week-05`
**PR link:** _[Add link after opening PR]_

### Completed this week
- Finalized initial evaluation of the prototype on benchmark datasets.
- Drafted and formatted the initial version of the final technical report.

### Problems / Blockers
- Had some initial variance in benchmark scores which was solved by setting the LLM temperature strictly to 0.

### Next week plan
- Clean up configuration setup and resolve Docker compose environment issues.

---

## Week 6

**Branch:** `taha-week-06`
**PR link:** _[Add link after opening PR]_

### Completed this week
- Resolved container startup and connection errors between the SpiceDB migration service (`spicedb-migrate`) and the backend database (`spicedb-postgres`).
- Cleaned up dependency listings in the virtual environment.

### Problems / Blockers
- Met minor DNS lookup issues in local Docker desktop on Windows, which was resolved by ensuring the database healthcheck passes before the migration driver attempts connection.

### Next week plan
- Implement multi-step agent reasoning and loop capabilities.

---

## Week 7

**Branch:** `week-07`
**PR link:** _[Add link after opening PR]_

### Completed this week
- Replaced the single-shot retrieval-generation LCEL chain in `query_engine.py` with a stateful **multi-step agent loop** using **LangGraph**.
- Added the following nodes in the LangGraph StateGraph:
  1. `guard_input`: Runs PII masking and prompt injection checks.
  2. `retrieve`: Vector search retrieval.
  3. `verify_and_rerank`: LLM-based chunk relevance evaluation, filtering, and score-based re-ranking.
  4. `rewrite_query`: Rewrites user query if no relevant context is verified, looping back to retrieval (max 2 steps).
  5. `generate`: Generates response from verified context.
  6. `guard_output`: Hallucination/groundedness validation and PII output anonymization.
- Optimized Presidio Analyzer initialization by explicitly loading the lightweight `en_core_web_sm` spaCy model (12MB) instead of the extremely heavy `en_core_web_lg` model (400MB).
- Refactored `tests/test_query_engine.py` to support LangGraph execution flows and mock `AIMessage` schemas.
- Updated `application_flow.md` to formally document the LangGraph Agent Loop workflow.

### Problems / Blockers
- Experienced validation failures in Pydantic during LLM mocking because of LangChain wrapping the mock in a callable `RunnableLambda` function. Resolved this by setting mock `side_effect` directly on the mock instance callable and using native `AIMessage` objects for return values.
- Slow network connection speed on the local machine made downloading the 400MB spaCy model impractical, which was resolved by switching to the 12.8MB lightweight model.

### Next week plan
- Prepare final project delivery.

---

## Week 8

**Branch:** current working tree
**PR link:** _[Add link after opening PR]_

### Completed this week
- Defined the retrieval / indirect prompt injection threat model in `docs/threat_model.md` (trust boundary at retrieved chunks, assets, adversary, attack patterns, eval protocol).
- Implemented the first mitigation in `query_engine.py`: local regex heuristic to drop poisoned chunks, XML context isolation, Groq scanner as a second layer; both layers are toggleable for ablation.
- Built a poisoned vs clean adversarial set (`experiments/datasets/adversarial_indirect_injection.json`) and an online-only ASR eval (`experiments/run_indirect_injection_eval.py`) that uses Groq over HTTPS — no extra local model installs.
- Wrote a full execution-and-results log: [`docs/task-execution-summary.md`](task-execution-summary.md) (how each task was run, files produced, ASR 60% → 0%).

### Problems / Blockers
- Local GPU/NLP downloads are impractical on this machine, so the eval path avoids Chroma, embeddings, spaCy, and Presidio and only calls Groq.

### Next week plan
- Ablation of agent loop vs defenses (accuracy and robustness).

