# Pull Request: [Week 02] Proposal Draft, Literature Review, and RAG Skeleton

## Summary of Changes

This Pull Request completes the tasks assigned for **Week 2**, including implementing the core RAG skeleton, expanding literature review, finishing the proposal, and cleaning up repository tracking of binary files.

### 1. Ingestion, Embedding, and Storage Pipeline
* **PDF Ingestion:** Integrated `LlamaIndex` with a `SentenceSplitter` configured for a chunk size of `1000` tokens and `200` tokens overlap to parse PDFs cleanly into indexable segments.
* **Embeddings:** Fully integrated the **Gemini API** (`models/gemini-embedding-001`) with automatic model resolution at runtime for generating high-quality 768-dimensional embeddings for both document ingestion and user queries.
* **Vector Store:** Setup persistent `ChromaDB` integration under the `chroma_db/` directory, allowing fast, local storage and retrieval of embedded chunks.

### 2. Interactive CLI RAG Interface
* Implemented an interactive CLI application inside `src/main.py` which:
  1. Detects if the database collection is empty, and automatically parses and indexes the default `datasets/system design.pdf`.
  2. Runs a request/response loop enabling user queries.
  3. Uses `Groq API` (Llama-3.1-8b-instant) to generate responses based *only* on context retrieved from the database.
  4. Displays retrieved source snippets transparently.

### 3. Documentation & Project Planning
* **Proposal:** Completed Section 3 (Research Questions) and Section 4 (Proposed Methodology) in `docs/proposal.md`.
* **Literature Review:** Added 3 key papers to `docs/literature-review.md` focusing on security and access control in RAG/agent architectures.
* **Weekly Log:** Updated `docs/weekly-progress.md` to log Week 2 updates, checklists, and blockers.

### 4. Repository & Git Hygiene
* Untracked `chroma_db/chroma.sqlite3` and `datasets/system design.pdf` from the Git index using `git rm --cached` to prevent committing heavy binary files.
* Configured `.gitignore` to explicitly ignore `datasets/**/*.pdf` files and persistent sqlite DB files.

---

## Verification Plan

### Automated Unit Tests
Executed the query engine test suite (`python -m unittest tests/test_query_engine.py`):
- `test_retrieve_context`: Mocks Gemini API call and verifies document retrieval from ChromaDB.
- `test_answer_query`: Mocks OpenAI/Groq client and validates formatted context parsing.
- `test_query_rag_system`: Verifies end-to-end routing of user query through embedding extraction and Groq model response.
- **Status:** **PASS**

### Manual Run
You can verify the interactive system by running:
```bash
python src/main.py
```
It will build the local Chroma index if not already present and start the query session.
