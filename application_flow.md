# Secure Agentic RAG: Application Flow

This document outlines the end-to-end data and execution flow of the Secure Agentic RAG system. It details how documents are indexed, how security permissions are registered, and how user queries are resolved through different access control mechanisms.

## 1. System Initialization & User Context

When the application (`src/main.py`) starts, the following initialization occurs:

1. **User Identity Setup**: The user is prompted to enter their username. This name represents their identity in the system (`ACTIVE_USER`) and is used for all subsequent permission checks in SpiceDB.
2. **Security Mode Selection**: The user selects the Access Control Filtering Mode:
   - `PRE` (Pre-filtering)
   - `POST` (Post-filtering)
   - `NONE` (Baseline, no security)
3. **Database Connections**: Connections to ChromaDB (for vector search) and SpiceDB (for Zanzibar-based Access Control) are established.

---

## 2. Document Ingestion Flow

When a user opts to upload a new PDF document, the `index_new_pdf` workflow is triggered.

### Step-by-Step Breakdown:
1. **PDF Parsing (`load_document.py`)**: The PDF is read using LlamaIndex's `PDFReader` to extract raw text.
2. **PII Anonymization**: The text is passed through **Microsoft Presidio**. It uses an Analyzer and an Anonymizer (along with custom regex patterns defined in `.env`) to identify and redact sensitive information (e.g., ABN numbers, emails, phone numbers) before they are stored.
3. **Chunking**: The anonymized text is split into overlapping chunks (e.g., 1000 characters with 200 overlap).
4. **Embedding Generation**: The chunks are sent to Google's **Gemini API** (`models/gemini-embedding-001` or similar) to generate vector embeddings.
5. **Access Control Configuration**: The user is prompted to provide a comma-separated list of usernames who are authorized to view this document. The `ACTIVE_USER` who uploaded it is automatically designated as the `owner`.
6. **Storage in ChromaDB**: 
   - A sanitized collection name is created based on the file name.
   - Each chunk is stored with its embedding and crucial **metadata**:
     ```json
     {
       "document_id": "sanitized_filename",
       "chunk_id": "sanitized_filename_chunk_1",
       "source": "path/to/file.pdf"
     }
     ```
7. **Registering Relationships in SpiceDB**:
   - The application writes Relationship Tuples to SpiceDB to build the permission graph:
     - `document:doc_id#owner@user:active_user`
     - `document:doc_id#viewer@user:authorized_viewer_1`
     - `chunk:chunk_id#parent_document@document:doc_id` (For every chunk generated)

---

## 3. Query & Security Guardrails Flow (LangGraph Agent Loop)

When the user enters a query, it is processed through a stateful multi-step agent loop using **LangGraph** designed to enforce multiple layers of security, verify context relevance, and dynamically retry queries:

### The LangGraph Agent Loop Workflow
The workflow transitions through the following nodes based on state and conditional routing logic:
1. **Input Guardrails (`guard_input` node)**:
   - **PII Scrubbing**: Sanitizes sensitive user query details (like email addresses and phone numbers) using Microsoft Presidio.
   - **Prompt Injection Prevention**: Uses a security LLM to evaluate the anonymized query for jailbreak attempts or malicious commands.
2. **Context Retrieval (`retrieve` node)**:
   - Evaluates access rights (via SpiceDB) and fetches semantic matches (via ChromaDB). (See *Access Control Mechanisms* below).
3. **Verification & Re-ranking (`verify_and_rerank` node)**:
   - **Indirect prompt injection filter (first mitigation)**: each retrieved chunk is scanned with a local regex heuristic, then (if needed) a Groq `SAFE`/`INJECTION` classifier. Poisoned chunks are discarded and recorded in diagnostics. See `docs/threat_model.md`.
   - An evaluator LLM grades the relevance of the remaining chunks.
   - Irrelevant chunks (scoring $< 3/5$ or flagged as irrelevant) are discarded.
   - The remaining verified chunks are re-ranked in descending order of relevance.
4. **Conditional Retry / Query Rewriting (`rewrite_query` node)**:
   - If no relevant contexts remain after verification, the query is passed to a reformulation node.
   - An LLM rewrites the query to improve semantic search matching, and loops back to **Context Retrieval** (up to 2 retry attempts).
5. **Answer Generation (`generate` node)**:
   - Formulates the final response using only the verified and ranked context chunks.
   - Retrieved text is wrapped in `<context>` tags and treated as passive data (context isolation).
6. **Output Guardrails (`guard_output` node)**:
   - **Groundedness Check**: Validates that the answer is fully grounded in the retrieved chunks, blocking hallucinations.
   - **PII Anonymization**: Scrubs any sensitive info from the final answer before presenting to the user.

---

## 4. Access Control Mechanisms (Retrieval Phase)

The Context Retrieval step behaves differently depending on the chosen **Filtering Mode**.

### SpiceDB Schema Context
The entire permission system evaluates against this schema:
```zed
definition user {}

definition document {
    relation viewer: user
    relation editor: user
    relation owner: user
    permission view = viewer + editor + owner
}

definition chunk {
    relation parent_document: document
    permission view = parent_document->view
}
```

### A. Pre-Filtering Mode (PRE)
*Checks permissions BEFORE searching the vector database.*

1. **SpiceDB Lookup**: The app calls `spicedb.lookup_resources("document", "view", "user", ACTIVE_USER)`.
2. **Graph Traversal**: SpiceDB traverses its graph and returns a list of all `document_id`s the user has the right to view.
3. **ChromaDB Search**: The app performs a vector search in ChromaDB, but attaches a strict `where` clause metadata filter: `{"document_id": {"$in": allowed_documents}}`.
4. **Result**: ChromaDB only searches and returns chunks from documents the user is explicitly allowed to see.
5. **LLM Generation**: The retrieved, authorized chunks are passed to the LLM (Groq) to generate the final answer.

### B. Post-Filtering Mode (POST)
*Searches the vector database first, then filters chunks based on permissions.*

1. **ChromaDB Search**: The app performs a global vector search in ChromaDB across all available data based on the query.
2. **Retrieval**: ChromaDB returns the top `N` most semantically relevant text chunks, regardless of permissions.
3. **SpiceDB Verification**: The app iterates through the retrieved chunks. For each chunk, it calls `spicedb.check_permission("chunk", chunk_id, "view", "user", ACTIVE_USER)`.
4. **Graph Traversal**: SpiceDB checks if the user has `view` permission on that specific chunk (by resolving the `parent_document` relation up to the document level).
5. **Redaction**: Any chunk that returns `False` from SpiceDB is discarded.
6. **LLM Generation**: Only the chunks that passed the permission check are forwarded to the LLM to formulate the response.

### C. No Filtering Mode (NONE)
*Baseline RAG without access control.*

1. **ChromaDB Search**: Global vector search retrieves the most relevant chunks.
2. **LLM Generation**: The chunks are immediately passed to the LLM. No SpiceDB checks are performed.

---

## 5. Response Generation & Transparency

Once the secure context (authorized chunks) is constructed, the prompt is sent to the LLM. The application then displays:
- The generated **Answer**.
- **Security Diagnostics**: Shows the active user, filtering mode, and statistics (e.g., number of chunks discarded in POST mode, or allowed documents in PRE mode).
- **Sources**: The actual text snippets that were passed to the LLM, ensuring transparency and trust in the system's generation logic.
