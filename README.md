# Kubernetes Native Secure Agentic RAG Prompt Injection Guardrails

> **CNIT/PNTLab Pisa · TECIP · Scuola Superiore Sant'Anna — AI Security Internship 2026**

---

## Research Problem
A scalable RAG pipeline where autonomous agents securely query restricted cybersecurity knowledge bases with enforced access control, audit logging, and robust prompt injection defenses.


---

## Objectives

1. Conduct a systematic literature review on the topic.
2. Design and implement a proof-of-concept prototype.
3. Evaluate the prototype on real or benchmark datasets.
4. Document findings in a final technical report.
5. Present results to the research group.

---

## Expected Deliverables

| Deliverable | Due |
|---|---|
| Literature review (`docs/literature-review.md`) | Week 2 |
| Architecture design document (`docs/proposal.md`) | Week 3 |
| Working prototype (`src/`) | Week 6 |
| Evaluation results (`experiments/results/`) | Week 7 |
| Final report (`docs/final-report.md`) | Week 8 |

---

## Recommended Technology Stack

```
Python, LangChain, OpenAI API, ChromaDB, FastAPI, Docker
```

See `requirements.txt` for pinned dependencies.

## Security evaluations

- [`docs/guardrail-comparison.md`](docs/guardrail-comparison.md) explains the prompt-injection and PII/secret guardrail benchmark.
- [`docs/indirect-injection-evaluation.md`](docs/indirect-injection-evaluation.md) explains the poisoned-context ASR evaluation and why it bypasses ChromaDB.
- [`docs/threat_model.md`](docs/threat_model.md) defines the indirect prompt-injection threat model.

---

## Weekly Workflow

```
Monday     – Review weekly tasks in tasks/week-XX.md
Tue–Thu    – Implementation / experiments
Friday     – Document progress in docs/weekly-progress.md
Friday     – Open weekly Pull Request from your branch → dev
```

---

## Branching Policy

| Branch | Purpose |
|---|---|
| `main` | Stable, supervisor-reviewed code only |
| `dev` | Integration branch — merge weekly PRs here |
| `<your-name>-week-XX` | Your working branch for each week |

**Students must never push directly to `main`.**

---

## Pull Request Policy

- One PR per week, targeting the `dev` branch.
- PR title format: `[Week XX] Brief description`
- PR description must reference the weekly task file and summarise what was done.
- A supervisor or co-student must review before merging.

---

## Getting Started

### 1. Prerequisites
Ensure you have the following installed on your machine:
- **Python 3.10+**
- **Docker Desktop** (with compose enabled)
- **API Keys**:
  - A [Groq API Key](https://console.groq.com/) for LLM generation, guardrails, and evaluations.
  - A [Google Gemini API Key](https://aistudio.google.com/) for generating document embeddings.

---

### 2. Clone the Repository
```bash
git clone https://github.com/AI-Security-Internships-2026/01-secure-agentic-rag.git
cd 01-secure-agentic-rag
```

---

### 3. Environment Configuration
Create a `.env` file in the root directory by copying the template:
```bash
cp .env.example .env
```
Open `.env` and fill in your keys and configuration details:
```env
# LLM Providers (OpenAI-compatible). Groq is the default; override for a VM DeepSeek server.
GROQ_API_KEY=gsk_...
GROQ_MODEL=openai/gpt-oss-20b
# LLM_BASE_URL=http://YOUR_VM_IP:8000/v1
# LLM_API_KEY=EMPTY
# LLM_MODEL=deepseek-chat
GOOGLE_API_KEY=AIzaSy...

# SpiceDB (Authzed) Configuration
SPICEDB_ENDPOINT=localhost:50051
SPICEDB_PRESHARED_KEY=foobar
```

#### Point generation at a DeepSeek model on a VM
The app uses LangChain `ChatOpenAI`, which talks to any **OpenAI-compatible** HTTP API. Groq is only the default `LLM_BASE_URL`. If DeepSeek is served with vLLM, Ollama, SGLang, or llama.cpp on the VM, set these in `.env` (comment out or ignore Groq):

```env
LLM_BASE_URL=http://YOUR_VM_IP:8000/v1
LLM_API_KEY=EMPTY
LLM_MODEL=deepseek-chat
```

1. On the VM, confirm the server exposes `/v1/chat/completions` (vLLM default port **8000**, Ollama **11434** with `/v1`, official DeepSeek cloud `https://api.deepseek.com/v1`).
2. Open the VM firewall (and cloud security group) for that port, or use an SSH tunnel from this laptop: `ssh -L 8000:127.0.0.1:8000 user@VM_IP`.
3. From this laptop, list models: `curl http://YOUR_VM_IP:8000/v1/models` — copy the `id` into `LLM_MODEL`.
4. Restart the CLI / eval so `python-dotenv` reloads `.env`. Embeddings still use `GOOGLE_API_KEY`; only chat/guardrails switch to DeepSeek.

---

### 4. Launch Local Services (Docker Compose)
Start the PostgreSQL metadata store and Authzed SpiceDB permission engine locally:
```bash
# Start all required backend services in the background
docker compose up -d
```
Verify that the `spicedb` and `postgres` containers are running healthily before continuing.

---

### 5. Setup Python Virtual Environment
```bash
# Create a virtual environment
python -m venv .venv

# Activate the virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows (Command Prompt):
.venv\Scripts\activate.bat
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Install project dependencies
pip install -r requirements.txt

# Download the lightweight NLP model required for Presidio PII guardrails
python -m spacy download en_core_web_sm
```

---

### 6. Run the Interactive CLI Application
Start the interactive RAG console:
```bash
python src/main.py
```
#### Interactive CLI Walkthrough:
1. **Enter Username**: Input your active user (e.g., `taha`, `admin`, `alice`).
2. **Select Access Control Filtering Mode**:
   - `[1]` **NONE**: No access check. Global search.
   - `[2]` **PRE**: Fetches allowed document IDs from SpiceDB first, then filters ChromaDB vector search.
   - `[3]` **POST**: Searches ChromaDB globally, then runs SpiceDB checks on each retrieved chunk, discarding unauthorized ones.
3. **Choose Document**: Select an existing indexed collection or choose the option to index/upload a new PDF document.
4. **Interactive Prompt Commands**:
   - Type `\user` to switch the active session user.
   - Type `\mode` to toggle between filtering modes on the fly.
   - Type `\change` to switch document databases.
   - Type `\spicedb` to print currently indexed simulator permissions.
   - Type `exit` to quit the session.

---

### 7. Run Automated Test Suites
To verify schema operations, database permissions, agent retry loops, and injection mitigations:

- **Run SpiceDB Access Control Tests**:
  ```bash
  python -m unittest tests/test_spicedb.py
  ```
- **Run LangGraph Query Engine Loop & Injection Mitigation Tests**:
  ```bash
  python -m unittest tests/test_query_engine.py tests/test_indirect_injection.py
  ```

---

## Roadmap to September 8, 2026

**Current state:** RAG stack (LangChain + ChromaDB + FAISS) with scalability testing done. Gap: no agent loop despite "agentic" in the project name — the current pipeline is single-shot retrieve-then-generate.

**Novel contribution target:** turn this into an actual *secure* agentic RAG by giving it a multi-step agent loop and defending it against indirect prompt injection carried in retrieved documents — a live, under-addressed threat in RAG security.

Threat model: [`docs/threat_model.md`](docs/threat_model.md). Adversarial eval (poisoned vs clean, ASR before/after):

```bash
python experiments/run_indirect_injection_eval.py
```

This experiment calls Groq over the network only. It does not download models or install extra packages.

Step-by-step execution log and tabulated results: [`docs/task-execution-summary.md`](docs/task-execution-summary.md).

| Date | Milestone |
|---|---|
| Aug 2 | Add a real multi-step agent loop (e.g. LangGraph) replacing the single-shot retrieve→generate chain: retrieve → verify/re-rank → generate |
| Aug 9 | Define the threat model for retrieval/indirect prompt injection (malicious instructions embedded in retrieved documents) and implement a first mitigation |
| Aug 16 | Build an adversarial eval set: poisoned vs. clean documents; measure attack success rate before/after mitigation |
| Aug 23 | Ablation: with/without agent loop, with/without defense — accuracy and robustness both measured |
| Aug 30 | Full benchmark against a non-agentic RAG baseline; consolidate results |
| Sep 6 | Paper/report draft |
| **Sep 8** | **Final submission** |

---

## Supervisor Note

This repository is managed by **CNIT/PNTLab Pisa, TECIP, Scuola Superiore Sant'Anna**.
Please contact your supervisor before making architectural changes.
All code must be original or properly attributed.
Do **not** commit API keys, passwords, or large datasets — see `.gitignore`.
