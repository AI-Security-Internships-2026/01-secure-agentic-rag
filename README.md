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

```bash
# 1. Clone the repository
git clone https://github.com/AI-Security-Internships-2026/01-secure-agentic-rag.git
cd 01-secure-agentic-rag

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create your weekly branch
git checkout dev
git pull origin dev
git checkout -b your-name-week-01

# 5. Run the starter script
python src/main.py
```

---

## Roadmap to September 8, 2026

**Current state:** RAG stack (LangChain + ChromaDB + FAISS) with scalability testing done. Gap: no agent loop despite "agentic" in the project name — the current pipeline is single-shot retrieve-then-generate.

**Novel contribution target:** turn this into an actual *secure* agentic RAG by giving it a multi-step agent loop and defending it against indirect prompt injection carried in retrieved documents — a live, under-addressed threat in RAG security.

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
