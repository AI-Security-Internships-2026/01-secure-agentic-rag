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
- Begin implementation of secure agentic reasoning and evaluation using security controls.
- Conduct initial evaluation of security threats against the RAG system.

---

_(Add a new section each week)_
