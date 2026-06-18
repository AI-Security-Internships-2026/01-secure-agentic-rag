# Week 2 Tasks — Secure Agentic RAG for Cybersecurity Knowledge Bases

**Target branch:** `taha-week-02`
**PR target:** `dev`
**Due:** End of Week 2

---

## Checklist

### a) Follow-up / Addressing Week 1 Feedback
- [x] README title change — update the repository's `README.md` title
- [x] Checklist formatting — update `docs/weekly-progress.md` to use `- [x]` or `- [ ]` instead of `- [✓]` for checkboxes
- [x] Personal intro — edit the Week 1 personal introduction in `docs/weekly-progress.md` to mention your NUST background and add 1–2 sentences on what specific technical skills you want to develop during the internship
- [x] Problems/Blockers — update `docs/weekly-progress.md` Week 1 section to describe what took longer than expected or what you found confusing (do not leave this section empty)

### b) Proposal & Documentation
- [x] Draft `docs/proposal.md` Section 3 (Research Questions)
- [ ] Draft `docs/proposal.md` Section 4 (Proposed Methodology)

### c) Literature Review
- [x] Add 3 more papers to `docs/literature-review.md` (aiming for 5 total by end of Week 2)
  - Specifically look for:
    - (a) A RAG access control paper
    - (b) A LangChain/LangGraph agent security paper

### d) Prototyping
- [x] Begin exploring LangChain agent + ChromaDB RAG skeleton in the `src/` directory

### e) Week 2 Pull Request
- [x] Create your weekly branch:
  ```bash
  git checkout dev
  git pull origin dev
  git checkout -b your-name-week-02
  ```
- [x] Commit your Week 2 changes:
  ```bash
  git add README.md docs/weekly-progress.md docs/literature-review.md docs/proposal.md src/
  git commit -m "[Week 02] Proposal draft, literature review, and RAG skeleton"
  git push origin your-name-week-02
  ```
- [ ] Open a Pull Request on GitHub:
  - Base branch: `dev`
  - PR title: `[Week 02] Proposal draft, literature review, and RAG skeleton`
  - Describe what you did and reference the issues addressed from Week 1 feedback

---

## Resources

- Project proposal: `docs/proposal.md`
- Literature review template: `docs/literature-review.md`
- Weekly log: `docs/weekly-progress.md`
- GitHub guide for students: see supervisor's `SUPERVISOR-README.md`
