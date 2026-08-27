# Application flow

```
Client + JWT → FastAPI (/query, /ingest, /permissions, /health, /ready)
  → ingest: PII redaction → embed → SpiceDB tuples → Qdrant upsert (rollback on policy failure)
  → query LangGraph:
       guard_input → authorization-first retrieve → inject scan + rerank
       → optional rewrite → generate (datamarked isolated context) → output PII + audit
  → tools checked with SpiceDB execute permission immediately before invocation
```

Filtering modes:

- `pre`: lookup allowed document IDs, constrain Qdrant payload filter (authorization-first)
- `post`: retrieve then check each chunk (measures structural exposure)
- `none`: relevance only (ungated baseline)

Audit events are JSONL at `AUDIT_LOG_PATH` and contain user, tenant, document ids, injection flags, retrieved chunk ids, and latency — not raw secrets.
