# HengJian Compliance Copilot

An internal compliance-retrieval service for testing institutions. It is designed
around tenant isolation, permission checks, source traceability, and query audits;
it is not a general-purpose standards chatbot.

## Run

Requires Python 3.10 or later and uses only the standard library.

Set `COMPLIANCE_API_TOKENS` to a JSON object mapping bearer tokens to identities:

```json
{
  "replace-with-secret": {
    "user_id": "reviewer-1",
    "tenant_id": "lab-east",
    "permissions": ["query", "manage_documents", "view_audit"]
  }
}
```

Keep tokens in deployment secrets, never in source control. Start the service
with `COMPLIANCE_API_TOKENS='…' python -m compliance_copilot`. The service
listens on `127.0.0.1:8000`; set `COMPLIANCE_HOST`, `COMPLIANCE_PORT`, and
`COMPLIANCE_DB` to configure the bind address and SQLite database path.

All endpoints except `/health` require `Authorization: ******

* `POST /documents` (requires `manage_documents`) stores a document in the
  caller's tenant. Required JSON fields: `document_id`, `title`, `standard`,
  `version`, and `text`.
* `POST /query` (requires `query`) retrieves matching documents only from the
  caller's tenant. The response contains excerpts and citations with document
  ID, standard, version, and relevance score; it does not generate a compliance
  conclusion.
* `GET /audit` (requires `view_audit`) returns query audit events for the
  caller's tenant, including user, query, timestamp, and retrieved citations.

The SQLite audit log is append-only through this service's API. Protect the
database file and backups with deployment-level access controls and retention
policies. This starter does not provide enterprise identity federation,
document-ingestion validation, tamper-evident storage, or LLM answer generation;
those require institution-specific security and governance decisions.

Run the focused test suite with:

```bash
python -m unittest discover -s tests -v
```
