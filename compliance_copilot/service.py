import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


class AccessDenied(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    permissions: frozenset[str]

    def require(self, permission: str) -> None:
        if permission not in self.permissions:
            raise AccessDenied("permission denied")


class ComplianceService:
    def __init__(self, database_path: str | Path):
        self.database_path = str(database_path)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    tenant_id TEXT NOT NULL,
                    document_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    standard TEXT NOT NULL,
                    version TEXT NOT NULL,
                    text TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, document_id)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    query_text TEXT NOT NULL,
                    citations TEXT NOT NULL
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def add_document(self, principal: Principal, document: dict) -> None:
        principal.require("manage_documents")
        required = ("document_id", "title", "standard", "version", "text")
        if any(not isinstance(document.get(field), str) or not document[field].strip()
               for field in required):
            raise ValueError("all document fields must be non-empty strings")

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO documents
                    (tenant_id, document_id, title, standard, version, text)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (principal.tenant_id, *(document[field] for field in required)),
            )

    @staticmethod
    def _terms(text: str) -> set[str]:
        return {
            term.casefold()
            for term in re.findall(r"[A-Za-z0-9]+|[\u4e00-\u9fff]", text)
        }

    def query(self, principal: Principal, question: str) -> dict:
        principal.require("query")
        if not isinstance(question, str) or not question.strip():
            raise ValueError("query must be a non-empty string")

        query_terms = self._terms(question)
        with self._connect() as connection:
            documents = connection.execute(
                """
                SELECT document_id, title, standard, version, text
                FROM documents
                WHERE tenant_id = ?
                """,
                (principal.tenant_id,),
            ).fetchall()

            ranked = []
            for document in documents:
                matched_terms = query_terms & self._terms(document["text"])
                if matched_terms:
                    ranked.append((len(matched_terms) / len(query_terms), document))
            ranked.sort(key=lambda item: (-item[0], item[1]["document_id"]))
            citations = [
                {
                    "document_id": document["document_id"],
                    "title": document["title"],
                    "standard": document["standard"],
                    "version": document["version"],
                    "score": round(score, 4),
                    "excerpt": document["text"][:500],
                }
                for score, document in ranked[:5]
            ]
            connection.execute(
                """
                INSERT INTO audit_events
                    (occurred_at, tenant_id, user_id, action, query_text, citations)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    principal.tenant_id,
                    principal.user_id,
                    "query",
                    question,
                    json.dumps(citations, ensure_ascii=False),
                ),
            )
        return {"query": question, "citations": citations}

    def audit_events(self, principal: Principal) -> list[dict]:
        principal.require("view_audit")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT event_id, occurred_at, user_id, action, query_text, citations
                FROM audit_events
                WHERE tenant_id = ?
                ORDER BY event_id
                """,
                (principal.tenant_id,),
            ).fetchall()
        return [
            {
                "event_id": row["event_id"],
                "occurred_at": row["occurred_at"],
                "user_id": row["user_id"],
                "action": row["action"],
                "query": row["query_text"],
                "citations": json.loads(row["citations"]),
            }
            for row in rows
        ]
