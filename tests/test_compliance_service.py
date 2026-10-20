import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from compliance_copilot.app import ComplianceApplication
from compliance_copilot.service import AccessDenied, ComplianceService, Principal


class ComplianceServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.service = ComplianceService(Path(self.temp_dir.name) / "test.sqlite3")
        self.lab_a = Principal("reviewer-a", "lab-a", frozenset(
            {"query", "manage_documents", "view_audit"}
        ))
        self.lab_b = Principal("reviewer-b", "lab-b", frozenset(
            {"query", "manage_documents", "view_audit"}
        ))
        self.document = {
            "document_id": "GB-123",
            "title": "Concrete test",
            "standard": "GB/T 123",
            "version": "2025",
            "text": "Concrete compressive strength test procedure.",
        }
        self.service.add_document(self.lab_a, self.document)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_query_returns_citations_and_audits_only_tenant_sources(self):
        response = self.service.query(self.lab_a, "concrete strength")
        self.assertEqual(response["citations"][0]["document_id"], "GB-123")
        self.assertEqual(response["citations"][0]["version"], "2025")
        events = self.service.audit_events(self.lab_a)
        self.assertEqual(events[0]["query"], "concrete strength")
        self.assertEqual(events[0]["citations"][0]["document_id"], "GB-123")
        self.assertEqual(self.service.query(self.lab_b, "concrete")["citations"], [])
        lab_b_events = self.service.audit_events(self.lab_b)
        self.assertEqual(len(lab_b_events), 1)
        self.assertEqual(lab_b_events[0]["citations"], [])

    def test_permission_is_required(self):
        viewer = Principal("viewer", "lab-a", frozenset())
        with self.assertRaises(AccessDenied):
            self.service.query(viewer, "concrete")

    def test_http_api_authenticates_and_enforces_tenant_scoped_roles(self):
        app = ComplianceApplication(
            self.service,
            {"lab-a-token": {"user_id": "reviewer-a", "tenant_id": "lab-a",
                             "permissions": ["query", "view_audit"]}},
        )
        status, payload = self._request(app, "POST", "/query", "lab-a-token",
                                        {"query": "concrete"})
        self.assertTrue(status.startswith("200"))
        self.assertEqual(payload["citations"][0]["document_id"], "GB-123")

        status, _ = self._request(app, "POST", "/documents", "lab-a-token",
                                  self.document)
        self.assertTrue(status.startswith("403"))
        status, _ = self._request(app, "GET", "/audit", "", None)
        self.assertTrue(status.startswith("401"))

    @staticmethod
    def _request(app, method, path, token, payload):
        body = json.dumps(payload).encode() if payload is not None else b""
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body)),
            "HTTP_AUTHORIZATION": " ".join(("Bearer", token)) if token else "",
            "wsgi.input": BytesIO(body),
        }
        captured = {}

        def start_response(status, headers):
            captured["status"] = status

        response = b"".join(app(environ, start_response))
        return captured["status"], json.loads(response)


if __name__ == "__main__":
    unittest.main()
