import hmac
import json
import os
from http import HTTPStatus

from compliance_copilot.service import AccessDenied, ComplianceService, Principal


class ComplianceApplication:
    def __init__(self, service: ComplianceService, token_identities: dict[str, dict]):
        self.service = service
        self.token_identities = token_identities

    def _principal(self, authorization: str) -> Principal | None:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return None
        identity = None
        for configured_token, candidate in self.token_identities.items():
            if hmac.compare_digest(token, configured_token):
                identity = candidate
        if not identity:
            return None
        try:
            user_id = identity["user_id"]
            tenant_id = identity["tenant_id"]
            permissions = identity["permissions"]
            if not isinstance(user_id, str) or not user_id or not isinstance(tenant_id, str) or not tenant_id:
                return None
            if not isinstance(permissions, list) or not all(
                isinstance(permission, str) for permission in permissions
            ):
                return None
            return Principal(user_id, tenant_id, frozenset(permissions))
        except (KeyError, TypeError):
            return None

    @staticmethod
    def _response(start_response, status: HTTPStatus, payload: dict) -> list[bytes]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        start_response(
            f"{status.value} {status.phrase}",
            [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
            ],
        )
        return [body]

    @staticmethod
    def _body(environ) -> dict:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
            if length < 1 or length > 1_000_000:
                raise ValueError
            payload = json.loads(environ["wsgi.input"].read(length))
            if not isinstance(payload, dict):
                raise ValueError
            return payload
        except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("request body must be a JSON object under 1 MB") from None

    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        if method == "GET" and path == "/health":
            return self._response(start_response, HTTPStatus.OK, {"status": "ok"})

        principal = self._principal(environ.get("HTTP_AUTHORIZATION", ""))
        if principal is None:
            return self._response(start_response, HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})

        try:
            if method == "POST" and path == "/query":
                result = self.service.query(principal, self._body(environ).get("query"))
                return self._response(start_response, HTTPStatus.OK, result)
            if method == "POST" and path == "/documents":
                self.service.add_document(principal, self._body(environ))
                return self._response(start_response, HTTPStatus.CREATED, {"status": "created"})
            if method == "GET" and path == "/audit":
                return self._response(
                    start_response, HTTPStatus.OK, {"events": self.service.audit_events(principal)}
                )
            return self._response(start_response, HTTPStatus.NOT_FOUND, {"error": "not found"})
        except AccessDenied:
            return self._response(start_response, HTTPStatus.FORBIDDEN, {"error": "permission denied"})
        except ValueError as error:
            return self._response(start_response, HTTPStatus.BAD_REQUEST, {"error": str(error)})
        except Exception:
            return self._response(start_response, HTTPStatus.CONFLICT, {"error": "request could not be completed"})


def create_app() -> ComplianceApplication:
    try:
        token_identities = json.loads(os.environ["COMPLIANCE_API_TOKENS"])
        if not isinstance(token_identities, dict):
            raise ValueError
    except (KeyError, ValueError, json.JSONDecodeError):
        raise RuntimeError("COMPLIANCE_API_TOKENS must be a JSON object") from None
    return ComplianceApplication(
        ComplianceService(os.environ.get("COMPLIANCE_DB", "compliance.sqlite3")),
        token_identities,
    )
