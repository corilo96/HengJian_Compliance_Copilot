import os
from wsgiref.simple_server import make_server

from compliance_copilot.app import create_app


application = create_app()
host = os.environ.get("COMPLIANCE_HOST", "127.0.0.1")
port = int(os.environ.get("COMPLIANCE_PORT", "8000"))

with make_server(host, port, application) as server:
    print(f"Compliance Copilot listening on http://{host}:{port}")
    server.serve_forever()
