"""An HTTP MCP endpoint that demands OAuth: 401 with a WWW-Authenticate
challenge pointing at protected-resource metadata, which it also serves."""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8766

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.startswith("/.well-known/oauth-protected-resource"):
            body = json.dumps({"resource": "http://127.0.0.1:%d/mcp" % port, "authorization_servers": ["https://auth.fixture.test"], "scopes_supported": ["mcp:tools", "mcp:read"]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0")); self.rfile.read(n)
        if self.headers.get("Authorization") == "Bearer fixture-token":
            req = json.loads(self.rfile.read(0) or b"{}") if False else None
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "oauth", "version": "1"}}}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Bearer resource_metadata="http://127.0.0.1:%d/.well-known/oauth-protected-resource", scope="mcp:tools"' % port)
        self.send_header("Content-Length", "0"); self.end_headers()

srv = ThreadingHTTPServer(("127.0.0.1", port), H)
print("ready", flush=True)
srv.serve_forever()
