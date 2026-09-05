"""Minimal MCP stdio server used by tests. Import and call serve(tools)."""
import json, sys

def serve(tools, name="stub", prompts=None, instructions=None, resources=None):
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            continue
        method = req.get("method")
        rid = req.get("id")
        if method == "initialize":
            caps = {"tools": {}}
            if prompts is not None: caps["prompts"] = {}
            if resources is not None: caps["resources"] = {}
            result = {"protocolVersion": req["params"].get("protocolVersion", "2025-06-18"),
                      "capabilities": caps, "serverInfo": {"name": name, "version": "0.0.1"}}
            if instructions: result["instructions"] = instructions
            out = {"jsonrpc": "2.0", "id": rid, "result": result}
        elif method == "prompts/list":
            out = {"jsonrpc": "2.0", "id": rid, "result": {"prompts": prompts or []}}
        elif method == "resources/list":
            out = {"jsonrpc": "2.0", "id": rid, "result": {"resources": resources or []}}
        elif method == "resources/templates/list":
            out = {"jsonrpc": "2.0", "id": rid, "result": {"resourceTemplates": []}}
        elif method == "tools/list":
            cursor = (req.get("params") or {}).get("cursor")
            if cursor is None and len(tools) > 2:
                out = {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools[:2], "nextCursor": "page2"}}
            else:
                out = {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools[2:] if cursor else tools}}
        elif rid is None:
            sys.stderr.write("notification %s\n" % method)
            continue
        else:
            out = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()
