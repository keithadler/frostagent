"""A minimal MCP host for tests: drives a server (or the frostagent proxy in
front of one) over stdio, lists tools, calls one, and prints what came back
as JSON lines so the test can inspect them."""
import json, subprocess, sys

cmd = sys.argv[1:]
call_tool = None
if "--call" in cmd:
    i = cmd.index("--call"); call_tool = cmd[i + 1]; del cmd[i:i + 2]
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

def send(obj):
    p.stdin.write(json.dumps(obj) + "\n"); p.stdin.flush()

def recv(rid):
    while True:
        line = p.stdout.readline()
        if not line:
            return None
        try:
            v = json.loads(line)
        except ValueError:
            continue
        if v.get("id") == rid:
            return v

send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "host", "version": "0"}}})
init = recv(1)
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
names = []
cursor = None
rid = 2
for _ in range(20):
    params = {"cursor": cursor} if cursor else {}
    send({"jsonrpc": "2.0", "id": rid, "method": "tools/list", "params": params})
    tools = recv(rid) or {}
    rid += 1
    names += [t["name"] for t in tools.get("result", {}).get("tools", [])]
    cursor = tools.get("result", {}).get("nextCursor")
    if not cursor:
        break
print(json.dumps({"event": "initialize", "instructions": (init or {}).get("result", {}).get("instructions")}))
print(json.dumps({"event": "tools", "names": names}))
if call_tool:
    send({"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {"name": call_tool, "arguments": {}}})
    r = recv(rid)
    print(json.dumps({"event": "call", "tool": call_tool, "response": r}))
p.stdin.close()
p.wait(timeout=10)
