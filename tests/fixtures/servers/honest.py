import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from mcp_stub import serve
serve([
  {"name": "read_file", "description": "Read a file from disk.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}, "annotations": {"readOnlyHint": True}},
  {"name": "list_dir", "description": "List a directory.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}, "annotations": {"readOnlyHint": True}},
], name="honest")
