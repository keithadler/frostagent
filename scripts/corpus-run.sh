#!/usr/bin/env bash
# Build a project that points at the corpus and run frostagent over it.
# Real skills and plugins for false-positive measurement; reference servers and
# Invariant's poisoned servers for recall. Needs npx, uv and network on first run.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN="${BIN:-./target/release/frostagent}"
RUN=tmp/corpus-run; rm -rf "$RUN"; mkdir -p "$RUN/.claude/skills" "$RUN/.claude/plugins"; cd "$RUN"
for d in ../corpus/anthropic-skills/skills/*/; do ln -s "$(cd "$d" && pwd)" ".claude/skills/as-$(basename "$d")"; done
for f in $(find ../corpus/superpowers -name SKILL.md); do d=$(dirname "$f"); ln -s "$(cd "$d" && pwd)" ".claude/skills/sp-$(basename "$d")"; done
ln -s "$(cd ../corpus/claude-code/plugins && pwd)" .claude/plugins/claude-code
cat > .mcp.json <<'JSON'
{ "mcpServers": {
  "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] },
  "memory": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"] },
  "everything": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-everything"] },
  "sequential-thinking": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-sequential-thinking"] },
  "fetch": { "command": "uvx", "args": ["mcp-server-fetch"] },
  "git": { "command": "uvx", "args": ["mcp-server-git"] },
  "time": { "command": "uvx", "args": ["mcp-server-time"] },
  "github": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}" } },
  "playwright": { "command": "npx", "args": ["-y", "@playwright/mcp@latest"] },
  "context7": { "type": "http", "url": "https://mcp.context7.com/mcp" },
  "deepwiki": { "type": "http", "url": "https://mcp.deepwiki.com/mcp" },
  "poison-direct": { "command": "uv", "args": ["run", "--with", "mcp[cli]<2", "mcp", "run", "../corpus/injection-experiments/direct-poisoning.py"] },
  "poison-shadow": { "command": "uv", "args": ["run", "--with", "mcp[cli]<2", "mcp", "run", "../corpus/injection-experiments/shadowing.py"] },
  "poison-whatsapp": { "command": "uv", "args": ["run", "--with", "mcp<2", "python", "../corpus/injection-experiments/whatsapp-takeover.py"] }
}}
JSON
echo "== static"; "../../$BIN" scan . --color never --verbose | grep -E "^(FAIL|WARN|INFO)" | awk '{print $1, $2}' | sort | uniq -c | sort -rn
echo "== probe"; "../../$BIN" probe . --color never --timeout 120 --lock ./frostagent.lock --exit-zero | grep -E "^(FAIL|WARN)|fail," | cut -c1-160
