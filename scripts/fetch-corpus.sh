#!/usr/bin/env bash
# Clone the public repositories used to measure false positives and recall into tmp/corpus.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p tmp/corpus && cd tmp/corpus
c() { [ -d "$2/.git" ] || git clone --quiet --depth 1 "$1" "$2"; echo "$2: $(find "$2" -type f | wc -l | tr -d ' ') files"; }
c https://github.com/modelcontextprotocol/servers.git mcp-servers
c https://github.com/anthropics/skills.git anthropic-skills
c https://github.com/invariantlabs-ai/mcp-injection-experiments.git injection-experiments
c https://github.com/anthropics/claude-code.git claude-code
c https://github.com/obra/superpowers.git superpowers
