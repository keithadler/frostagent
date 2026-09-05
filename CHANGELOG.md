# Changelog

## 0.1.0

Probe covers stdio, streamable HTTP and legacy SSE; prompts, resources
and initialize instructions are inspected and locked alongside tools.
Source-level capabilities for local servers and npx packages in the npm
cache. Clients: Claude Code, Claude Desktop, Cursor, VS Code, Windsurf,
Gemini CLI, Zed, OpenCode, Codex (TOML), Cline, Roo, Kiro, Amp, plugins.
Baseline mode, `explain`, generated rules reference, color.

First release. Static rules over MCP server configs, hooks, permissions and
skills for Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Gemini and
Claude Code plugins. Live probe over stdio and streamable HTTP with tool
poisoning, hidden Unicode, URL, size, shadowing, annotation and exec-surface
checks. Lockfile with drift detection. Policy file in the frost dialect with
`may`, `trust`, `forbid`, `in`, `until` and `require lock`. Output as text,
JSON, SARIF and GitHub annotations. GitHub Action and pre-commit hook.
