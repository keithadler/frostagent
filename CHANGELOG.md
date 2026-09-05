# Changelog

## 1.0.0

Interfaces are now stable; see `docs/compatibility.md` for what that promises.

- **Argument tracing.** For servers whose code is on this machine, including
  npx packages already in the npm cache, tool handler parameters are followed
  through assignments into shell strings, evals, spawned processes, SQL,
  filesystem paths and network destinations. New rules `tool-arg-shell`,
  `tool-arg-eval`, `tool-arg-exec`, `tool-arg-sql`, `tool-arg-fs`,
  `tool-arg-network`. Handlers registered inline or by name, high-level and
  low-level MCP APIs, TypeScript, JavaScript and Python.
- **Startup side effects.** `probe` snapshots the home directory and its config
  folders before and after each server starts; new entries are reported as
  `probe-side-effect`. Found a server that writes a telemetry client id and
  fetches remote A/B flags on first start.
- **Paraphrase-hardened poisoning patterns**: "prior to invoking other tools",
  "the user need not be informed", "silently append", "these instructions take
  precedence", `<system>` blocks, "include the contents of ~/.ssh". Four
  paraphrased attacks added to the recall fixtures.
- **Clients**: Claude Desktop on Linux and Windows, VS Code, Cline, Roo and Zed
  under `%APPDATA%`, `USERPROFILE` as the home fallback.
- **Hardening**: 64 MB cap on what a stdio server may stream during a probe,
  32 MB cap on HTTP bodies, randomized never-panic tests for the policy, TOML,
  JSON-comment, SSE and env-expansion parsers.
- **Measured** on 23 real servers with 246 tools: zero poisoning, hidden-Unicode
  or instruction false positives; every `exec-surface` note on a tool that runs
  code. Details in `docs/threats.md`.


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
