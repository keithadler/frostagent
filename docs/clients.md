# Clients and config files

Project level, relative to the scanned directory:

| Client | File | Read |
|---|---|---|
| Claude Code | `.mcp.json` | servers |
| Claude Code | `.claude/settings.json`, `.claude/settings.local.json` | hooks, permissions, servers |
| Claude Code | `.claude/skills/*/SKILL.md` | skills |
| Claude Code plugins | `.claude/plugins/**` with `.mcp.json`, `hooks/hooks.json`, `skills/` | servers, hooks, skills |
| Cursor | `.cursor/mcp.json` | servers |
| VS Code | `.vscode/mcp.json` (`servers`) | servers |
| Windsurf | `.windsurf/mcp.json` | servers |
| Gemini CLI | `.gemini/settings.json` | servers |
| Zed | `.zed/settings.json` (`context_servers`) | servers |
| OpenCode | `opencode.json`, `.opencode/opencode.json` (`mcp`) | servers |
| Codex | `.codex/config.toml` (`[mcp_servers.*]`) | servers |
| Roo | `.roo/mcp.json` | servers |
| Kiro | `.kiro/settings/mcp.json` | servers |
| Amp | `amp.json` | servers |

User level, with `--user`:

| Client | File |
|---|---|
| Claude Code | `~/.claude.json` (global `mcpServers` and the `projects[<dir>].mcpServers` for the scanned directory) |
| Claude Code | `~/.claude/settings.json`, `~/.claude/settings.local.json`, `~/.claude/skills`, `~/.claude/plugins` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| Gemini CLI | `~/.gemini/settings.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Zed | `~/.config/zed/settings.json` |
| OpenCode | `~/.config/opencode/opencode.json` |
| Amp | `~/.config/amp/settings.json` |
| Kiro | `~/.kiro/settings/mcp.json` |
| Codex | `~/.codex/config.toml` |
| VS Code | `~/Library/Application Support/Code/User/mcp.json`, `~/.config/Code/User/mcp.json` |
| Cline | VS Code globalStorage `saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| Roo | VS Code globalStorage `rooveterinaryinc.roo-cline/settings/mcp_settings.json` |

Server entries may use `command` as a string (most clients), an array
(OpenCode), or an object with `path`, `args`, `env` (Zed). Environment is read
from `env` or `environment`; URLs from `url`, `serverUrl` or `httpUrl`. JSON
with `//` and `/* */` comments is accepted, as VS Code and Cursor write it.

Not read: Continue's `config.yaml` (YAML), JetBrains' XML settings. Point
frostagent at a JSON or TOML export, or open an issue with a sample.

## Windows and Linux

- Home is `HOME`, or `USERPROFILE` on Windows.
- Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `~/.config/Claude/claude_desktop_config.json` (Linux), `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- VS Code, Cline, Roo and Zed on Windows: under `%APPDATA%\Code\User\...` and `%APPDATA%\Zed\settings.json`; on Linux under `~/.config/Code/User/...` and `~/.config/zed/settings.json`.
- Everything else uses the same dot-directory under the home directory on all three systems.
