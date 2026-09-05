# Threat model

What can go wrong when an agent is given tools, and which rule catches it.
The attacks below are documented in public research and incident reports; the
rule names are frostagent's.

## Tool poisoning

A server returns a tool whose description contains instructions to the model:
read a file, include its contents in an argument to another tool, do not
mention it. The model reads descriptions to decide how to call tools, so the
description is executed as surely as code. Invariant Labs published working
examples against Cursor in April 2025; frostagent detects all three of their
public demonstration servers.

Rules: `tool-poisoning`, `prompt-poisoning`, `instructions-poisoning`,
`resource-poisoning`, `hidden-unicode`, `tool-url`, `oversized-description`.

Parameter descriptions inside the input schema are scanned too, since hosts
render them to the model. The initialize `instructions` field is scanned
because hosts pass it to the model as system text.

## Rug pull

A server behaves on first inspection and changes its tools later: a version
bump, or a sleeper that turns malicious on the second load. Nothing in the
protocol tells the host a description changed.

Rules: `tool-drift`, `tool-added`, `tool-removed`, `server-unlocked`. The
lockfile records a SHA-256 of every tool's name, description, schema and
annotations, and of prompts and instructions. Commit it. `require lock` in
the policy makes an unlocked server a failure.

## Shadowing and lookalikes

A malicious server exposes a tool with the same name as a trusted server's
tool, or a name one character away, and the model calls the wrong one. Some
poisoning payloads also instruct the model to change how it calls another
server's tool, which is why one bad server can compromise a good one.

Rules: `tool-shadowing`, `tool-lookalike`.

## Supply chain

`npx -y pkg` and `uvx pkg` fetch whatever the registry serves today. A
compromised or typo-squatted package runs with your permissions the next time
the agent starts. Tokens written literally into config files leak through
backups, sync, screenshots and commits.

Rules: `unpinned-package`, `unpinned-image`, `remote-script-exec`,
`plaintext-secret`, `secret-in-args`, `untrusted-location`, `plain-http`,
`privileged-container`, `dangerous-flag`.

## Confused deputy through hooks and permissions

Hooks run shell commands automatically with tool input on stdin. A hook that
pipes that input to `curl` exfiltrates every command the agent runs; one that
`eval`s it executes whatever a poisoned tool result put there. A permission
rule that pre-approves `Bash(*)` removes the last human check.

Rules: `hook-network`, `hook-eval`, `hook-destructive`, `hook-sudo`,
`hook-external-script`, `broad-permission`, `dangerous-permission`,
`permissive-mode`, `network-permission`.

## Skills as an injection surface

A skill is a Markdown file the model reads as instructions, plus scripts it may
run. A skill from a marketplace can carry steering text, hidden characters,
commands that read credential stores, or a download-and-run step.

Rules: `skill-directive`, `hidden-unicode`, `skill-secret-access`,
`skill-destructive`, `skill-network`, `broad-skill-tools`, `skill-exec`,
`skill-links`.

## What the server's code can do

A tool named `read_file` whose implementation spawns processes, reads the whole
environment, or connects to hosts unrelated to its purpose is a different tool
from the one its description promises. For servers whose source is on the
machine, including npx packages already in the npm cache, frostagent reads it.

Rules: `server-exec`, `server-eval`, `server-credential-access`,
`server-network`, `server-env`, `server-fs-write`, `annotation-mismatch`,
`exec-surface`, `destructive-unmarked`.

This is regex-level extraction. It answers "can this code do X at all". It
does not trace whether a tool argument reaches the exec call; frostjs and
frostpy do that, and wiring them in is the next step.

## Out of scope

- A poisoned result arriving through a legitimate tool at runtime. That needs
  a runtime guard between agent and server, not a linter.
- Servers behind an interactive OAuth sign-in. Their tools are not inspected
  and the report says so.
- Semantic review of what a tool description means. frostagent flags the
  patterns that appear in every published attack; a novel phrasing can pass.
  The lockfile still catches it the moment it changes.

## Measurements

Numbers from the 0.1.0 corpus run, September 2026:

| Set | Result |
|---|---|
| 11 reference and popular servers, 108 tools (filesystem, memory, everything, sequential-thinking, fetch, git, time, github, playwright, context7, deepwiki) | 0 poisoning, 0 oversized, 0 lookalike findings; 1 annotation mismatch on the `everything` test server |
| 3 Invariant tool-poisoning servers | 3 of 3 caught as `tool-poisoning`; both `add` tools flagged as shadowing; `.ssh` read caught from source before running |
| 44 real skills (Anthropic skills repo, superpowers, Claude Code plugins) | 0 directive findings, 0 hidden-Unicode findings, 2 destructive warnings both on `sudo` or a bare-variable `rm -rf` that are worth a look |
| 13 hooks from Claude Code's example plugins | 0 findings |
## What was measured

Numbers from the 1.0.0 release, reproducible with `scripts/fetch-corpus.sh`
and `scripts/corpus-run.sh`. The corpus is other people's real servers and
skills, not ours.

### Live servers

23 servers answered a probe: the seven Model Context Protocol reference servers,
GitHub, Playwright, Puppeteer, Context7 (local and remote), DeepWiki, Hugging
Face, Notion, Firecrawl, Tavily, Exa, Kubernetes, Sentry, Brave Search, Slack
and Desktop Commander. 246 tools, 6 sets of startup instructions.

| Rule | Findings | Of which false |
|---|---|---|
| `tool-poisoning`, `hidden-unicode`, `instructions-poisoning`, `prompt-poisoning`, `resource-poisoning` | 0 | 0 |
| `exec-surface` | 8 | 0: browser evaluate and run-code tools, a shell tool, `kubectl` and pod exec, a generic API executor |
| `oversized-description` | 3 | 3 are the same server's long but honest descriptions; a warning by design |
| `annotation-mismatch` | 2 | arguable; both tools claim read-only and have names that suggest otherwise |
| `tool-shadowing` | 11 | 0: three servers really do all expose `read_file`, `list_directory` and friends |
| `probe-side-effect` | 1 | 0: a server wrote a config with `telemetryEnabled: true`, a generated client id and remotely fetched A/B flags on first start |

### Source of local servers

Argument tracing on the reference filesystem server finds the expected flows:
every tool's arguments select filesystem paths, and nothing reaches a shell or
eval. Invariant Labs' three poisoning servers are flagged before they run:
each reads `~/.ssh` and the client's own `mcp.json` in source.

Known gap: tracing is file-local. A server that registers a switch in one file
and calls `handlers.startProcess(args)` in another is not followed across the
call. Desktop Commander and the Kubernetes server are shaped that way and show
their exec surface through `exec-surface` at probe time instead.

### Attacks

| Sample | Caught by |
|---|---|
| Invariant direct poisoning (`add` leaks SSH keys) | `tool-poisoning`, and `server-credential-access` from source |
| Invariant shadowing (rewrites another server's `send_email`) | `tool-poisoning`, `tool-shadowing` |
| Invariant WhatsApp sleeper rug pull | `server-credential-access` from source on day one; `tool-drift` when the tool changes |
| Four paraphrases written for this release ("prior to invoking other tools", "the user need not be informed", "silently forward", "include the contents of ~/.cursor/mcp.json") | `tool-poisoning`, all four |
| Zero-width space in a tool name | `hidden-unicode` |
| Instruction in a parameter description | `tool-poisoning` (schema) |
| Steering text in startup `instructions`, a prompt, a resource | `instructions-poisoning`, `prompt-poisoning`, `resource-poisoning` |

### Skills and hooks

44 skills from Anthropic's skills repository, the Claude Code plugin examples and
the superpowers collection, plus 13 hooks: no `skill-directive` findings after
the 1.0 patterns, one `skill-destructive` warning on `rm -rf "$SESSION_DIR"`
(a real, if routine, hazard), and `skill-network` on every skill that documents
`curl` to its vendor's API, which is what that rule is for.

### Runtime

`frostagent proxy` covers what the static checks cannot: a result that arrives
through an honest tool carrying instructions, a tool list that changes
mid-session, a call to a tool the server never published. In the test suite a
poisoned fixture server behind the proxy in enforce mode loses its poisoned
tools, its blanked instructions, and its call to a removed tool, while an
injected result reaches the host with a warning in front of it.

### What this does not show

Twenty-three servers is a sample, not the ecosystem. Every threshold was tuned
by one person against this corpus. Pattern matching catches the phrasings above
and their near neighbours; a determined author writes around it, and the
lockfile is the answer to that. Redacted configs from other machines are the
most useful contribution to this table.
