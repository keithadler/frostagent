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
