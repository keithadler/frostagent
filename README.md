# frostagent

What may your agent's tools do? A one-screen policy says; the check fails on anything else.

frostagent is a deny-by-default capability linter for AI agent setups. It reads the
MCP servers, hooks, permission rules and skills that Claude Code, Claude Desktop,
Cursor, VS Code and Claude Code plugins have been given, starts each server the way
the host would and inspects the tools it offers, and reports everything that grants
power without saying so. A lockfile pins each tool's description and schema, so a
server that changes its tools under you fails the build. Part of the
[frost](https://github.com/keithadler/frost) family with
[frostjs](https://github.com/keithadler/frostjs), [frostpy](https://github.com/keithadler/frostpy)
and [frostphp](https://github.com/keithadler/frostphp).

```
$ frostagent probe --user
probing meshy ... 24 tools in 1290 ms
probing retro-diffusion ... 20 tools in 527 ms
probing scantheblock ... failed: HTTP 401: authentication rejected

frostagent 0.1.0 — no policy file (everything is reported; run `frostagent init` to write one)
scanned 33 files: 9 servers, 0 hooks, 1 permission rule, 16 skills; probed 9 servers (46 tools)

FAIL  dangerous-permission permission "Bash(rm -rf ~/Library/Containers/...)"   ~/Downloads/app/.claude/settings.local.json (permissions.allow)
      pre-approves `rm -rf ~/Library/Containers/...`, which can destroy data or escalate privileges, with no confirmation.
WARN  plaintext-secret    server "meshy"   ~/.claude.json (projects[~/Downloads/app].mcpServers.meshy)
      env `MESHY_API_KEY` holds a literal secret (high-entropy value under a credential key, 40 chars).
      Reference it instead: "MESHY_API_KEY": "${MESHY_API_KEY}".
WARN  unpinned-package    server "meshy"   ~/.claude.json (projects[~/Downloads/app].mcpServers.meshy)
      `npx -y @meshy-ai/meshy-mcp-server` fetches `@meshy-ai/meshy-mcp-server` at whatever version the
      registry serves today. Pin it: `@meshy-ai/meshy-mcp-server@<version>`.
WARN  annotation-mismatch tool "meshy/meshy_send_to_slicer"
      annotated readOnlyHint=true but its name starts with `send`, a verb that changes something.

1 fail, 4 warn, 12 info (hidden; --verbose shows them), 0 allowed by policy
```

That is a real run against a real machine, trimmed. Every line is something the
person had not decided on purpose.

## What it catches

**In configuration**, without running anything:

- Servers fetched unpinned: `npx -y pkg`, `uvx pkg`, `docker run image` with no version, tag or digest.
- Tokens written into config files, in `env`, `headers` or on the command line, rather than referenced as `${VAR}`. A project file that may be committed is a failure; a per-user file is a warning.
- Remote servers over plain `http://`.
- Commands that download and run a script in one step, containers with host access, binaries living in `/tmp` or `Downloads`, flags that disable safety checks.
- Hooks that reach the network with tool input on stdin, evaluate what they receive, delete things, or use sudo.
- Permission rules that pre-approve a whole tool (`Bash(*)`, `mcp__*`), a destructive command, or a bypass mode.
- Skills whose commands download-and-run, read `~/.ssh` or `~/.aws`, delete outside the project, ask the user for credentials, or contain text aimed at steering the model against the user.
- Invisible characters anywhere: zero-width, bidirectional overrides, tag characters.

**In live tools**, by starting each server and calling `tools/list`:

- Tool poisoning: descriptions or parameter descriptions that instruct the model ("before calling any other tool", "do not tell the user", "ignore previous instructions").
- URLs in descriptions, which is where a poisoned tool sends what it steals.
- Descriptions many times longer than their peers.
- The same tool name on two servers, or names one edit apart.
- Tools annotated read-only whose names start with a verb that writes.
- Tools that take a command, script or query as free text.
- Drift: any tool whose description or schema changed since `frostagent lock` approved it.

Run `frostagent rules` for the full list with default severities.

## Install

```
cargo install frostagent
```

or download a binary from the releases page. One static executable, no runtime.

## Use

```
frostagent                      lint the current project
frostagent --user               also read ~/.claude.json, ~/.claude, Claude Desktop, Cursor
frostagent probe --user         also start every server and inspect its tools
frostagent lock                 approve the tools as they are now (writes frostagent.lock)
frostagent init                 write a starter frostagent.policy
frostagent summary              read the policy back in plain English
```

Exit code 1 on any failure (or on warnings with `--fail-on warn`), 0 otherwise.
`--format json|sarif|github` for machines and for GitHub code scanning.

Probing runs the servers exactly as your agent would, with their configured env,
and kills them after `tools/list`. It is opt-in because it executes code. Nothing
is uploaded anywhere.

## The policy

`frostagent.policy` sits in the project. One sentence per line. Everything the
linter finds is reported until a line here allows it.

```
policy "app"
server "meshy" may unpinned-package                   -- upstream publishes no tags, tracked in #12
server "*" may plaintext-secret in "~/.claude.json"   -- per-user file, never committed
skill "deploy" may skill-network until 2026-12-31     -- talks to build.vendor.io, reviewed
trust server "unity"                                  -- built here, reviewed in its own repo
forbid exec-surface                                   -- free-text code parameters are failures here
require lock                                          -- every probed server must be locked
```

Subjects are `server`, `skill`, `hook`, `permission`, `tool` or `everything`.
Names may use `*`. `in "<file>"` limits a line to one config file. `until` makes
an exception expire, and an expired line is itself a warning. `trust` turns a
subject off entirely. `forbid` turns a rule's warnings into failures. Unknown
rule names are errors, so a typo cannot silently allow anything.

`frostagent summary` prints the policy as sentences so a reviewer can read it
without knowing the syntax.

## The lockfile

```
frostagent lock --user
```

probes every server and writes `frostagent.lock`: for each server, the SHA-256 of
every tool's name, description, input schema and annotations. From then on
`frostagent probe` reports `tool-drift` as a failure when any of those change,
`tool-added` when a server grows a tool, and `tool-removed` when one disappears.
Commit the lockfile. Review the diff when it changes, the way you would a
dependency lockfile, because a tool description is the part of a dependency that
your model reads and obeys.

## In CI

```yaml
- uses: keithadler/frostagent@v0.1
  with:
    args: probe --format github
```

or with the SARIF upload for code scanning:

```yaml
- run: frostagent --format sarif > frostagent.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: frostagent.sarif
```

And as a pre-commit hook:

```yaml
repos:
  - repo: https://github.com/keithadler/frostagent
    rev: v0.1.0
    hooks:
      - id: frostagent
```

## What it does not do

It does not read the server's source code. frostjs and frostpy do that for
JavaScript and Python; wiring their taint analysis to tool arguments is the next
step. It does not sit between the agent and the servers at runtime, so a poisoned
result arriving through a legitimate tool is out of scope for a linter. It does
not perform OAuth sign-ins, so remote servers that require one are reported as
not inspected.

## License

MIT.
