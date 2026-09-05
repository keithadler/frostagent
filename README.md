# frostagent

What may your agent's tools do? A one-screen policy says; the check fails on anything else.

frostagent is a deny-by-default capability linter for AI agent setups. It reads
the MCP servers, hooks, permission rules and skills that Claude Code, Claude
Desktop, Cursor, VS Code, Codex, Zed, Windsurf, Gemini CLI, OpenCode, Cline and
plugins have been given. It starts each server the way the host would, over
stdio, streamable HTTP or legacy SSE, and inspects the tools, prompts, resources
and startup instructions it offers. It reads the source of servers that live on
the machine, including npx packages already in the npm cache, and says what the
code can do. A lockfile pins every tool's description and schema so a server
that changes under you fails the build. Nothing is uploaded anywhere.

Part of the [frost](https://github.com/keithadler/frost) family with
[frostjs](https://github.com/keithadler/frostjs), [frostpy](https://github.com/keithadler/frostpy)
and [frostphp](https://github.com/keithadler/frostphp): the same one-screen
policy dialect, the same rule that everything is off until a line turns it on.

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

1 fail, 3 warn, 12 info (hidden; --verbose shows them), 0 allowed
```

A real run against a real machine, trimmed. Every line is something the person
had not decided on purpose.

## What it catches

**In configuration**, without running anything

- Servers fetched unpinned: `npx -y pkg`, `uvx pkg`, `docker run image` with no version, tag or digest.
- Tokens written into config files, in `env`, `headers` or on the command line, instead of `${VAR}`. In a file that may be committed that is a failure; in a per-user file, a warning.
- Remote servers over plain `http://`. Commands that download and run a script in one step. Containers with host access. Binaries in `/tmp` or `Downloads`. Flags that disable safety checks.
- Hooks that pipe tool input to the network, `eval` what they receive, delete things or use sudo.
- Permission rules that pre-approve a whole tool (`Bash(*)`, `mcp__*`), a destructive command, or a bypass mode.
- Skills whose commands download-and-run, read `~/.ssh` or `~/.aws`, delete outside the project, ask for credentials, or carry text aimed at steering the model against the user.
- Invisible characters anywhere: zero-width, bidirectional overrides, Unicode tags.

**In the server's source**, when it is on the machine

- Process spawning, runtime eval, credential-store reads, network hosts, environment variables read, file writes. A `read_file` tool whose code spawns processes is not the tool its description promises.

**In live servers**, by starting each one and listing what it offers

- Tool poisoning: descriptions, parameter descriptions, prompt templates, resources or initialize instructions that tell the model to call other tools first, hide something, or send data somewhere.
- URLs in descriptions, descriptions many times longer than their peers, the same tool name on two servers, names one edit apart, read-only annotations on tools whose names write, tools that take a command or query as free text.
- Drift: any tool, prompt or instruction text that changed since `frostagent lock` approved it.

Run `frostagent rules` for all 51 rules, `frostagent explain <rule>` for what one
means and how to fix or allow it, or read [docs/rules.md](docs/rules.md).

## Install

Binaries for macOS (Apple silicon and Intel), Linux and Windows are on the
[releases page](https://github.com/keithadler/frostagent/releases). One static
executable, about 3.5 MB, no runtime.

From source, with Rust 1.75 or newer:

```
cargo install --git https://github.com/keithadler/frostagent --tag v1.1.0
```

A crates.io release and a Homebrew tap (`keithadler/frost`) follow once the
first release has settled; the formula is drafted in `packaging/`.

## What it is not

- **Not a sandbox.** The linter tells you what your agent may do at check time. It does not stop Claude Code or Cursor from calling a tool that appeared after you approved the session. The proxy does, for the stdio servers you have put it in front of, and for nothing else.
- **Probing runs other people's code.** `probe` and `lock` start every configured server with the env from your config. That is the point, and it is also the dangerous part. On a machine you do not fully trust, use `--only` to pick servers, and read the list frostagent prints before you answer yes.
- **Source analysis is static.** It reads what is on disk. Minified bundles, code fetched at runtime and behaviour that starts after `tools/list` are outside it. Poisoned descriptions are the easy catch; a server that misbehaves in its results is what the proxy and the lockfile are for.
- **Client coverage rots.** Claude Code, Cursor, Codex, Zed and Windsurf change their config formats. Each format has a fixture in the test suite so a break fails CI, and `frostagent clients` shows which files were read on your machine. If yours is missing, that is an issue worth filing.
- **The measurements are a lab result.** Zero poisoning false positives on 23 servers we chose. On a real machine with nine servers, the first run produced auth notes, unpinned warnings and skill warnings that all needed a policy line. The cost of adoption is writing that policy and keeping the lockfile current, not installing the binary.

## Servers that need a sign-in

A remote server that wants OAuth is reported as `server-auth` with the
authorization server and scopes from its challenge, not as a failure. Export a
token from a client you have signed in with as `FROSTAGENT_AUTH_<NAME>` to
inspect its tools. See [docs/proxy.md](docs/proxy.md#oauth-servers).

## Stability

1.0 means the commands, flags, policy grammar, rule ids, lockfile, baseline and
JSON output are stable for the 1.x series. [docs/compatibility.md](docs/compatibility.md)
says exactly what that covers.

## Examples

[`examples/clean-project`](examples/clean-project) passes with nothing to
waive. [`examples/risky-project`](examples/risky-project) has one of everything,
each finding explained, and lists [`examples/poisoned-server`](examples/poisoned-server),
a runnable stdlib server that carries every published poisoning technique so
you can see the report without finding a real one. [`examples/output`](examples/output)
holds the text, JSON, SARIF and GitHub output for each, and a sample lockfile.
[`examples/ci`](examples/ci) has the workflow and pre-commit files.

```
frostagent examples/risky-project
frostagent probe examples/risky-project
```

## Use

```
frostagent                      lint the current project
frostagent --user               also read ~/.claude.json, ~/.claude, Claude Desktop, Cursor, Codex, Zed ...
frostagent probe --user         also start every server and inspect its tools
frostagent lock                 approve the tools as they are now (writes frostagent.lock)
frostagent init                 write a starter frostagent.policy
frostagent summary              read the policy back in plain English
frostagent explain <rule>       what a rule means, how to fix it, how to allow it
frostagent baseline             record today's findings; later runs report only new ones
```

Exit code 1 on any failure, or on warnings with `--fail-on warn`. `--format
json|sarif|github` for machines and for GitHub code scanning. Color when
stdout is a terminal, off with `NO_COLOR` or `--color never`.

Probing runs the servers exactly as your agent would, with their configured env
expanded from your shell, and kills them after listing. It is a separate command
because it executes code. Servers that need an interactive OAuth sign-in are
reported as not inspected.

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
rule names are errors, so a typo cannot silently allow anything. Waived findings
are kept in the JSON output and shown with `--verbose`; nothing disappears.

`frostagent summary` prints the policy as sentences. `frostagent baseline`
records the current findings for a repo you are adopting the tool in, so the
build stays green until something new appears. See [docs/policy.md](docs/policy.md).

## The lockfile

```
frostagent lock --user
```

probes every server and writes `frostagent.lock`: the SHA-256 of every tool's
name, description, input schema and annotations, of every prompt, and of the
initialize instructions. From then on `frostagent probe` reports `tool-drift`
as a failure when any of them change, `tool-added` when a server grows a tool,
`tool-removed` when one disappears. Commit it and review its diff the way you
review a dependency lockfile. A tool description is the part of a dependency
that your model reads and obeys.

## Measured

Numbers from the corpus in [docs/threats.md](docs/threats.md), September 2026:

| | |
|---|---|
| Reference and popular servers probed (filesystem, memory, everything, sequential-thinking, fetch, git, time, github, playwright, context7, deepwiki) | 11 servers, 108 tools, 0 poisoning or oversize false positives |
| Invariant Labs tool-poisoning demonstration servers | 3 of 3 caught; both `add` tools flagged as shadowing; the `.ssh` read caught from source before running |
| Real skills from Anthropic's skills repo, superpowers and Claude Code's plugins | 44 skills, 0 directive or hidden-Unicode false positives |
| Hooks from Claude Code's example plugins | 13, 0 findings |
| Tests | 22 unit, 9 end-to-end including fake stdio and SSE servers and a tampered lockfile |

## In CI

```yaml
- uses: keithadler/frostagent@v1
  with:
    args: probe --format github
```

With SARIF upload for code scanning, and as a pre-commit hook: see
[docs/ci.md](docs/ci.md).

## Compared with mcp-scan

Invariant's mcp-scan is the other tool in this space and it is good. The
differences that matter: frostagent runs entirely on your machine and never
sends tool descriptions to a service; it covers hooks, permission rules and
skills as well as MCP servers, since those are the same attack surface; it reads
server source; its policy is a committed file in a dialect a reviewer can read
without knowing the tool; and its lockfile lives in the repo. mcp-scan has a
runtime proxy, which frostagent does not have yet.

## What it does not do

It does not trace whether a tool argument reaches an exec call inside the
server; frostjs and frostpy do that for JavaScript and Python, and wiring them
in is the next step. It does not sit between the agent and the servers at
runtime, so a poisoned result arriving through a legitimate tool is out of
scope. It does not perform OAuth sign-ins.

## License

MIT.
