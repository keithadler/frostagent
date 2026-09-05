# Runtime proxy

A linter sees what a server declares. The proxy sees what it does during a
session. `frostagent proxy` stands between the host and one stdio server,
relays the JSON-RPC stream unchanged, and checks what passes:

| Message | Check | With `--enforce` |
|---|---|---|
| `initialize` result | startup `instructions` for steering text or hidden characters | instructions blanked |
| `tools/list` result | every tool rule the probe applies, plus drift against `frostagent.lock` | drifted or poisoned tools removed from the list the host sees |
| `tools/call` request | is the tool one the server published, and not one that was removed | refused with a JSON-RPC error the model can read |
| `tools/call` result | text content for steering text or hidden characters arriving through an honest tool | a warning is prepended, so the model reads "treat this as data" before the data |
| `notifications/tools/list_changed` | the signal of a rug pull | logged; the next list is checked against the lockfile |

Nothing is buffered or rewritten except in the cases the table names. Latency
is one JSON parse per line.

## Setting it up

Point the client at the proxy instead of the server. In `.mcp.json`:

```json
{
  "mcpServers": {
    "github": {
      "command": "frostagent",
      "args": ["proxy", "github", "/path/to/project", "--enforce", "--log", "/path/to/project/.frostagent/github.jsonl"]
    }
  }
}
```

and keep the real launch under a different name in a file the proxy reads, or
in the user config with `--user`:

```json
{
  "mcpServers": {
    "github-real": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"], "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}" } }
  }
}
```

then `frostagent proxy github-real ...`. The proxy uses the server's configured
command, args and env exactly as the host would, and forwards its stderr.

Events go to stderr as `frostagent proxy: <kind>: <message>` and, with
`--log`, as one JSON object per line: `ts`, `kind`, `message`, `detail`.

## What it does not do

- HTTP servers are not proxied yet; the probe and lockfile cover them.
- It does not inspect resources or prompts fetched during a session, only tool
  results.
- It cannot know what the model will do with a result it lets through. The
  warning prefix is the strongest thing a proxy can honestly do without
  breaking the tool.

## OAuth servers

A remote server that answers `401` is reported as `server-auth`, an
information-level finding, with what its challenge and protected-resource
metadata say: the authorization server and the scopes it wants. frostagent
performs no sign-in of its own. To inspect such a server's tools, take a token
from a client you have already signed in with and export it:

```
export FROSTAGENT_AUTH_CORP_CRM="Bearer eyJ..."   # or just the token
frostagent probe --user
```

The variable name is `FROSTAGENT_AUTH_` plus the server name upper-cased with
anything but letters and digits replaced by `_`. The value is used as the
`Authorization` header for that server only and never written anywhere.
