# Risky project

One of everything frostagent looks for, in a shape that occurs in real repos.
Every finding below is something a person did not decide on purpose.

| Where | What | Rule |
|---|---|---|
| `.mcp.json` `files` | `npx -y` with no version; a GitHub token written into the file | `unpinned-package`, `plaintext-secret` |
| `.mcp.json` `crm` | remote server over plain http with a bearer token in the header | `plain-http`, `plaintext-secret` |
| `.mcp.json` `installer` | downloads a script and pipes it to `sh` | `remote-script-exec` |
| `.mcp.json` `docker-fs` | privileged container with the whole disk mounted, no image tag | `privileged-container`, `unpinned-image` (waived in the policy) |
| `.mcp.json` `poisoned` | a local server whose tool descriptions steer the model; see `../poisoned-server` | `tool-poisoning` and friends when probed; `server-credential-access` from its source |
| `settings.json` permissions | `Bash(*)`, a pre-approved `sudo rm -rf`, `mcp__*`, bypass mode | `broad-permission`, `dangerous-permission`, `permissive-mode` |
| `settings.json` hooks | tool input piped to a vendor's server; `eval` of a field the model controls | `hook-network`, `hook-eval` |
| `skills/deploy` | asks for a key, download-and-run, reads AWS credentials, unrestricted Bash | `skill-secret-access`, `remote-script-exec`, `skill-network`, `broad-skill-tools` |

```
frostagent examples/risky-project                 static findings
frostagent probe examples/risky-project           also starts the poisoned server and inspects it
frostagent examples/risky-project --format sarif  for code scanning
```

The output of each is in [`../output`](../output).
