# The policy file

`frostagent.policy`, in the project root, or anywhere with `--policy`.

## Grammar

```
policy "<name>"
<subject> may <rule> [in "<file glob>"] [until YYYY-MM-DD]
trust <subject>
forbid <rule>
require lock
```

`<subject>` is one of:

```
server "<name>"        skill "<name>"        hook "<event>[:<matcher>]"
permission "<rule>"    tool "<server>/<tool>" everything
```

Names are matched case-insensitively and may contain `*`. Comments start with
`--` or `#` and run to the end of the line. Keywords are case-insensitive.

## Semantics

- Every finding is active unless a line says otherwise. There is no allow-all.
- `may` waives one rule for matching subjects. The finding is kept and shown
  under "allowed by policy" with `--verbose` and in JSON, so nothing disappears.
- `in "<file>"` limits the waiver to findings whose source file matches; use
  `~` for the home directory.
- `until` makes the waiver expire. After the date the finding is active again
  and a `policy-expired` warning names the line.
- `trust` drops every finding about the subject. Use it for things you build
  and review elsewhere.
- `forbid` raises a rule's findings to failures. Use it to make an
  informational rule such as `exec-surface` block the build in a sensitive repo.
- `require lock` makes a probed server without a lockfile entry a failure
  instead of a note.
- A rule name that does not exist is a parse error. Run `frostagent rules`.

## Examples

Allow the one server whose upstream has no versions, for now:

```
server "meshy" may unpinned-package until 2026-12-31   -- ask vendor for tags
```

Accept that per-user Claude Code config stores tokens literally, while still
failing on tokens in the repo:

```
server "*" may plaintext-secret in "~/.claude.json"
```

A skill that legitimately deploys:

```
skill "deploy" may skill-network
skill "deploy" may skill-exec
```

A plugin you installed on purpose and do not want to hear about:

```
trust skill "cloudflare*"
```
