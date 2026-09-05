# CI and hooks

## GitHub Actions

The repository ships a composite action. It installs the binary with cargo
from the tagged source (about two minutes on a cold runner; cache `~/.cargo`
to make it seconds) and runs it with the arguments you give.

```yaml
name: frostagent
on: [push, pull_request]
jobs:
  frostagent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: keithadler/frostagent@v0.1
        with:
          args: --format github
```

Add `probe` to start the servers in CI. Servers that need secrets read them
from the environment when the config references `${VAR}`, so pass them as
job secrets. Servers that need an interactive OAuth sign-in are reported as
not inspected.

For code scanning:

```yaml
      - run: frostagent --format sarif > frostagent.sarif || true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: frostagent.sarif
```

## pre-commit

```yaml
repos:
  - repo: https://github.com/keithadler/frostagent
    rev: v0.1.0
    hooks:
      - id: frostagent
```

The hook runs the static scan on every commit. Add `args: [probe]` to probe
as well; it takes a few seconds per server.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | no failures (or `--exit-zero`) |
| 1 | at least one failure, or a warning with `--fail-on warn` |
| 2 | usage error, unreadable policy, unreadable lockfile |
