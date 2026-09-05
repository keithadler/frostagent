# Sample output

Generated from the example projects with `frostagent 1.0.0`; paths trimmed to
the repository root.

| File | Command |
|---|---|
| `clean-project.txt` | `frostagent examples/clean-project` |
| `risky-project.txt` | `frostagent examples/risky-project --verbose` |
| `risky-project.probe.txt` | `frostagent probe examples/risky-project --only poisoned --verbose` |
| `risky-project.json` | `--format json` |
| `risky-project.sarif` | `--format sarif` |
| `risky-project.github.txt` | `--format github` |
| `risky-project.summary.txt` | `frostagent summary --policy examples/risky-project/frostagent.policy` |
| `explain-tool-poisoning.txt` | `frostagent explain tool-poisoning` |
| `frostagent.lock.example` | `frostagent lock examples/risky-project --only poisoned` |
