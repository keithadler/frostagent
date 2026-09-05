# Contributing

Thank you. The most useful contributions, in order:

1. **A config frostagent misread.** Open an issue with the file (tokens replaced by `${VAR}`), the client that wrote it, and what frostagent said. Client coverage lives in `src/discover.rs`; each format has a unit test there.
2. **A false positive.** Paste the finding and the text it matched. Every rule's pattern lives in `src/rules.rs` with a test beside it; the corpus in `scripts/corpus-run.sh` is what we tune against, so a fix should keep the corpus numbers in `docs/threats.md` at zero false positives.
3. **A poisoning phrasing that got through.** Same, with the description. Add it to `tests/fixtures/servers/poisoned.py` so it stays caught.
4. **A new rule.** Add it to the `rules!` table with an `about` and a `fix`, implement the check, add a unit test, regenerate `docs/rules.md` with `frostagent rules --markdown`, and say in `docs/threats.md` which attack it addresses.

## Working on it

```
cargo test                        # 22 unit + 9 end-to-end; python3 needed for the fake servers
cargo clippy --all-targets -- -D warnings
cargo fmt --all
cargo run -- probe examples/risky-project
```

`scripts/fetch-corpus.sh` then `scripts/corpus-run.sh` reproduces the
measurements. First run needs network for npx and uv.

## Rules for rules

- Deny by default. A finding is reported until a policy line allows it. Never
  add a rule that is silent by default.
- Say what, where, and how to fix, in one sentence each. The reader may not
  know MCP.
- A rule must be explainable without the tool: `frostagent explain <rule>`
  should make sense to a reviewer who has never run it.
- No network from the linter itself, ever. Probing talks only to the servers
  the user configured.

## Style

Plain Rust, standard library where possible. Four direct dependencies. No
`unsafe`. Messages in sentences, no jargon a security team would not use with
an engineer.

By contributing you agree your work is released under the MIT license.
