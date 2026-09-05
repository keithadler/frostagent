# Compatibility

frostagent 1.0 follows semantic versioning. Within 1.x these do not change in
ways that break you:

- **Commands and flags** listed by `frostagent --help`. New ones may be added.
- **Exit codes**: 0 nothing to report at the chosen level, 1 findings, 2 usage
  or configuration error (unreadable policy, bad flag, missing directory).
- **Policy grammar**: `policy`, `<kind> "<name>" may <rule> [in "<file>"] [until DATE]`,
  `trust <kind> "<name>"`, `forbid <rule>`, `require lock`, comments with `--`
  or `#`. A policy that parses today parses in every 1.x.
- **Rule ids.** A rule is never renamed or removed in 1.x. New rules may be
  added; because everything is reported by default, a new rule can produce new
  findings after an upgrade. The changelog lists every new rule.
- **Default severities** of existing rules do not go up within 1.x. They may go
  down when the corpus shows a rule is noisy.
- **Lockfile** `frostagent.lock` version 1: `servers.<name>.{launch, locked_at, tools, prompts, instructions}`.
  A newer frostagent reads every version-1 lockfile. Fingerprints are SHA-256 of
  name, description, schema and annotations; they change only when the tool does.
- **Baseline** `frostagent.baseline.json` version 1: a list of finding keys.
  Keys are stable for a given rule, subject and source file.
- **JSON output** top-level keys: `tool`, `version`, `policy`, `summary`,
  `setup`, `capabilities`, `findings`, `allowed`, `probes`. Fields may be added,
  not removed or retyped.
- **SARIF** 2.1.0 with one rule per rule id.
- **GitHub Action inputs**: `args`, `version`.
- **Proxy**: `frostagent proxy <server> [dir] [--enforce] [--log FILE]`, the
  JSON-RPC error code `-32001` for refused calls, and the `[frostagent]` prefix
  on flagged results. Log line keys `ts`, `kind`, `message`, `detail`.
- **Environment**: `FROSTAGENT_AUTH_<NAME>`, `NO_COLOR`.

What may change in a minor release: heuristics behind a rule (what text counts
as steering, which hosts are placeholders), the set of config files discovered,
message wording, the text report layout, and the order of findings.

Anything not listed here, including the internal module layout, is not an
interface.
