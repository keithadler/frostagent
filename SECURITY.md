# Security

frostagent reads configuration files and, when asked with `probe`, starts the
servers those files describe with the environment they specify. It never sends
data anywhere itself, has no telemetry, and writes only the files it names
(`frostagent.policy`, `frostagent.lock`, `frostagent.baseline.json`).

## Reporting

If you find a way to make frostagent miss an attack it claims to catch, execute
something it should not, or leak a token, email keith.adler@icloud.com with the
details. Please do not open a public issue for a bypass until a fix is out; a
false positive is fine as a public issue.

Expect an acknowledgement within a few days and a fix or a public note within
30 days.

## What frostagent does not protect against

A linter cannot see a poisoned result arriving through a legitimate tool at
runtime, and pattern matching cannot catch a steering phrasing it has not seen.
The lockfile catches the change afterwards. See `docs/threats.md` for the full
list of what is in and out of scope.
