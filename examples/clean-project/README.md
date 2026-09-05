# Clean project

A setup that passes with nothing to waive. Every package is pinned, every token
is a `${VAR}` reference, permissions name specific commands, and the one hook
runs a script that is committed with the repo and uses a single field of its
input.

```
$ frostagent examples/clean-project
frostagent 0.1.0 — policy "clean-project" (examples/clean-project/frostagent.policy)
scanned 2 files: 3 servers, 1 hook, 6 permission rules, 0 skills

0 fail, 0 warn, 0 info, 0 allowed
```

If the two npx packages are already in your npm cache, a few `INFO` lines appear
under `--verbose`: frostagent found their source and reports what the code can
do (the filesystem server writes files, the GitHub server reads a token from
env and talks to the network). Those are descriptions, not problems.

`frostagent probe examples/clean-project` starts the three servers and, because
the policy says `require lock`, fails until `frostagent lock` has recorded their
tools once.
