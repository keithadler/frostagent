# CI samples

- `github-actions.yml`: fail the build on findings, with inline annotations on the pull request.
- `github-code-scanning.yml`: upload SARIF so findings appear under the Security tab with rule descriptions.
- `pre-commit-config.yaml`: run the static scan before every commit.

For servers in CI, reference tokens as `${VAR}` in the config and pass them as
job secrets; frostagent expands them the same way the agent host does. Commit
`frostagent.lock` and add `require lock` to the policy so a server that changes
its tools fails the pull request that pulled the change in.
