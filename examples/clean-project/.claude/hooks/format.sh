#!/bin/sh
# Format the file the agent just edited. Reads the hook payload from stdin, uses one field, runs nothing it received.
file=$(jq -r '.tool_input.file_path // empty')
case "$file" in
  *.ts|*.tsx|*.js) npx --no-install prettier --write "$file" >/dev/null 2>&1 || true ;;
esac
exit 0
