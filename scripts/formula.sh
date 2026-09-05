#!/usr/bin/env bash
# Fill the sha256 of a released tarball into packaging/frostagent.rb. Usage: scripts/formula.sh v0.1.0
set -euo pipefail
cd "$(dirname "$0")/.."
tag="${1:?tag}"
url="https://github.com/keithadler/frostagent/archive/refs/tags/${tag}.tar.gz"
sha=$(curl -sL "$url" | shasum -a 256 | cut -d' ' -f1)
sed -i '' -e "s|url \".*\"|url \"$url\"|" -e "s|sha256 \".*\"|sha256 \"$sha\"|" packaging/frostagent.rb
echo "packaging/frostagent.rb -> $tag $sha"
