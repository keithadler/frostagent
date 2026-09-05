# Homebrew formula for the keithadler/homebrew-frost tap. Fill in the sha256
# with scripts/formula.sh after a release is published.
class Frostagent < Formula
  desc "Deny-by-default capability linter for AI agent setups (MCP servers, hooks, permissions, skills)"
  homepage "https://github.com/keithadler/frostagent"
  url "https://github.com/keithadler/frostagent/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_WITH_SHA256"
  license "MIT"
  head "https://github.com/keithadler/frostagent.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    (testpath/".mcp.json").write '{"mcpServers":{"a":{"command":"npx","args":["-y","pkg"]}}}'
    output = shell_output("#{bin}/frostagent scan #{testpath} --color never")
    assert_match "unpinned-package", output
    assert_match "frostagent", shell_output("#{bin}/frostagent --version")
  end
end
