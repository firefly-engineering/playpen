# playpen for a host without Nix: the one channel off Nix is this formula, and this repository is
# its tap (spec §16.2, ADR 0019). It installs the binary and nothing else: no toolchain fragment
# ships, and shims are the operator's own `ln -s`, because the formula cannot see the policy.
#
# Head-only until the first release is tagged: a stable `url` needs a tag to point at.
class Playpen < Formula
  desc "Confine an agent's process tree to a declared boundary"
  homepage "https://github.com/firefly-engineering/playpen"
  license "Apache-2.0"
  head "https://github.com/firefly-engineering/playpen.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    (testpath/"policy.yaml").write "version: 1\n"
    system bin/"playpen", "check", "--no-filesystem", "--policy", testpath/"policy.yaml"
  end
end
