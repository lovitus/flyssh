class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.8"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.8/flyssh-2.0.8-darwin-arm64.tar.gz"
      sha256 "c01ef1b0d04eb2dbff97271db55985690f5de64b9423ae5bb1470c56d78f85ab"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.8/flyssh-2.0.8-darwin-amd64.tar.gz"
      sha256 "eec43d5d079a1ef0a205e24ba07dc9f4e7039ddd9e310e2bcbeb53e04ae9b82d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.8/flyssh-2.0.8-linux-arm64.tar.gz"
      sha256 "ab6c45a5ec94dce35121c03f875328dee44a211cec4b07003c4dc4a93b58b68a"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.8/flyssh-2.0.8-linux-amd64.tar.gz"
      sha256 "f929ab0dfed94fe3c4c5128d4cd9ee6501f49a4ba11b09786ac3d268d91fb87b"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
