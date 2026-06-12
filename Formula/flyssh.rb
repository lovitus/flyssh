class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.9"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.9/flyssh-2.0.9-darwin-arm64.tar.gz"
      sha256 "4b243778030f71f94ff10f9fb2a376de7cc5a319b8df47549427cdfbe7268e42"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.9/flyssh-2.0.9-darwin-amd64.tar.gz"
      sha256 "cbb1c0ecaff9573b5d40678a840b212f37dd8d1a67f25935ac56eb9b9071202c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.9/flyssh-2.0.9-linux-arm64.tar.gz"
      sha256 "02bbb32e8144eac4ee9bb77b598f2920333b4257e4e333e4c0298998d2cdd185"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.9/flyssh-2.0.9-linux-amd64.tar.gz"
      sha256 "1485aaeca9d37efba720ff3bd07fed9f680a79970e5c91768a45008993112053"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
