class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.3"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.3/flyssh-2.0.3-darwin-arm64.tar.gz"
      sha256 "6150e590f94ed6262438f101d83815800741643c95fb72834cd6c2db3c3c99d6"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.3/flyssh-2.0.3-darwin-amd64.tar.gz"
      sha256 "e8f91274bc1b83e2f9062099ca5018d89f5aa65f7cf5acbccea4f4bd55ad4880"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.3/flyssh-2.0.3-linux-arm64.tar.gz"
      sha256 "de67d3d02ed2e2162b8f00dd07b1b9a63e9957e7011b9ec7ccdec74e82b0a705"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.3/flyssh-2.0.3-linux-amd64.tar.gz"
      sha256 "7bef2a1f60a91d5ff5e67b2e9c6b2675db418ebc2b1d9952cefd914a69093690"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
