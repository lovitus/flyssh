class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.1/flyssh-2.0.1-darwin-arm64.tar.gz"
      sha256 "54314acf42a07a924d40be086196a58d2aacb39624589c8d654f44aa92c1545d"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.1/flyssh-2.0.1-darwin-amd64.tar.gz"
      sha256 "9491be6f5a45b2ba21df2910c3998e39fbef1fe95a471edf372c5d0ed58528a6"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.1/flyssh-2.0.1-linux-arm64.tar.gz"
      sha256 "1b0a1dc462397c61d8a0c66f8fb21b8b8e15914367eb6ff59ea9e735db2d8a69"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.1/flyssh-2.0.1-linux-amd64.tar.gz"
      sha256 "a2e1ff39279310f99e0b7197aec515696048baf933886fa442af3a619ce2a245"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
