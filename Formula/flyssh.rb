class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.2"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.2/flyssh-2.0.2-darwin-arm64.tar.gz"
      sha256 "e83d101d863dfcbdadef39628478ec4c5ed088101f879730bc831c3cd9e2ec4f"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.2/flyssh-2.0.2-darwin-amd64.tar.gz"
      sha256 "43c695f0901049851df0dd342905e5e9dea89266be83e09c929ce6987f2d6e95"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.2/flyssh-2.0.2-linux-arm64.tar.gz"
      sha256 "2b3e8d0179e811835922ec4b734105c669cd8b7620540b699ff80820277b9a8a"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.2/flyssh-2.0.2-linux-amd64.tar.gz"
      sha256 "79dbd8b6cbfc99a7e665a579cc326663d663dc125bc5c9f21b1b3d65ace2455a"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
