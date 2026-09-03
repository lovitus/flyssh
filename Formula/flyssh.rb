class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.12"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.12/flyssh-2.0.12-darwin-arm64.tar.gz"
      sha256 "b2d5c3ad52b87e0bd0b4111ab542b52cfecf2adb29eb477ec8a35ac7aa002fe8"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.12/flyssh-2.0.12-darwin-amd64.tar.gz"
      sha256 "e46acea81a43f0bd83dbf39e8ea83615b302f8dec698ff9cf34fe8a298d39494"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.12/flyssh-2.0.12-linux-arm64.tar.gz"
      sha256 "6a331dd9b41e80c0b918a8c61264b887258e9681e6bdf67634d5394739064978"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.12/flyssh-2.0.12-linux-amd64.tar.gz"
      sha256 "67551bdaec02aca2e655f41121fb2ec2ecb87c483e7574e6691386185491f7bc"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
