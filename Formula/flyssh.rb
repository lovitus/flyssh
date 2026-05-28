class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.4"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.4/flyssh-2.0.4-darwin-arm64.tar.gz"
      sha256 "fd35473e9ec5ade10758d749e0971a441cf79a461fc4df097eaa56a89ea6a5f7"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.4/flyssh-2.0.4-darwin-amd64.tar.gz"
      sha256 "d11ef466312e8a451748175aee13cf52c364eb2de2d2f456ff3dccfd19f6ff40"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.4/flyssh-2.0.4-linux-arm64.tar.gz"
      sha256 "1236f7b767f79c763d22d7c2180a13dafa153478b1ae8e1d5f32f11372f90aad"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.4/flyssh-2.0.4-linux-amd64.tar.gz"
      sha256 "4813c1a92145ed8fc6f028cdf887fccfc895c756d31497edc28f9963f2385a4c"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
