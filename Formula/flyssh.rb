class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.10"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.10/flyssh-2.0.10-darwin-arm64.tar.gz"
      sha256 "f931039ee8954ec2cd5a096affa238784564b070092d55d44bc4c39e29502094"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.10/flyssh-2.0.10-darwin-amd64.tar.gz"
      sha256 "62e28206a005c16cd5293a13371fb3d01f93a514d8657933a1f9c2797d024be4"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.10/flyssh-2.0.10-linux-arm64.tar.gz"
      sha256 "ed93af167400fed8dd18b37918e7bd64a818ceb0c8779e906fca2f5b76249ebf"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.10/flyssh-2.0.10-linux-amd64.tar.gz"
      sha256 "a41e0516bfff9be7f23317e5482dd1bf75106cd0962195d5c54146b72bdb9ffb"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
