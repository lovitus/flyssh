class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.16"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.16/flyssh-2.0.16-darwin-arm64.tar.gz"
      sha256 "e818251786fc95a3e2c6554eac69d922b07715a24dfc8eb11cee525fac1e4372"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.16/flyssh-2.0.16-darwin-amd64.tar.gz"
      sha256 "72ae60f80ecbae68dc8899f62f94a97ed65b6e4c26bed0c8accf2b8948df2077"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.16/flyssh-2.0.16-linux-arm64.tar.gz"
      sha256 "d20744030780ccdbfd003df303f78fc20d9b0f3c2a95dcc2d535d7003846cd0c"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.16/flyssh-2.0.16-linux-amd64.tar.gz"
      sha256 "26684340cf0779681d5dd46b492ac2c68e478393cf9cb88fa18050ce78801031"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
