class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.15"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.15/flyssh-2.0.15-darwin-arm64.tar.gz"
      sha256 "fb38cdaba896a72a13bb23500a48524ef5ffec65c7706c9d406297e14630a21f"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.15/flyssh-2.0.15-darwin-amd64.tar.gz"
      sha256 "e190d110c05c1ef28caa8b8adc83bf0ef1fe6bff898f32012cb140a98e916af3"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.15/flyssh-2.0.15-linux-arm64.tar.gz"
      sha256 "bf003c40d68870b0bed6a2ea1960d1e7ec0a3789dbe321923a6f3bbc55dca0b5"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.15/flyssh-2.0.15-linux-amd64.tar.gz"
      sha256 "a3f4cbed67ab3b171834febae5b42ab26f9c8a401280455f88fd6d3898465302"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
