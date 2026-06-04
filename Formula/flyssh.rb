class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.7"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.7/flyssh-2.0.7-darwin-arm64.tar.gz"
      sha256 "3f9c2ec63a229f8ba5387680c82c589a9c723c88f0765e789e3ddd2eda7c7e99"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.7/flyssh-2.0.7-darwin-amd64.tar.gz"
      sha256 "f7a5a0ffcbd95ecdddd8a6b18b4abb747157ff737d15ce3c6a39a98c91f479e1"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.7/flyssh-2.0.7-linux-arm64.tar.gz"
      sha256 "c033d75dc98bea79ae6b2b6deb91f86bcd9f800912b1080b54933806e63607e0"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.7/flyssh-2.0.7-linux-amd64.tar.gz"
      sha256 "39adfbdf21a06333a8c2d3ccc103d896d24a05871ab2dcf8d4f95f8e5c485c67"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
