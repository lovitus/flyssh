class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.6"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.6/flyssh-2.0.6-darwin-arm64.tar.gz"
      sha256 "15f4dfe2c1903544be29d35040e0014c3a53c20bbea6ec6eadf3ef50a587f92b"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.6/flyssh-2.0.6-darwin-amd64.tar.gz"
      sha256 "ee0019c522a38425820b941416dbd2e3dffc78892eaeb002fd71dc6242da44bd"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.6/flyssh-2.0.6-linux-arm64.tar.gz"
      sha256 "beea06673196b92030634cbd03c1048277a985a0f229afbe74ba13546ccb5e0f"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.6/flyssh-2.0.6-linux-amd64.tar.gz"
      sha256 "d17f860430d29474f5586539fcf9acf54a07a2e48daea49f8eeff0a3e56b545b"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
