class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.14"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.14/flyssh-2.0.14-darwin-arm64.tar.gz"
      sha256 "bbad3750a0ca6b004ae29ae562853fa5ecf9acc962405441619b0db3b28a7d58"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.14/flyssh-2.0.14-darwin-amd64.tar.gz"
      sha256 "9942c0c5523a6e6c3b645dff87ca86b260dea372ad8c0ea3197beef795fa0e26"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.14/flyssh-2.0.14-linux-arm64.tar.gz"
      sha256 "5066414fee776a44379be1f25c05171ff7d916ae6cd5a9feb12d2dcbae147d72"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.14/flyssh-2.0.14-linux-amd64.tar.gz"
      sha256 "ecd183ac99357097ee36f72581f3642dc57d1df1beb0c3a584299f720f09f77e"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
