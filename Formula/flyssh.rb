class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.11"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.11/flyssh-2.0.11-darwin-arm64.tar.gz"
      sha256 "b89316866a6edf2ca71d5376624379e3d44bbabd85b5eecb11a0d1d8cd078fd5"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.11/flyssh-2.0.11-darwin-amd64.tar.gz"
      sha256 "b360fba4492131011a0fef1bec4511e980826f848f2bcb55495b164fc144a639"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.11/flyssh-2.0.11-linux-arm64.tar.gz"
      sha256 "91338a047481ee5925d7a94d764bf64368d6d8a23331dd1a05d16692fb2bd41e"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.11/flyssh-2.0.11-linux-amd64.tar.gz"
      sha256 "8a02ec8ba6fdd4b6fb4348d413de364c2695b625dd88b690bcd51bc1bfcfdaa1"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
