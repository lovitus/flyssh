class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.13"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.13/flyssh-2.0.13-darwin-arm64.tar.gz"
      sha256 "2dc45052223707417486b40ae27a043bd407097134328fad6ecd8a3813f12cd4"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.13/flyssh-2.0.13-darwin-amd64.tar.gz"
      sha256 "066d474674c9274058fd9e65f9c741b1903e9f3c1aafda8c5851264244304235"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.13/flyssh-2.0.13-linux-arm64.tar.gz"
      sha256 "c7f6d4a5d54afd595273c4c5a49a4ebbc96bf55f3149211fc38238ed59e07b75"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.13/flyssh-2.0.13-linux-amd64.tar.gz"
      sha256 "9ddce4368ec2c63b7e60a4f50adb4e365d0cf9f25f9f1594b0153eb1dcc677a9"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
