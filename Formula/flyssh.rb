class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/lovitus/flyssh"
  version "2.0.5"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.5/flyssh-2.0.5-darwin-arm64.tar.gz"
      sha256 "16a52a32870049025998003ecc2bebabbeeb43e8f1b7dc0811f596e012611297"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.5/flyssh-2.0.5-darwin-amd64.tar.gz"
      sha256 "fb3a9df6a8c61d1c3f2ea6dec992d399843136be147828a2f9549905b84535ac"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.5/flyssh-2.0.5-linux-arm64.tar.gz"
      sha256 "5d57f949b5a09507c3bfdb806cc9f17e8776ef1dccf684452116d970f6b310bb"
    end

    on_intel do
      url "https://github.com/lovitus/flyssh/releases/download/v2.0.5/flyssh-2.0.5-linux-amd64.tar.gz"
      sha256 "5867e546e191e5e1d596b056b094bdbb5699eeb0f51f6a36c3decbc9f2601df9"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/flyssh --version")
  end
end
