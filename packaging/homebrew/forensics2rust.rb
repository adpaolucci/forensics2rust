class Forensics2rust < Formula
  desc "Pure-Rust 45-tool read-only Windows DFIR suite, Iced GUI, CLI, and MCP server"
  homepage "https://forensics2rust.guap.ca"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/adpaolucci/forensics2rust/releases/download/v0.1.0/forensics2rust-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/adpaolucci/forensics2rust/releases/download/v0.1.0/forensics2rust-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/adpaolucci/forensics2rust/releases/download/v0.1.0/forensics2rust-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "forensics2rust"
    bin.install "forensics2rust-iced"
    doc.install "README.md", "CHANGELOG.md"
    prefix.install "LICENSE", "NOTICE"
  end

  test do
    assert_match "forensics2rust", shell_output("#{bin}/forensics2rust --help")
    assert_match "forensics2rust-iced", shell_output("#{bin}/forensics2rust-iced --help")
  end
end
