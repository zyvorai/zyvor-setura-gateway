# Template: scripts/update-homebrew.sh renders this into Formula/setura.rb.
class Setura < Formula
  desc "Publish and diagnose a local Envoy gateway"
  homepage "https://github.com/zyvorai/zyvor-setura-gateway"
  version "@VERSION@"
  license :cannot_represent # LicenseRef-Zyvor-Production-2.0

  on_macos do
    on_arm do
      url "https://github.com/zyvorai/zyvor-setura-gateway/releases/download/v@VERSION@/setura_@VERSION@_darwin_arm64.tar.gz"
      sha256 "@SHA_DARWIN_ARM64@"
    end
    on_intel do
      url "https://github.com/zyvorai/zyvor-setura-gateway/releases/download/v@VERSION@/setura_@VERSION@_darwin_amd64.tar.gz"
      sha256 "@SHA_DARWIN_AMD64@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/zyvorai/zyvor-setura-gateway/releases/download/v@VERSION@/setura_@VERSION@_linux_arm64.tar.gz"
      sha256 "@SHA_LINUX_ARM64@"
    end
    on_intel do
      url "https://github.com/zyvorai/zyvor-setura-gateway/releases/download/v@VERSION@/setura_@VERSION@_linux_amd64.tar.gz"
      sha256 "@SHA_LINUX_AMD64@"
    end
  end

  def install
    bin.install "setura"
    man1.install "man/setura.1"
    (bash_completion/"setura").write Utils.safe_popen_read(bin/"setura", "completion", "bash")
    (zsh_completion/"_setura").write Utils.safe_popen_read(bin/"setura", "completion", "zsh")
    (fish_completion/"setura.fish").write Utils.safe_popen_read(bin/"setura", "completion", "fish")
  end

  test do
    assert_match "setura", shell_output("#{bin}/setura version")
  end
end
