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
    # The archive unpacks to setura_VERSION_OS_ARCH/; Homebrew enters that directory.
    bin.install "setura"
    man1.install "man/setura.1"
    generate_completions_from_executable(bin/"setura", "completion", shells: [:bash, :zsh, :fish], shell_parameter_format: :arg)
    doc.install "README.md", "NOTICE"
    prefix.install "LICENSE"
  end

  def caveats
    <<~EOS
      Zyvor Setura is source-available under the Zyvor Production Licence v2.0.
      A paid Order is required for use; a 30-day trial is available from
      sales@zyvor.dev. Setura works without a key. To check a licence key:
        setura licence verify KEY
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/setura version")
    assert_match "unlicensed", shell_output("#{bin}/setura version --verbose")
    assert_match "setura", shell_output("#{bin}/setura completion bash")
  end
end
