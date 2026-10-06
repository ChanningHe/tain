{
  description = "Tain — general-purpose repository mirror sync framework";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustExtensions = [
          "rust-src"
          "rust-analyzer"
          "clippy"
          "rustfmt"
          "llvm-tools-preview"
        ];

        rustVersion = (builtins.fromTOML (builtins.readFile ./rust-toolchain.toml)).toolchain.channel;
        rustToolchain = pkgs.rust-bin.stable.${rustVersion}.default.override {
          extensions = rustExtensions;
          # Static release binaries: `cargo zigbuild --release --target <t>`.
          targets = [
            "x86_64-unknown-linux-musl"
            "aarch64-unknown-linux-musl"
          ];
        };

        commonPackages = with pkgs; [
          cargo-llvm-cov
          cargo-nextest
          cargo-zigbuild
          pkg-config
          zig
        ];

        darwinFrameworks = pkgs.lib.optionals pkgs.stdenv.isDarwin (
          with pkgs;
          [
            libiconv
          ]
        );

        baseEnv = {
          RUST_BACKTRACE = "1";
        };

        baseShellHook = ''
          echo "Tain dev shell"
          echo "  $(rustc --version)"
          echo "  $(cargo --version)"
        '';
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [ rustToolchain ] ++ commonPackages ++ darwinFrameworks;
          env = baseEnv;
          shellHook = baseShellHook;
        };

        formatter = pkgs.nixfmt;
      }
    );
}
