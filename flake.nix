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

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = rustExtensions;
        };

        commonPackages = with pkgs; [
          cargo-llvm-cov
          cargo-nextest
          pkg-config
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
