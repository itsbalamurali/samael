{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    nix-filter.url = "github:numtide/nix-filter";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
    crane = {
      url = "github:ipetkov/crane";
    };
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, nix-filter, rust-overlay, crane, advisory-db, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          overlays = [
            (import rust-overlay)
            (final: prev: {
              nix-filter = nix-filter.lib;
              rust-toolchain = pkgs.rust-bin.nightly.latest.default;
              rust-dev-toolchain = pkgs.rust-toolchain.override {
                extensions = [ "rust-src" ];
              };
            })
          ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          craneLib =
            (crane.mkLib pkgs).overrideToolchain pkgs.rust-toolchain;
          lib = pkgs.lib;

          # samael is pure-Rust (the RustCrypto backend + the pure-Rust `xml-sec`
          # stack), so it builds with no C libraries, no bindgen and no build
          # script. Nothing extra is needed in nativeBuildInputs.

          # Keep the test fixtures (test_vectors/) in the build source alongside
          # the Rust sources that crane would otherwise filter out.
          fixtureFilter = path: _type:
            builtins.match ".*test_vectors.*" path != null;
          sourceAndFixtures = path: type:
            (fixtureFilter path type) || (craneLib.filterCargoSources path type);
          src = lib.cleanSourceWith {
            src = ./.;
            filter = sourceAndFixtures;
          };
          cargoFile = builtins.fromTOML (builtins.readFile ./Cargo.toml);
          commonArgs = {
            pname = "samael";
            inherit src;
            version = cargoFile.package.version;
          };
          # Build *just* the cargo dependencies, so we can reuse
          # all of that work (e.g. via cachix) when running in CI
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          samael = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
          });
        in
        rec {
          # `nix build`
          packages.default = samael;

          # `nix develop`
          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [ rust-dev-toolchain nixpkgs-fmt ];
          };

          checks = {
            # Build the crate as part of `nix flake check` for convenience
            inherit samael;

            # Run clippy (and deny all warnings) on the crate source,
            # again, resuing the dependency artifacts from above.
            #
            # Note that this is done as a separate derivation so that
            # we can block the CI if there are issues here, but not
            # prevent downstream consumers from building our crate by itself.
            samael-clippy = craneLib.cargoClippy (commonArgs // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets"; #--  --deny warnings
            });

            samael-doc = craneLib.cargoDoc (commonArgs // {
              inherit cargoArtifacts;
            });

            # Check formatting
            samael-fmt = craneLib.cargoFmt {
              inherit src;
            };

            # Audit dependencies
            samael-audit = craneLib.cargoAudit {
              inherit src advisory-db;
              # RUSTSEC-2023-0071: Marvin attack (RSA timing sidechannel) in the
              # pure-Rust `rsa` crate. There is no fixed release available yet;
              # this is a known, accepted limitation of the RustCrypto RSA stack.
              cargoAuditExtraArgs = "--ignore RUSTSEC-2023-0071";
            };

            # Run tests with cargo-nextest
            # Consider setting `doCheck = false` on `samael` if you do not want
            # the tests to run twice
            samael-nextest = craneLib.cargoNextest (commonArgs // {
              inherit cargoArtifacts;
              partitions = 1;
              partitionType = "count";
            });
          };
        });
}
