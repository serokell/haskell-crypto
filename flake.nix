# SPDX-FileCopyrightText: 2020 Serokell <https://serokell.io/>
#
# SPDX-License-Identifier: MPL-2.0

{
  edition = 201911;

  description = "Easy-and-safe-to-use high-level cryptographic primitives.";

  outputs = { self, nixpkgs, haskell-nix }:
    let
      pkgs = nixpkgs {
        inherit (haskell-nix) config overlays;
      };

      project = pkgs.haskell-nix.stackProject {
        src = pkgs.haskell-nix.haskellLib.cleanGit {
          name = "haskell-crypto";
          src = ./.;
        };
        modules = [
          ({ pkgs, ... }: {
            packages = {
              # TODO: https://github.com/k0001/hs-libsodium/issues/2
              libsodium.components.library.build-tools = [ project.c2hs ];

              # TODO: https://github.com/input-output-hk/haskell.nix/issues/626
              NaCl.cabal-generator = pkgs.lib.mkForce null;
              crypto-sodium.cabal-generator = pkgs.lib.mkForce null;
            };
          })
        ];
      };
      inherit (project) NaCl crypto-sodium;
    in {
      packages = {
        NaCl = NaCl.components.library;
        crypto-sodium = crypto-sodium.components.library;
      };

      checks = {
        build = self.packages.NaCl;
        test = NaCl.checks.test;
      };
    };
}
