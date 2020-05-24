# SPDX-FileCopyrightText: 2020 Serokell <https://serokell.io/>
#
# SPDX-License-Identifier: MPL-2.0

{
  edition = 201911;

  description = "Easy-and-safe-to-use high-level cryptographic primitives.";

  outputs = { self, nixpkgs, haskell-nix }:
    let
      pkgs = nixpkgs {
        overlays = haskell-nix.overlays;
      };

      project = pkgs.haskell-nix.stackProject {
        src = pkgs.haskell-nix.haskellLib.cleanGit {
          name = "nacl";
          src = ./.;
          subDir = "NaCl";
        };
      };
      nacl = project.nacl;
    in {
      packages = {
        nacl = nacl.components.library;
      };

      checks = {
        build = self.packages.nacl;
        test = nacl.checks.test;
      };
    };
}
