# SPDX-FileCopyrightText: 2021 Serokell <https://serokell.io/>
#
# SPDX-License-Identifier: MPL-2.0

{
  description = "Easy-and-safe-to-use high-level cryptographic primitives.";

  nixConfig = {
    flake-registry = "https://github.com/serokell/flake-registry/raw/master/flake-registry.json";
  };

  inputs = {
    nixpkgs.url = "github:serokell/nixpkgs";
    haskell-nix = {
      inputs.hackage.follows = "hackage";
      inputs.stackage.follows = "stackage";
    };
    hackage.flake = false;
    stackage.flake = false;
  };

  outputs = { nixpkgs, haskell-nix, flake-utils, serokell-nix, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        overlays = [ haskell-nix.overlay ];
        pkgs = import nixpkgs { inherit system overlays; };
        hn = pkgs.haskell-nix;

        flake = serokell-nix.lib.haskell.makeFlake hn hn.stackProject {
          src = hn.haskellLib.cleanGit {
            name = "haskell-crypto";
            src = ./.;
          };
          ignorePackageYaml = true;
          ghcVersions = [ "902" "928" "945" ];
        };

      in flake
  );
}
