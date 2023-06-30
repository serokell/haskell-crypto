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
    haskell-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, haskell-nix, flake-utils, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        overlays = [ haskell-nix.overlay ];
        pkgs = import nixpkgs { inherit system overlays; };
        hn = pkgs.haskell-nix;

        prj = hn.stackProject {
          src = hn.haskellLib.cleanGit {
            name = "haskell-crypto";
            src = ./.;
          };
          ignorePackageYaml = true;
        };
      in { inherit (prj.flake') packages apps checks; }
  );
}
