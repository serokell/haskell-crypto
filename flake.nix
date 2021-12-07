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

  outputs = { self, nixpkgs, hackage, stackage, haskell-nix, flake-utils, serokell-nix }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system}.extend haskell-nix.overlay;
        hn = pkgs.haskell-nix;

        flake = serokell-nix.lib.haskell.makeFlake hn hn.stackProject {
          src = hn.haskellLib.cleanGit {
            name = "haskell-crypto";
            src = ./.;
          };
          modules = [
            ({ lib, ... }: {
              packages = {
                # TODO: https://github.com/input-output-hk/haskell.nix/issues/626
                # (also, it gets cleaned away for some reason)
                secure-memory.cabal-generator = lib.mkForce null;
                NaCl.cabal-generator = lib.mkForce null;
                crypto-sodium.cabal-generator = lib.mkForce null;
                crypto-sodium-streamly.cabal-generator = lib.mkForce null;
                # TODO: rename ./hpack/package.yaml back to ./hpack/common.yaml
                # (the name had to be changed as otherwise it gets cleaned in the process)
              };
            })
          ];
          ghcVersions = [ "8107" "901" "921" ];
        };

      in flake
  );
}
