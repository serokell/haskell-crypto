# SPDX-FileCopyrightText: 2020 Serokell <https://serokell.io/>
#
# SPDX-License-Identifier: MPL-2.0

{
  description = "Easy-and-safe-to-use high-level cryptographic primitives.";

  inputs = {
    nixpkgs.url = "github:serokell/nixpkgs";

    hackage = {
      url = "github:input-output-hk/hackage.nix";
      flake = false;
    };
    stackage = {
      url = "github:input-output-hk/stackage.nix";
      flake = false;
    };
    haskell-nix = {
      url = "github:input-output-hk/haskell.nix/81fb54dbfdd350b6ad8271973545f1b668975394";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";

    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, hackage, stackage, haskell-nix, flake-utils, flake-compat }:
  flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
    let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [
          (haskell-nix.internal.overlaysOverrideable {
            sourcesOverride = haskell-nix.internal.sources // {
              inherit hackage stackage;
            };
          }).combined-eval-on-build
        ];
      };

      inherit (nixpkgs.lib)
        flip isDerivation pipe
        concatLists filter listToAttrs
        mapAttrs mapAttrs' mapAttrsToList nameValuePair;
      hslib = pkgs.haskell-nix.haskellLib;

      closure = pkgs.haskell-nix.stackProject {
        src = hslib.cleanGit {
          name = "haskell-crypto";
          src = ./.;
        };
        modules = [
          ({ pkgs, ... }: {
            packages = {
              # TODO: https://github.com/k0001/hs-libsodium/issues/2
              libsodium.components.library.build-tools = [ closure.c2hs ];

              # TODO: https://github.com/input-output-hk/haskell.nix/issues/626
              # (also, it gets cleaned away for some reason)
              secure-memory.cabal-generator = pkgs.lib.mkForce null;
              NaCl.cabal-generator = pkgs.lib.mkForce null;
              crypto-sodium.cabal-generator = pkgs.lib.mkForce null;
              crypto-sodium-streamly.cabal-generator = pkgs.lib.mkForce null;
              # TODO: rename ./hpack/package.yaml back to ./hpack/common.yaml
              # (the name had to be changed as otherwise it gets cleaned in the process)
            };
          })
        ];
      };
      project = hslib.selectProjectPackages closure;
      haskell-checks = pipe project [
        (mapAttrsToList (pname: p: mapAttrsToList (tname: nameValuePair "${pname}-${tname}") p.checks))
        concatLists
        (filter (pair: isDerivation pair.value))
        listToAttrs
      ];
    in rec {
      packages = mapAttrs (_: p: p.components.library) project;

      checks = {
        reuse = pkgs.runCommand "reuse-lint" {
          nativeBuildInputs = [ pkgs.reuse ];
        } ''reuse --root ${./.} lint > "$out"'';
      } //
      (mapAttrs' (n: p: { name = "build-" + n; value = p; }) packages) //
      (mapAttrs' (n: t: { name = "test-" + n; value = t; }) haskell-checks);

      devShell = pkgs.mkShell {
        buildInputs = with pkgs; [
          nixFlakes
        ];
      };
    }
  );
}
