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
        overlays = [
          haskell-nix.overlay
          (self: prev: {
            # Haskell's libsodium from lts-21.25 expects libsodium-1.0.18 to be available
            # hence we need an ugly workaround based on what haskell.nix does:
            # https://github.com/input-output-hk/haskell.nix/blob/741af0b3ea023287c0449ec72c00792a7df4175e/test/default.nix#L13
            haskell-nix = prev.haskell-nix // {
              extraPkgconfigMappings = prev.haskell-nix.extraPkgconfigMappings or {} // {
                "libsodium" = [ "libsodium-18" ];
              };
            };
            libsodium-18 = prev.libsodium.overrideAttrs (old: {
              version = "1.0.18";
              src = prev.fetchFromGitHub {
                owner = "jedisct1";
                repo = "libsodium";
                rev = "1.0.18";
                sha256 = "sha256-TOtnEEeiAC+VoCerqtsKd+MIf/k2zTbUhFhPBnovv4w=";
              };
            });
          })
        ];
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
