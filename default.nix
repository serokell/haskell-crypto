# SPDX-FileCopyrightText: 2020 Serokell <https://serokell.io/>
#
# SPDX-License-Identifier: MPL-2.0

#
# nix-flakes shim with haskell.nix support
#

let
  sources = import ./nix/sources.nix {};
  # https://github.com/input-output-hk/haskell.nix/blob/master/lib/override-with.nix
  tryOverride = override: default:
    let
      try = builtins.tryEval (builtins.findFile builtins.nixPath override);
    in if try.success then
      builtins.trace "using search host <${override}>" try.value
       else
         default;
  inputs = builtins.mapAttrs (name: s: import (tryOverride "flake-${name}" s)) sources;
  nixpkgs = import (inputs.haskell-nix {}).sources.nixpkgs-default;
  flake = (import ./flake.nix).outputs (inputs // { self = flake; inherit nixpkgs; });
in
{ exposeFlake ? false }:
if exposeFlake then
  flake
else
  flake.packages
