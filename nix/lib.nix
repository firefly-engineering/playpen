# `playpen.lib`: values an operator splices into their policy by name, never defaults merged
# behind them ([ADR 0015]).
#
# [ADR 0015]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0015-the-nix-module-is-a-projection-and-home-manager-is-the-primary-tier.md
{ nixpkgs }:
let
  inherit (nixpkgs) lib;
in
{
  # The toolchain roots for `packages`: one `{ path }` per store path in their closure
  # ([spec §8.3]). `closureInfo` computes the closure, so this reads its output while evaluating;
  # each path keeps its store reference, so the policy that names it keeps it alive.
  #
  # [spec §8.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#83-toolchain
  closureRoots =
    packages:
    let
      pkgs = nixpkgs.legacyPackages.${(lib.head packages).system};
      info = pkgs.closureInfo { rootPaths = packages; };
    in
    lib.optionals (packages != [ ]) (
      map (path: { inherit path; }) (
        lib.filter (path: path != "") (lib.splitString "\n" (builtins.readFile "${info}/store-paths"))
      )
    );

  # The endpoint rule sets playpen ships ([spec §7.6]), by name: each the list of `{ method, path }`
  # its file under `endpoints/` holds, so `fragments.endpoints.<name> = playpen.lib.endpoints.<name>;`
  # declares it and a route's `endpoints = [ "<name>" ];` applies it. Nothing names one for you.
  #
  # [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
  endpoints = lib.mapAttrs' (
    file: _:
    lib.nameValuePair (lib.removeSuffix ".json" file) (lib.importJSON (../endpoints + "/${file}"))
  ) (builtins.readDir ../endpoints);
}
