# The compiled-profile ceiling, estimated at build time ([spec §15.3], [ADR 0014]): the profiles
# whose toolchain and workspace roots will not fit under macOS's 65,535 bytes, one message each.
#
# Only `sandbox_init` knows a profile's compiled size, and a build cannot call it on its own
# behalf, so this is a model of it, measured with playpen 0.1.0 on macOS 26.6: each granted path
# costs the bytes it does not share with its predecessor in sorted order, plus 10. It predicts
# what the spec measured, about 6,300 roots differing only at their end and about 310 whose
# 200-character names differ from the first, and is within 250 bytes of the compiled size for
# 1,100 to 1,967 store paths. The launch-time refusal stays the backstop.
#
# ponytail: exclusions and the kind table's paths are not counted, which `reserve` absorbs; count
# them if a profile near the ceiling passes here and is refused at launch.
#
# [spec §15.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#153-the-compiled-profile-ceiling
# [ADR 0014]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0014-the-toolchain-is-a-declared-closure.md
{ lib }:
policy:
let
  # macOS's own figure, as `errorbuf` reports it; no dependency exports it.
  ceiling = 65535;
  perPath = 10;
  # The floor and playpen's own grants, which every profile carries: measured at a few hundred
  # bytes, held at several times that.
  reserve = 2048;

  shared =
    a: b:
    let
      go =
        i: if i < lib.stringLength a && lib.substring i 1 a == lib.substring i 1 b then go (i + 1) else i;
    in
    go 0;

  size =
    paths:
    let
      sorted = lib.sort lib.lessThan (lib.unique paths);
    in
    lib.foldl' (acc: x: acc + x) 0 (
      lib.zipListsWith (prev: path: lib.stringLength path - shared path prev + perPath) (
        [ "" ] ++ sorted
      ) sorted
    );

  workspaces = policy.workspaces or { };
  paths =
    profile:
    map (root: root.path) (profile.toolchain or [ ])
    ++ lib.concatMap (name: map (root: root.path) (workspaces.${name}.roots or [ ])) (
      profile.workspaces or [ ]
    );
in
lib.concatLists (
  lib.mapAttrsToList (
    name: profile:
    let
      estimated = size (paths profile) + reserve;
    in
    lib.optional (estimated > ceiling)
      "profile:${name}: about ${toString estimated} bytes compiled, over macOS's ceiling of ${toString ceiling}; its toolchain has ${
        toString (lib.length (profile.toolchain or [ ]))
      } roots"
  ) (policy.profiles or { })
)
