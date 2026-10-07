# The playpen module, one body for every tier ([spec §16.1], [ADR 0015]): home-manager, the
# primary tier, and NixOS and nix-darwin for a host with no per-user Nix. Each tier differs only in
# where the document lands and where the binaries go.
#
# `programs.playpen.policy` mirrors the policy schema one-to-one ([`policy-type.nix`]) and is
# emitted as a pure projection of it, so the module ships no defaults: it has nowhere to put one.
# The document is checked by `playpen check --no-filesystem` as it is built, so an incoherent
# policy fails the switch instead of the next launch. Nothing here reads `osConfig`.
#
# [spec §16.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#161-nix
# [ADR 0015]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0015-the-nix-module-is-a-projection-and-home-manager-is-the-primary-tier.md
{ packages, tier }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.playpen;
  policy = import ./policy-type.nix { inherit lib; };
  built = import ./policy.nix { inherit lib pkgs; };
  ours = packages.${pkgs.stdenv.hostPlatform.system};

  document = built.document {
    playpen = cfg.package;
    policy = policy.prune cfg.policy;
  };

  # A shim is a symlink to playpen named for its `shims` key ([spec §11.3]), and only a kind the
  # operator enabled gets one: installing them unasked would change what `claude` means in every
  # shell.
  #
  # [spec §11.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#113-shims
  shims = built.shims {
    playpen = cfg.package;
    names = lib.attrNames (
      lib.filterAttrs (_: shim: cfg.shims.${shim.kind}.enable or false) (
        if cfg.policy.shims == null then { } else cfg.policy.shims
      )
    );
  };
in
{
  options.programs.playpen = {
    enable = lib.mkEnableOption "playpen";

    package = lib.mkOption {
      type = lib.types.package;
      default = ours.playpen;
      defaultText = lib.literalMD "playpen, from this flake";
      description = "The playpen binary: installed, linked by every shim, and run to check the policy.";
    };

    policy = lib.mkOption {
      inherit (policy) type;
      description = ''
        The policy document, key for key. An unset option is absent from the document, never a
        default: what playpen assumes for an absent key is playpen's own.
      '';
    };

    shims = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule {
          options.enable = lib.mkEnableOption "a shim for every `shims` entry of this kind";
        }
      );
      default = { };
      example = lib.literalExpression "{ claude.enable = true; }";
      description = ''
        Which kinds get shims, by kind. A shim is a symlink to playpen, named for its key in the
        policy's `shims`.
      '';
    };
  };

  config = lib.mkIf cfg.enable (
    {
      home = {
        xdg.configFile."playpen/policy.yaml".source = document;
        home.packages = [
          cfg.package
          shims
        ];
      };
      nix-darwin = {
        environment.etc."playpen/policy.yaml".source = document;
        environment.systemPackages = [
          cfg.package
          shims
        ];
      };
      # The dedicated floor goes into the system generation, where playpen finds it with no
      # variable set and it rolls back with the system that built it ([spec §8.2]).
      #
      # [spec §8.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#82-the-floor
      nixos = {
        environment.etc."playpen/policy.yaml".source = document;
        environment.systemPackages = [
          cfg.package
          shims
          (pkgs.runCommand "playpen-system-floor" { } ''
            mkdir -p "$out/share/playpen"
            ln -s ${ours.floor} "$out/share/playpen/floor"
          '')
        ];
        environment.pathsToLink = [ "/share/playpen" ];
      };
    }
    .${tier}
  );
}
