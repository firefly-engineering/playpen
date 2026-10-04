{
  description = "playpen: confine an agent's process tree to a declared boundary";

  nixConfig = {
    extra-substituters = [ "https://firefly-toolbox.cachix.org" ];
    extra-trusted-public-keys = [
      "firefly-toolbox.cachix.org-1:4RgCoc0+CS7QhRarG109VmWlnlYi+rQ5JYrCsRP5aK8="
    ];
  };

  inputs = {
    nix-pins.url = "github:firefly-engineering/nix-pins";
    nixpkgs.follows = "nix-pins/nixpkgs";
    toolbox.url = "github:firefly-engineering/toolbox";
    toolbox.inputs.nix-pins.follows = "nix-pins";
  };

  outputs =
    { nixpkgs, toolbox, ... }:
    let
      # The systems toolbox builds for; it does not ship x86_64-darwin.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems f;

      # rust-toolchain.toml stays the one place the Rust version is written, so rustup (CI)
      # and this shell cannot disagree.
      rustVersion = (builtins.fromTOML (builtins.readFile ./rust-toolchain.toml)).toolchain.channel;

      # A dedicated floor, for a host whose OS is not an FHS tree ([spec §8.2]). It carries the
      # OS's own command binaries under `bin`, the canary among them at `bin/true`, and at
      # `closure` the store paths they need, one per line.
      #
      # `closureInfo` is the generator and the only author of that list, as for a toolchain
      # closure (spec §8.3, §16.1): nothing hand-written can widen it, and playpen grants one
      # root per line rather than a coarse `/nix/store` root, which would be a leak.
      #
      # coreutils and bash, because that is what the FHS floor already grants: `/bin` and
      # `/usr/bin` are floor subtrees, so on an FHS host every OS command, shell included, is
      # inside the floor. A floor carrying less than that would be a narrower floor, not a
      # faithful one.
      floorFor =
        pkgs:
        pkgs.runCommand "playpen-floor" { } ''
          mkdir -p "$out/bin"
          for exe in ${pkgs.coreutils}/bin/*; do
            ln -s "$exe" "$out/bin/$(basename "$exe")"
          done
          ln -s ${pkgs.bash}/bin/sh "$out/bin/sh"
          cp ${
            pkgs.closureInfo {
              rootPaths = [
                pkgs.coreutils
                pkgs.bash
              ];
            }
          }/store-paths "$out/closure"
        '';
    in
    {
      # Exposed so an operator on a non-FHS host can build a floor and point `PLAYPEN_FLOOR` at
      # it, and so the dev shell below can set that variable for the suite.
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        nixpkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          floor = floorFor pkgs;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          reg = toolbox.registry.${system};
          rust =
            reg.rust.versions.${rustVersion}
              or (throw "toolbox has no Rust ${rustVersion}; add it to toolbox or change rust-toolchain.toml");
        in
        {
          # On Darwin, no C toolchain from Nix: rustc links with the OS's own `cc`, so the
          # binaries the suite confines load only OS libraries. A Nix-linked one loads from
          # /nix/store, which no boundary grants, and dies in dyld before it can run.
          #
          # Linux gets stdenv's `cc`, because there is no OS `cc` to fall back on: on NixOS
          # the C toolchain only ever comes from /nix/store, so withholding it leaves rustc
          # with no linker at all.
          default = (if pkgs.stdenv.hostPlatform.isDarwin then pkgs.mkShellNoCC else pkgs.mkShell) (
            {
              packages = [
                rust
                reg.just.versions.${reg.just.default}
                # The job-control row's shell, run outside the boundary by the harness itself.
                pkgs.dash
              ];
            }
            # The suite's canary has to be a binary the bare floor alone can run. On Linux the
            # shell may be a non-FHS host, where no such binary exists outside a dedicated
            # floor, so it names one built here rather than leaving the suite to find `/bin/true`
            # and fail. On an FHS host this is harmless: the floor is the same either way, with
            # this closure added.
            // nixpkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
              PLAYPEN_FLOOR = floorFor pkgs;
            }
          );
        }
      );
    };
}
