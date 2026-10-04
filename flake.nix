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
    in
    {
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
          # No C toolchain from Nix: rustc links with the OS's own `cc`, so the binaries the
          # suite confines load only OS libraries. A Nix-linked one loads from /nix/store, which
          # no boundary grants, and dies in dyld before it can run.
          default = pkgs.mkShellNoCC {
            packages = [
              rust
              reg.just.versions.${reg.just.default}
            ];
          };
        }
      );
    };
}
