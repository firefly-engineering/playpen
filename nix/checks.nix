# The module's own checks: each tier emits a policy playpen accepts, a policy playpen would refuse
# fails the build, and shims exist only for an enabled kind.
{
  self,
  nixpkgs,
  home-manager,
  darwin,
  system,
}:
let
  pkgs = nixpkgs.legacyPackages.${system};
  inherit (pkgs) lib;
  playpen = self.packages.${system}.playpen;

  # Every shape the option tree has to carry: a tagged union, a one-of table, a tag-or-string
  # value, a free-form table, and a closure and a shipped endpoint rule set spliced in by name.
  policy = {
    version = 1;
    definitions.note = "free-form";
    minters.gh.command = [ "/etc/playpen/minters/gh" ];
    fragments = {
      env.rust = [ "RUSTUP_HOME" ];
      endpoints.github-git-read-only = self.lib.endpoints.github-git-read-only;
    };
    workspaces.w = {
      roots = [
        {
          path = "/home/op/src/w";
          mode = "readwrite";
        }
      ];
      areas = {
        cache = {
          lifetime = "persistent";
          concurrency = "shared";
        };
        target.lifetime = "ephemeral";
      };
      forge.org = "firefly-engineering";
      credentials = [
        {
          host = "github.com";
          path_prefix = "/firefly-engineering/";
          minter = "gh";
          delivery.env = "GH_TOKEN";
          endpoints = [ "github-git-read-only" ];
        }
      ];
    };
    profiles.p = {
      workspaces = [ "w" ];
      toolchain = self.lib.closureRoots [ pkgs.hello ];
      env = {
        fragments = [ "rust" ];
        set = {
          CARGO_HOME.area = "w/cache";
          GIT_AUTHOR_NAME = "playpen agent";
        };
      };
    };
    shims = {
      claude = {
        target = "/opt/homebrew/bin/claude";
        kind = "claude";
        flags = [ "--dangerously-skip-permissions" ];
      };
      omp = {
        target = "/home/op/.local/bin/omp";
        kind = "omp";
        profile = "p";
      };
    };
  };

  home =
    extra:
    (home-manager.lib.homeManagerConfiguration {
      inherit pkgs;
      modules = [
        self.homeManagerModules.default
        {
          home = {
            username = "op";
            homeDirectory = "/home/op";
            stateVersion = "25.05";
            # nix-pins moves nixpkgs and home-manager together.
            enableNixpkgsReleaseCheck = false;
          };
          programs.playpen = {
            enable = true;
            inherit policy;
            shims.claude.enable = true;
          };
        }
        extra
      ];
    }).config;

  document = (home { }).xdg.configFile."playpen/policy.yaml".source;
  shims = lib.findFirst (p: p.name == "playpen-shims") null (home { }).home.packages;

  # Fails to build, saying `expected`: a failure for any other reason is not this one.
  refused =
    name: expected: extra:
    let
      failure = pkgs.testers.testBuildFailure (home extra).xdg.configFile."playpen/policy.yaml".source;
    in
    pkgs.runCommand name { } ''
      grep -F ${lib.escapeShellArg expected} ${failure}/testBuildFailure.log
      touch $out
    '';
in
{
  # A standalone home-manager configuration, so the module reads no `osConfig`: there is none.
  home-document = pkgs.runCommand "home-document" { nativeBuildInputs = [ pkgs.yq-go ]; } ''
    # Unset options are absent, never null.
    ! grep -q null ${document}
    [ "$(yq '.profiles.p.env.set.CARGO_HOME.area' ${document})" = w/cache ]
    [ "$(yq -o=json -I=0 '.fragments.endpoints["github-git-read-only"]' ${document})" = \
      "$(yq -p=json -o=json -I=0 . ${../endpoints/github-git-read-only.json})" ]
    [ "$(yq '.profiles.p.toolchain[].path' ${document})" = "$(cat ${
      pkgs.closureInfo { rootPaths = [ pkgs.hello ]; }
    }/store-paths)" ]
    touch $out
  '';

  home-shims = pkgs.runCommand "home-shims" { } ''
    [ "$(readlink ${shims}/bin/claude)" = ${lib.getExe playpen} ]
    # `omp` is a kind nobody enabled.
    [ ! -e ${shims}/bin/omp ]
    touch $out
  '';

  # A profile naming a workspace that does not exist is incoherent.
  home-incoherent = refused "home-incoherent" "refusal.workspace.unknown" {
    programs.playpen.policy.profiles.p.workspaces = lib.mkForce [ "nowhere" ];
  };
}
// lib.optionalAttrs pkgs.stdenv.hostPlatform.isDarwin {
  # 1,500 distinct store-path-shaped roots compile to about 93 kB, well over the ceiling.
  home-over-ceiling = refused "home-over-ceiling" "over macOS's ceiling of 65535" {
    programs.playpen.policy.profiles.p.toolchain = lib.mkForce (
      map (i: {
        path = "/nix/store/${lib.substring 0 32 (builtins.hashString "sha256" (toString i))}-pkg-1.0";
      }) (lib.range 1 1500)
    );
  };

  nix-darwin-document =
    (darwin.lib.darwinSystem {
      inherit system;
      modules = [
        self.darwinModules.default
        {
          system.stateVersion = 6;
          programs.playpen = {
            enable = true;
            inherit policy;
          };
        }
      ];
    }).config.environment.etc."playpen/policy.yaml".source;
}
// lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
  nixos-document =
    let
      config =
        (nixpkgs.lib.nixosSystem {
          modules = [
            self.nixosModules.default
            {
              nixpkgs.hostPlatform = system;
              system.stateVersion = "25.05";
              boot.loader.grub.enable = false;
              fileSystems."/" = {
                device = "none";
                fsType = "tmpfs";
              };
              programs.playpen = {
                enable = true;
                inherit policy;
              };
            }
          ];
        }).config;
    in
    pkgs.runCommand "nixos-document" { } ''
      cp ${config.environment.etc."playpen/policy.yaml".source} $out
      [ -e ${config.system.path}/share/playpen/floor/closure ]
    '';
}
