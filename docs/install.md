# Installing playpen

playpen reads one policy file from a fixed search path ([spec §10.1](spec.md#101-location)) and
cannot tell who wrote it. On a Nix host the flake's module writes it; anywhere else you do. Either
way playpen itself has no runtime dependency on how it was installed
([spec §16](spec.md#16-distribution)).

## Nix

The flake exposes `homeManagerModules.default` (the primary tier), and `nixosModules.default` and
`darwinModules.default` for a host with no per-user Nix
([ADR 0015](adr/0015-the-nix-module-is-a-projection-and-home-manager-is-the-primary-tier.md)).

```nix
{ playpen, pkgs, ... }:
{
  imports = [ playpen.homeManagerModules.default ];

  programs.playpen = {
    enable = true;
    # Key for key the policy document (spec §10.3). Nothing here has a default: an option you do
    # not set is absent from the file.
    policy = {
      version = 1;
      workspaces.playpen.roots = [
        { path = "/Users/op/src/github.com/firefly-engineering/playpen"; mode = "readwrite"; }
      ];
      profiles.firefly = {
        workspaces = [ "playpen" ];
        # One root per store path in the closure.
        toolchain = playpen.lib.closureRoots [ pkgs.git pkgs.jujutsu ];
        env.set.CARGO_HOME.area = "playpen/cargo-cache"; # `!area playpen/cargo-cache`
      };
      shims.claude = {
        target = "/opt/homebrew/bin/claude";
        kind = "claude";
      };
    };
    # Shims are opt-in by kind: this links `claude` to playpen.
    shims.claude.enable = true;
  };
}
```

- The home-manager module writes `~/.config/playpen/policy.yaml`; the NixOS and nix-darwin
  modules write `/etc/playpen/policy.yaml`. A user document wins over the system one, which is
  then never read.
- The policy is checked as it is built, with `playpen check --no-filesystem`: a policy playpen
  would refuse fails the switch. On macOS a profile whose roots would not fit the compiled-profile
  ceiling ([spec §15.3](spec.md#153-the-compiled-profile-ceiling)) fails it too.
- `closureRoots` reads its closure while evaluating, so it needs import-from-derivation, which Nix
  allows unless `allow-import-from-derivation` is off.
- An `!area` value is written `{ area = "<workspace>/<area>"; }`, its untagged form.
- On NixOS the module also installs the dedicated floor ([spec §8.2](spec.md#82-the-floor)) in
  the system generation, where playpen finds it without `PLAYPEN_FLOOR`.

## Homebrew

This repository is its own tap ([ADR 0019](adr/0019-a-homebrew-toolchain-is-a-keg-list-and-a-shim-is-the-playpen-binary.md)).
Until a release is tagged the formula builds `main`:

```sh
brew tap firefly-engineering/playpen https://github.com/firefly-engineering/playpen
brew install --HEAD firefly-engineering/playpen/playpen
```

### The toolchain is a keg list

Grant each keg the agent needs by its `opt/` link, never `/opt/homebrew` whole: the prefix holds
SSH host private keys under `etc/ssh/` ([spec §8.3](spec.md#83-toolchain)). Homebrew closes the
list over dependencies; name the kegs you want and let it add the rest:

```sh
sh -c '{ printf "%s\n" "$@"; brew deps --installed --union "$@"; } | sort -u |
  while read -r keg; do echo "      - { path: $(brew --prefix)/opt/${keg##*/} }"; done' - node jj
```

Paste the output under the profile's `toolchain:`. Rerun it when you add a keg; `brew upgrade`
re-points the `opt/` links, so an upgrade needs nothing.

### Shims are links you place

A shim is a symlink to playpen named for its key in `shims` ([spec §11.3](spec.md#113-shims)).
For `shims.claude`:

```sh
ln -s "$(brew --prefix)/bin/playpen" ~/.local/bin/claude
```

Put the link in a directory the agent cannot write, and ahead of the real `claude` on your `PATH`.
playpen refuses to launch through a link or directory a profile can write.

### Check the policy

There is no build to fail, so check the policy yourself after editing it:

```sh
playpen check
```

Without `--no-filesystem` this also checks that every root, exclusion and shim target exists on
this host.

## Minters for Anthropic

Both channels install `playpen-minter-anthropic` beside `playpen`: the reference minters for
Anthropic ([spec §7.5](spec.md#75-subscription-logins)). playpen models no service, so it never
runs one on its own: a policy names it in `minters`, and a credential route names the minter.

> **Never declare a minter that refreshes the host's login.** Anthropic refresh tokens are
> single-use, so a minter that refreshes without writing back logs the host out within one
> access-token lifetime. playpen ships no refreshing minter; both of these only read.

The reference minter is a lookup of the dedicated grant `claude setup-token` mints: one year long,
scoped `user:inference`, with no refresh token. Mint it outside the boundary, then store it in
your own keystore item, never Claude Code's: the Keychain item `playpen-anthropic-setup-token` on
macOS, `~/.config/playpen/anthropic-setup-token.json` (mode 0600) on Linux. `store` reads the
token on stdin, so it is on no command line; paste it and end with Ctrl-D:

```sh
claude setup-token
playpen-minter-anthropic store
```

`store` records `expires_at` as a year from now. Repeat both steps when the grant expires; until
then the minter fails, refusing the run, rather than hand over a dead token.

The fallback, `host-login`, returns the access token of the host's own `claude` login, read-only:
Claude Code's Keychain item on macOS, and `$CLAUDE_CONFIG_DIR/.credentials.json`, else
`~/.claude/.credentials.json`, on Linux. It never refreshes, so it fails once that token has
expired until `claude` on the host has refreshed it.

```yaml
minters:
  anthropic:
    command: [playpen-minter-anthropic, setup-token]
  anthropic-host-login:
    command: [playpen-minter-anthropic, host-login]
profiles:
  firefly:
    credentials:
      - host: api.anthropic.com
        path_prefix: /
        minter: anthropic # or anthropic-host-login
        delivery: { env: CLAUDE_CODE_OAUTH_TOKEN }
```

`--service <name>` names a Keychain item and `--file <path>` a file, on either platform. On macOS
with `CLAUDE_CONFIG_DIR` set, Claude Code adds a hash of that directory to its item's name, so
`host-login` needs `--service` naming it.
