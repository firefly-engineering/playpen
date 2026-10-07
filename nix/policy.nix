# What every tier of the module builds from a policy: the document, checked, and the shim links.
{ lib, pkgs }:
{
  # The document as YAML, failing the build where playpen would refuse it at launch for a reason
  # the document alone decides: its syntax and coherence ([spec §10.5]), and on macOS a toolchain
  # over the compiled-profile ceiling ([`ceiling.nix`]). Existence is never checked here: it is a
  # fact about the host at launch, not about the document.
  #
  # The output is the file and nothing else, so it reads as one a person wrote. It refers to every
  # store path the policy names, so the generation that holds it keeps them alive.
  #
  # [spec §10.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#105-validation-tiers
  document =
    { playpen, policy }:
    let
      yaml = (pkgs.formats.yaml_1_2 { }).generate "policy.yaml" policy;
      over = import ./ceiling.nix { inherit lib; } policy;
    in
    pkgs.runCommand "playpen-policy.yaml" { } ''
      ${lib.getExe playpen} check --no-filesystem --policy ${yaml}
      ${lib.optionalString (pkgs.stdenv.hostPlatform.isDarwin && over != [ ]) ''
        echo ${lib.escapeShellArg (lib.concatStringsSep "\n" over)} >&2
        exit 1
      ''}
      cp ${yaml} "$out"
    '';

  # One symlink to playpen per name, under `bin`.
  shims =
    { playpen, names }:
    pkgs.runCommand "playpen-shims" { } ''
      mkdir -p "$out/bin"
      ${lib.concatMapStrings (name: ''
        ln -s ${lib.getExe playpen} "$out/bin/"${lib.escapeShellArg name}
      '') names}
    '';
}
