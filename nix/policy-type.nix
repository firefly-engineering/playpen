# The policy's option type, read from the committed JSON Schema rather than written beside it
# ([ADR 0015]): the schema is generated from playpen's serde types and CI-gated against them, so
# the option tree mirrors the policy by construction and cannot drift from it.
#
# Every option the schema marks optional is `null` until the operator sets it, and a `null` is
# dropped on emission ([`prune`]), so no value reaches the document that the operator did not
# write. A schema `default` is never copied: it is what playpen assumes when a key is absent,
# which is exactly what absence already says.
#
# A union of tables (an area's `lifetime` variants, `forge`'s `org` or `repos`) becomes one table
# holding every variant's keys. Which combinations are legal is playpen's to say, and
# `playpen check` says it when the policy is built.
#
# [ADR 0015]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0015-the-nix-module-is-a-projection-and-home-manager-is-the-primary-tier.md
{ lib }:
let
  inherit (lib) types;

  schema = lib.importJSON ../schema/policy.schema.json;

  # A `$ref` names a definition; the referring node's own keywords are kept beside it.
  deref =
    node:
    if node ? "$ref" then
      deref (schema."$defs".${lib.removePrefix "#/$defs/" node."$ref"} // removeAttrs node [ "$ref" ])
    else
      node;

  isTable = node: (node.type or null) == "object" && node ? properties;
  isWord = node: (node.type or null) == "string" && (node ? enum || node ? const);
  words = node: node.enum or [ node.const ];

  # One table holding every variant's keys; a key is required only where every variant requires
  # it, and a tag each variant fixes to one word takes any of them.
  unionOfTables =
    variants:
    let
      required = map (v: v.required or [ ]) variants;
    in
    {
      type = "object";
      properties = lib.zipAttrsWith (
        _: nodes:
        let
          derefed = map deref nodes;
        in
        if lib.all isWord derefed then
          {
            type = "string";
            enum = lib.unique (lib.concatMap words derefed);
          }
        else
          lib.head nodes
      ) (map (v: v.properties) variants);
      required = lib.foldl' lib.intersectLists (lib.head required) required;
    };

  typeOf =
    node':
    let
      node = deref node';
      variants = map deref (node.oneOf or node.anyOf);
      type = node.type or null;
    in
    if node ? oneOf || node ? anyOf then
      if lib.all isTable variants then
        typeOf (unionOfTables variants)
      else if lib.all isWord variants then
        types.enum (lib.concatMap words variants)
      else
        types.oneOf (map typeOf variants)
    else if lib.isList type then
      types.nullOr (typeOf (node // { type = lib.head (lib.remove "null" type); }))
    else if isTable node then
      types.submodule { options = lib.mapAttrs (option node) node.properties; }
    else if type == "object" then
      types.attrsOf (typeOf node.additionalProperties)
    else if type == "array" then
      types.listOf (typeOf node.items)
    else if isWord node then
      types.enum (words node)
    else if type == "string" then
      types.str
    else if type == "integer" && node ? const then
      types.enum [ node.const ]
    else if type == "integer" then
      types.ints.unsigned
    else
      # `definitions`: free-form, by declaration.
      types.anything;

  option =
    table: name: node':
    let
      node = deref node';
      required = lib.elem name (table.required or [ ]);
    in
    lib.mkOption (
      {
        type = if required then typeOf node else types.nullOr (typeOf node);
      }
      // lib.optionalAttrs (!required) { default = null; }
      // lib.optionalAttrs (node ? description || node'.description or null != null) {
        description = node'.description or node.description;
      }
    );
in
{
  type = typeOf schema;

  # The document as the operator wrote it: every option they left unset removed, at any depth.
  prune =
    let
      go =
        value:
        if lib.isAttrs value then
          lib.mapAttrs (_: go) (lib.filterAttrs (_: v: v != null) value)
        else if lib.isList value then
          map go value
        else
          value;
    in
    go;
}
