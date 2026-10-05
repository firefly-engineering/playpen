use super::*;

const ORIGIN: &str = "/etc/playpen/policy.yaml";

fn parse(text: &str) -> Result<Policy, Refusal> {
    Policy::parse(text, Path::new(ORIGIN))
}

/// The refusal `text` earns, which must have `code`.
fn refused(text: &str, code: Code) -> Refusal {
    let refusal = parse(text).expect_err("the policy is refused");
    assert_eq!(refusal.code, code, "{refusal}");
    refusal
}

/// Whether `refusal` names `line:column` of the policy.
fn names(refusal: &Refusal, line: u32, column: u32) -> bool {
    refusal
        .message()
        .contains(&format!("{ORIGIN}:{line}:{column}"))
}

const MINIMAL: &str = "\
version: 1
workspaces:
  playpen:
    roots:
      - { path: /src/playpen, mode: readwrite }
profiles:
  dev:
    workspaces: [playpen]
    toolchain: []
";

#[test]
fn reads_a_minimal_policy() {
    let policy = parse(MINIMAL).expect("minimal policy parses");
    let root = &policy.workspaces["playpen"].roots[0];
    assert_eq!(root.path, Path::new("/src/playpen"));
    assert_eq!(root.mode, Mode::Readwrite);
    assert_eq!(policy.profiles["dev"].workspaces[0].value, "playpen");
}

#[test]
fn the_smallest_policy_is_its_version() {
    assert!(parse("version: 1\n").is_ok());
}

/// The worked example of spec §10.3, which must parse as written.
#[test]
fn reads_the_worked_example() {
    let policy = parse(WORKED_EXAMPLE).expect("the worked example parses");
    let firefly = &policy.profiles["firefly"];
    assert_eq!(firefly.credentials[0].host, "api.anthropic.com");
    assert_eq!(
        firefly.env.set["CARGO_HOME"],
        SetValue::Area(AreaRef::Area("playpen/cargo-cache".into()))
    );
    assert_eq!(
        firefly.env.set["GIT_AUTHOR_NAME"],
        SetValue::Literal("playpen agent".into())
    );
    let areas = &policy.workspaces["playpen"].areas;
    assert!(matches!(
        areas["landing"],
        Area::Persistent {
            concurrency: Concurrency::Exclusive
        }
    ));
    assert!(matches!(
        areas["cargo-cache"],
        Area::Persistent {
            concurrency: Concurrency::Shared
        }
    ));
    assert!(matches!(areas["target"], Area::Ephemeral {}));
    assert!(matches!(
        policy.workspaces["playpen"].forge,
        Some(Forge::Org(ref org)) if org == "firefly-engineering"
    ));
    assert_eq!(policy.shims["omp"].profile.as_deref(), Some("firefly"));
}

#[test]
fn json_is_valid_input() {
    let text = r#"{"version": 1, "profiles": {"dev": {"workspaces": [], "toolchain": []}}}"#;
    assert!(parse(text).is_ok());
}

/// JSON has no tags, so an area reference is the one-key mapping the tag stands for.
#[test]
fn json_names_an_area_as_a_mapping() {
    let text = r#"{"version": 1, "profiles": {"dev": {"workspaces": [], "toolchain": [],
        "env": {"set": {"X": {"area": "w/a"}}}}}}"#;
    let policy = parse(text).expect("parses");
    assert_eq!(
        policy.profiles["dev"].env.set["X"],
        SetValue::Area(AreaRef::Area("w/a".into()))
    );
}

#[test]
fn a_multi_document_stream_is_a_syntax_refusal() {
    let refusal = refused("version: 1\n---\nversion: 1\n", Code::PolicySyntax);
    assert!(names(&refusal, 2, 1), "{refusal}");
}

#[test]
fn malformed_yaml_is_a_syntax_refusal() {
    refused("version: [1\n", Code::PolicySyntax);
}

#[test]
fn unknown_field_is_refused() {
    let refusal = refused("version: 1\nprofils: {}\n", Code::PolicyUnknownField);
    assert!(names(&refusal, 2, 1), "{refusal}");
}

#[test]
fn unknown_nested_field_is_refused() {
    let text = MINIMAL.replace("mode: readwrite", "mode: readwrite, exlude: []");
    refused(&text, Code::PolicyUnknownField);
}

#[test]
fn unrecognised_version_is_refused() {
    let refusal = refused("version: 2\n", Code::PolicyVersion);
    assert!(names(&refusal, 1, 10), "{refusal}");
}

/// A document written for another version is refused as that, not for keys this one lacks.
#[test]
fn the_version_is_judged_before_the_keys() {
    refused("version: 2\nfrobnicate: {}\n", Code::PolicyVersion);
}

#[test]
fn a_missing_version_is_a_type_refusal() {
    refused("profiles: {}\n", Code::PolicyType);
}

#[test]
fn a_foreign_tag_is_refused() {
    let text = MINIMAL.replace("mode: readwrite", "mode: !foo readwrite");
    let refusal = refused(&text, Code::PolicyTag);
    assert!(names(&refusal, 5, 37), "{refusal}");
}

#[test]
fn a_core_schema_tag_is_refused() {
    refused("version: !!int 1\n", Code::PolicyTag);
}

#[test]
fn a_tag_on_a_container_is_refused() {
    refused("version: 1\nprofiles: !set {}\n", Code::PolicyTag);
}

#[test]
fn a_foreign_tag_inside_definitions_is_refused() {
    refused("version: 1\ndefinitions:\n  x: !foo y\n", Code::PolicyTag);
}

#[test]
fn a_type_mismatch_is_refused() {
    refused("version: 1\nprofiles: []\n", Code::PolicyType);
}

#[test]
fn mode_no_is_an_invalid_variant() {
    let text = MINIMAL.replace("mode: readwrite", "mode: no");
    let refusal = refused(&text, Code::PolicyType);
    assert!(refusal.message().contains("`no`"), "{refusal}");
}

#[test]
fn a_nul_in_a_value_is_a_type_refusal() {
    let text = MINIMAL.replace("/src/playpen,", "\"/src/play\\0pen\",");
    refused(&text, Code::PolicyType);
}

#[test]
fn a_nul_in_a_key_is_a_type_refusal() {
    refused("version: 1\n\"a\\0b\": 1\n", Code::PolicyType);
}

#[test]
fn concurrency_is_refused_on_an_ephemeral_area() {
    let text = MINIMAL.replace(
        "    roots:",
        "    areas: { t: { lifetime: ephemeral, concurrency: shared } }\n    roots:",
    );
    refused(&text, Code::PolicyUnknownField);
}

#[test]
fn forge_is_exactly_one_of_org_or_repos() {
    let text = MINIMAL.replace(
        "    roots:",
        "    forge: { org: a, repos: [a/b] }\n    roots:",
    );
    assert!(parse(&text).is_err());
}

#[test]
fn a_toolchain_root_has_no_mode() {
    let text = MINIMAL.replace(
        "toolchain: []",
        "toolchain: [{ path: /nix/store/x, mode: read }]",
    );
    refused(&text, Code::PolicyUnknownField);
}

#[test]
fn the_area_tag_is_accepted() {
    let text = format!("{MINIMAL}    env: {{ set: {{ X: !area playpen/landing }} }}\n");
    let policy = parse(&text).expect("parses");
    assert_eq!(
        policy.profiles["dev"].env.set["X"],
        SetValue::Area(AreaRef::Area("playpen/landing".into()))
    );
}

/// `definitions:` is free-form: whatever it holds is checked only where it is used.
#[test]
fn definitions_hold_anything() {
    let text = "version: 1\ndefinitions:\n  anything: { at: [all, 1, true] }\n";
    assert!(parse(text).is_ok());
}

const MERGED_TYPO: &str = "\
version: 1
definitions:
  base: &base
    path: /src/playpen
    mdoe: read
workspaces:
  playpen:
    roots:
      - <<: *base
        mode: read
";

/// R-policy-span through a merge key: the typo is in `definitions:`, refused where it is used,
/// naming both sites.
#[test]
fn a_typo_inside_definitions_is_refused_at_its_use_site() {
    let refusal = refused(MERGED_TYPO, Code::PolicyUnknownField);
    assert!(names(&refusal, 9, 13), "use site: {refusal}");
    assert!(names(&refusal, 5, 5), "definition site: {refusal}");
}

#[test]
fn an_unused_typo_inside_definitions_is_not_refused() {
    let text = MERGED_TYPO.replace(
        "      - <<: *base\n        mode: read\n",
        "      - { path: /a, mode: read }\n",
    );
    assert!(parse(&text).is_ok());
}

/// The use site is the first merge outside `definitions:`, even when the anchor is merged into
/// another definition first.
#[test]
fn a_merge_through_a_definition_names_the_outer_use_site() {
    let text = "\
version: 1
definitions:
  base: &base
    mdoe: read
  root: &root
    <<: *base
    path: /src/playpen
workspaces:
  playpen:
    roots:
      - <<: *root
        mode: read
";
    let refusal = refused(text, Code::PolicyUnknownField);
    assert!(names(&refusal, 11, 13), "use site: {refusal}");
    assert!(names(&refusal, 4, 5), "definition site: {refusal}");
}

#[test]
fn a_merge_from_a_list_names_its_alias() {
    let text = "\
version: 1
definitions:
  a: &a { path: /src/playpen }
  b: &b { mdoe: read }
workspaces:
  playpen:
    roots:
      - <<: [*a, *b]
        mode: read
";
    let refusal = refused(text, Code::PolicyUnknownField);
    assert!(names(&refusal, 8, 18), "use site: {refusal}");
    assert!(names(&refusal, 4, 11), "definition site: {refusal}");
}

/// The kinds serde-saphyr hands back only as a message, each raised through an alias, so a
/// release that rewords them fails here rather than misfiling a refusal.
#[test]
fn an_unknown_field_through_an_alias_is_named_as_one() {
    let text = "\
version: 1
definitions:
  root: &root { path: /src/playpen, mode: read, mdoe: read }
workspaces:
  playpen:
    roots: [*root]
";
    let refusal = refused(text, Code::PolicyUnknownField);
    assert!(names(&refusal, 6, 13), "use site: {refusal}");
}

#[test]
fn an_invalid_variant_through_a_merge_is_a_type_refusal() {
    let text = MERGED_TYPO.replace("mdoe: read", "mode: no");
    let text = text.replace("        mode: read\n", "");
    let refusal = refused(&text, Code::PolicyType);
    assert!(names(&refusal, 9, 13), "use site: {refusal}");
    assert!(names(&refusal, 5, 11), "definition site: {refusal}");
}

#[test]
fn a_missing_field_through_an_alias_is_a_type_refusal() {
    let text = "\
version: 1
definitions:
  root: &root { path: /src/playpen }
workspaces:
  playpen:
    roots: [*root]
";
    refused(text, Code::PolicyType);
}

/// An anchor in a typed position is deserialised there first, so its refusal is its own.
#[test]
fn a_typo_in_a_typed_anchor_is_refused_at_its_definition() {
    let text = "\
version: 1
workspaces:
  a:
    roots:
      - &root { path: /a, mode: read, mdoe: read }
  b:
    roots:
      - <<: *root
";
    let refusal = refused(text, Code::PolicyUnknownField);
    assert!(names(&refusal, 5, 39), "{refusal}");
    assert!(!refusal.message().contains("defined at"), "{refusal}");
}

#[test]
fn a_refusal_is_one_line() {
    let refusal = refused(MERGED_TYPO, Code::PolicyUnknownField);
    assert!(!refusal.to_string().contains('\n'), "{refusal}");
}

const WORKED_EXAMPLE: &str = r#"
version: 1

definitions:
  anthropic-route: &anthropic-route
    host: api.anthropic.com
    path_prefix: /
    minter: anthropic-setup-token
    delivery: { env: CLAUDE_CODE_OAUTH_TOKEN }
    endpoints: [anthropic-inference-only]

minters:
  gh-app:
    command: [/etc/playpen/minters/github-app-token]
    revoke: [/etc/playpen/minters/github-app-revoke]
  anthropic-setup-token:
    command: [/etc/playpen/minters/keychain-read, playpen-anthropic-setup-token]

fragments:
  env:
    rust: [CARGO_HOME, RUSTUP_HOME]
  endpoints:
    github-read-only:
      - { method: GET,  path: /*/*/info/refs }
      - { method: POST, path: /*/*/git-upload-pack }
      - { method: GET,  path: /repos/*/*/** }
    anthropic-inference-only:
      - { method: POST, path: /v1/messages }

workspaces:
  playpen:
    roots:
      - { path: /Users/op/src/github.com/firefly-engineering/playpen, mode: readwrite }
    areas:
      landing: { lifetime: persistent }                  # concurrency defaults to exclusive
      cargo-cache: { lifetime: persistent, concurrency: shared }
      target: { lifetime: ephemeral }
    forge: { org: firefly-engineering }
    credentials:
      - host: github.com
        path_prefix: /firefly-engineering/
        minter: gh-app
        delivery: { env: GH_TOKEN }
        endpoints: [github-read-only]
      - host: api.github.com
        path_prefix: /repos/firefly-engineering/
        minter: gh-app
        delivery: { env: GH_TOKEN }
        endpoints: [github-read-only]

  notes:
    roots:
      - path: /Users/op/Documents/notes
        mode: read
        exclude:
          - { path: /Users/op/Documents/notes/private }   # classes default to all

profiles:
  firefly:
    prefixes: [/Users/op/src/github.com/firefly-engineering/]
    workspaces: [playpen, notes]
    toolchain:                       # emitted by playpen.lib.closureRoots on a Nix host
      - { path: /nix/store/…-git-2.51.2 }
      - { path: /nix/store/…-jujutsu-0.33.0 }
      # …one root per store path in the closure
    env:
      fragments: [rust]
      allow: [COLORTERM]
      set:
        CARGO_HOME: !area playpen/cargo-cache
        GIT_AUTHOR_NAME: playpen agent
        GIT_AUTHOR_EMAIL: agent@example.invalid
        GIT_COMMITTER_NAME: playpen agent
        GIT_COMMITTER_EMAIL: agent@example.invalid
    credentials:
      - *anthropic-route
    agent_state:
      claude: { share: [CLAUDE.md, settings.json, skills] }   # CLAUDE.md is imported, not linked
      omp: { share: [] }

  catch-all:
    prefixes: [/]                     # longest prefix wins, so `/` loses to everything
    workspaces: [notes]
    toolchain: []

shims:
  claude:
    target: /opt/homebrew/bin/claude  # stable link; resolved at launch
    kind: claude
    flags: [--dangerously-skip-permissions]
  omp:
    target: /Users/op/.local/bin/omp
    kind: omp
    profile: firefly
"#;

/// A root is a literal path, never a pattern ([spec §5.2]): a glob is refused at parse, wherever a
/// path is a grant.
///
/// [spec §5.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#52-brought-roots
#[test]
fn a_glob_in_a_root_is_a_type_refusal() {
    for glob in ["/src/*", "/src/play?en", "/src/[ab]"] {
        // Quoted, so the glob is a path to YAML and not flow syntax or an alias.
        let text = MINIMAL.replace("/src/playpen", &format!("{glob:?}"));
        let refusal = refused(&text, Code::PolicyType);
        assert!(names(&refusal, 5, 17), "{refusal}");
    }
}

#[test]
fn a_glob_in_an_exclusion_or_a_toolchain_root_is_a_type_refusal() {
    let excluded = MINIMAL.replace(
        "mode: readwrite }",
        "mode: readwrite, exclude: [{ path: \"/src/playpen/*\" }] }",
    );
    refused(&excluded, Code::PolicyType);
    let toolchain = MINIMAL.replace(
        "toolchain: []",
        "toolchain: [{ path: \"/nix/store/*-git\" }]",
    );
    refused(&toolchain, Code::PolicyType);
}
