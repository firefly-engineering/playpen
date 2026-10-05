//! Shims end to end ([spec §11.3]): the binary invoked under another name, dispatched on
//! `argv[0]`, with injected flags, re-entry and the link's own integrity.
//!
//! [spec §11.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#113-shims

mod common;

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use tempfile::TempDir;

use common::{Fixture, PLAYPEN, assert_refused, os_bin};

/// An installed shim: a symlink to the playpen binary, and a home holding the policy where the
/// search path finds it. `HOME` is used rather than `XDG_CONFIG_HOME` because `HOME` is in the
/// floor and crosses the boundary, so a shim re-entering from inside finds the same policy the
/// outer launch did.
struct Installed {
    /// The directory holding the link, which the profile reads and cannot write.
    dir: TempDir,
    name: String,
    home: TempDir,
}

impl Installed {
    /// Install a shim named `name`, and write the policy `document(link_dir, policy_dir)` builds
    /// where the search path will find it.
    fn new(name: &str, document: impl FnOnce(&Path, &Path) -> Value) -> Self {
        let dir = TempDir::new().expect("link dir");
        std::os::unix::fs::symlink(PLAYPEN, dir.path().join(name)).expect("symlink");
        let home = TempDir::new().expect("home");
        let policy_dir = home.path().join(".config/playpen");
        std::fs::create_dir_all(&policy_dir).expect("mkdir");
        let document = document(dir.path(), &policy_dir);
        std::fs::write(policy_dir.join("policy.json"), document.to_string()).expect("policy");
        Self {
            dir,
            name: name.to_owned(),
            home,
        }
    }

    fn link(&self) -> PathBuf {
        self.dir.path().join(&self.name)
    }

    fn policy(&self) -> PathBuf {
        self.home.path().join(".config/playpen/policy.json")
    }

    /// Invoke the shim from inside `root`, under `fx`'s state directory.
    fn invoke(&self, fx: &Fixture, root: &Path, argv: &[&str]) -> Command {
        let mut command = Command::new(self.link());
        command.args(argv);
        self.environment(&mut command, fx, root);
        command
    }

    /// As [`Installed::invoke`], with `argv[0]` the bare name, as a `PATH` lookup leaves it.
    fn invoke_by_name(&self, fx: &Fixture, root: &Path) -> Command {
        let mut command = Command::new(self.link());
        command.arg0(&self.name).env(
            "PATH",
            format!(
                "{}:{}",
                self.dir.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
        self.environment(&mut command, fx, root);
        command
    }

    fn environment(&self, command: &mut Command, fx: &Fixture, root: &Path) {
        command
            .current_dir(root)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("PLAYPEN_PROFILE")
            .env("XDG_STATE_HOME", fx.state_home())
            .env("HOME", self.home.path());
    }
}

/// The toolchain a shim launch needs to read: the policy, the link's directory and the playpen
/// binary. All read-only, so self-integrity passes.
fn readable(link_dir: &Path, policy_dir: &Path) -> Value {
    let playpen_dir = Path::new(PLAYPEN).parent().expect("a directory");
    json!([
        {"path": policy_dir},
        {"path": link_dir},
        {"path": playpen_dir},
    ])
}

/// A policy with one profile `p` over `root`, whose `prefixes` select it from inside `root`, and
/// the shim table `shims`.
fn document(root: &Path, link_dir: &Path, policy_dir: &Path, shims: Value) -> Value {
    json!({
        "version": 1,
        "workspaces": {"w": {"roots": [{"path": root, "mode": "readwrite"}]}},
        "profiles": {"p": {
            "workspaces": ["w"],
            "toolchain": readable(link_dir, policy_dir),
            "prefixes": [root],
        }},
        "shims": shims,
    })
}

/// How many injected tokens `sh -c` consumes before `"$@"` begins: `-c`, the script, and the name
/// it takes as `$0`.
const CONSUMED_BY_SH: usize = 3;

/// A shim whose target prints each of its arguments on a line of its own, with `then` injected
/// after the tokens `sh -c` consumes.
fn prints_argv(then: &[&str]) -> Value {
    let mut flags = vec![
        "-c".to_owned(),
        "printf '%s\\n' \"$@\"".to_owned(),
        "argv".to_owned(),
    ];
    flags.extend(then.iter().map(|flag| (*flag).to_owned()));
    json!({"target": os_bin("sh"), "kind": "claude", "flags": flags})
}

fn lines(output: &std::process::Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

fn succeeded(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A shim launches its target confined, with the shim's flags in front of the caller's argv, and
/// playpen reads none of it.
#[test]
fn a_symlink_named_claude_launches_its_target_confined() {
    let fx = Fixture::new();
    let shim = Installed::new("claude", |link_dir, policy_dir| {
        document(
            fx.root(),
            link_dir,
            policy_dir,
            json!({"claude": prints_argv(&["--dangerously-skip-permissions"])}),
        )
    });
    let output = shim
        .invoke(&fx, fx.root(), &["hello", "--profile"])
        .output()
        .expect("the shim");
    succeeded(&output);
    // The flags come first, and everything the caller passed is opaque — `--profile` included.
    assert_eq!(
        lines(&output),
        ["--dangerously-skip-permissions", "hello", "--profile"]
    );
    // A run of its own was recorded, under the shim's kind and the selected profile.
    let ids = fx.run_ids();
    assert_eq!(ids.len(), 1, "{ids:?}");
    assert_eq!(fx.record(&ids[0])["kind"], "claude");
    assert_eq!(fx.record(&ids[0])["profile"], "p");
}

/// Invoked under a name the policy declares no shim for, there is nothing to look up.
#[test]
fn an_unknown_name_refuses() {
    let fx = Fixture::new();
    let shim = Installed::new("codex", |link_dir, policy_dir| {
        document(
            fx.root(),
            link_dir,
            policy_dir,
            json!({"claude": {"target": os_bin("true"), "kind": "claude"}}),
        )
    });
    let output = shim.invoke(&fx, fx.root(), &[]).output().expect("the shim");
    let run = assert_refused(&output, "refusal.shim.unknown");
    let message = fx.record(&run)["refusal"]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(message.contains("\"codex\""), "{message}");
    assert!(message.contains("declared shims: claude"), "{message}");
}

/// A target that is not there refuses, and a relative one is never resolved against `PATH`: a
/// shim on `PATH` that searched `PATH` would find itself.
#[test]
fn a_missing_or_relative_target_refuses() {
    for target in ["/nonexistent/claude", "echo"] {
        let fx = Fixture::new();
        let shim = Installed::new("claude", |link_dir, policy_dir| {
            document(
                fx.root(),
                link_dir,
                policy_dir,
                json!({"claude": {"target": target, "kind": "claude"}}),
            )
        });
        let output = shim.invoke(&fx, fx.root(), &[]).output().expect("the shim");
        assert_refused(&output, "refusal.root.missing");
    }
}

/// A pinned `profile` is the chain's explicit step and wins; without one, `PLAYPEN_PROFILE` then
/// the working directory decide ([spec §11.4]).
///
/// [spec §11.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#114-profile-selection
#[test]
fn a_pinned_profile_wins_and_otherwise_the_chain_decides() {
    let fx = Fixture::new();
    let chain = |link_dir: &Path, policy_dir: &Path, shim: Value| {
        let toolchain = readable(link_dir, policy_dir);
        json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": fx.root(), "mode": "readwrite"}]}},
            "profiles": {
                "pinned": {"workspaces": ["w"], "toolchain": toolchain, "prefixes": []},
                "by-env": {"workspaces": ["w"], "toolchain": toolchain, "prefixes": []},
                "by-cwd": {"workspaces": ["w"], "toolchain": toolchain, "prefixes": [fx.root()]},
            },
            "shims": {"claude": shim},
        })
    };
    let pinned = Installed::new("claude", |link_dir, policy_dir| {
        chain(
            link_dir,
            policy_dir,
            json!({"target": os_bin("true"), "kind": "claude", "profile": "pinned"}),
        )
    });
    // The pin beats the environment.
    let output = pinned
        .invoke(&fx, fx.root(), &[])
        .env("PLAYPEN_PROFILE", "by-env")
        .output()
        .expect("the shim");
    succeeded(&output);
    assert_eq!(selected(&fx), "pinned");

    let unpinned = Installed::new("claude", |link_dir, policy_dir| {
        chain(
            link_dir,
            policy_dir,
            json!({"target": os_bin("true"), "kind": "claude"}),
        )
    });
    // With the pin gone, the environment beats the working directory.
    let output = unpinned
        .invoke(&fx, fx.root(), &[])
        .env("PLAYPEN_PROFILE", "by-env")
        .output()
        .expect("the shim");
    succeeded(&output);
    assert_eq!(selected(&fx), "by-env");

    // With neither, the working directory's longest prefix does.
    let output = unpinned
        .invoke(&fx, fx.root(), &[])
        .output()
        .expect("the shim");
    succeeded(&output);
    assert_eq!(selected(&fx), "by-cwd");
}

/// The profile of the most recent run the fixture recorded.
fn selected(fx: &Fixture) -> String {
    let ids = fx.run_ids();
    let latest = ids.last().expect("a run");
    fx.record(latest)["profile"]
        .as_str()
        .expect("a profile")
        .to_owned()
}

/// `P-argv`: the injected argv `explain --shim --json` shows is the argv the child received, with
/// provenance. The kind table's entries show too, because a shim is where a kind is named.
#[test]
fn explain_shim_shows_the_injected_argv_and_the_child_receives_it() {
    let fx = Fixture::new();
    let shim = Installed::new("claude", |link_dir, policy_dir| {
        document(
            fx.root(),
            link_dir,
            policy_dir,
            json!({"claude": prints_argv(&["--one", "--two"])}),
        )
    });
    let output = fx
        .playpen(&["explain", "--shim", "claude", "--json"])
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("PLAYPEN_PROFILE")
        .env("HOME", shim.home.path())
        .output()
        .expect("playpen explain");
    succeeded(&output);
    let resolved: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let argv = resolved["argv"].as_array().expect("argv").clone();
    assert_eq!(
        argv[0],
        json!({"value": os_bin("sh"), "from": "shim:claude.target"})
    );
    let from: Vec<_> = argv[1..]
        .iter()
        .map(|arg| arg["from"].as_str().expect("provenance"))
        .collect();
    assert_eq!(
        from,
        (0..argv.len() - 1)
            .map(|i| format!("shim:claude.flags[{i}]"))
            .collect::<Vec<_>>()
    );
    // The kind table's entries, with the kind as their author.
    let env = resolved["env"].as_array().expect("env").clone();
    let var = |name: &str| {
        env.iter()
            .find(|var| var["name"] == name)
            .unwrap_or_else(|| panic!("{name} is not in {resolved}"))
            .clone()
    };
    assert_eq!(var("CLAUDE_CODE_SANDBOXED")["from"], "kind:claude");
    assert_eq!(var("CLAUDE_CONFIG_DIR")["from"], "kind:claude");

    // What the child received: every injected token `sh -c` did not consume, then the caller's.
    let seen = shim
        .invoke(&fx, fx.root(), &["caller"])
        .output()
        .expect("the shim");
    succeeded(&seen);
    let mut expected: Vec<String> = argv[1 + CONSUMED_BY_SH..]
        .iter()
        .map(|arg| arg["value"].as_str().expect("a token").to_owned())
        .collect();
    expected.push("caller".into());
    assert_eq!(lines(&seen), expected);
}

/// No flag reaches the manifest: the agent already holds its own argv ([spec §13.2]).
///
/// [spec §13.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#132-content
#[test]
fn no_injected_flag_appears_in_the_manifest() {
    let fx = Fixture::new();
    let shim = Installed::new("claude", |link_dir, policy_dir| {
        document(
            fx.root(),
            link_dir,
            policy_dir,
            json!({"claude": {
                "target": os_bin("sh"),
                "kind": "claude",
                "flags": ["-c", "cat \"$PLAYPEN_MANIFEST\"", "argv", "--a-telltale-flag"],
            }}),
        )
    });
    let output = shim.invoke(&fx, fx.root(), &[]).output().expect("the shim");
    succeeded(&output);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("--a-telltale-flag"), "{text}");
    serde_json::from_str::<playpen::manifest::Manifest>(&text).expect("a manifest");
}

/// Inside an existing boundary the shim `exec`s the target in place: no new sandbox, no new run
/// record, and the outer run's environment kept whole.
#[test]
fn a_shim_inside_a_boundary_execs_the_target_in_place() {
    let fx = Fixture::new();
    let shim = Installed::new("claude", |link_dir, policy_dir| {
        document(
            fx.root(),
            link_dir,
            policy_dir,
            json!({"claude": {
                "target": os_bin("sh"),
                "kind": "claude",
                "flags": ["-c", "echo \"$PLAYPEN_ACTIVE\"", "argv"],
            }}),
        )
    });
    let before = fx.run_ids().len();
    let link = shim.link();
    let mut command = fx.playpen(&["run", "--profile", "p", "--agent", "claude", "--policy"]);
    let output = command
        .arg(shim.policy())
        .arg("--")
        .arg(link.to_str().expect("a UTF-8 path"))
        .current_dir(fx.root())
        .env_remove("XDG_CONFIG_HOME")
        .env("HOME", shim.home.path())
        .output()
        .expect("playpen run");
    succeeded(&output);
    // The target ran inside, and read the outer run's own environment.
    assert_eq!(lines(&output), ["p"]);
    // One new record, the outer run's: the re-entry opened none.
    assert_eq!(fx.run_ids().len(), before + 1);
}

/// Self-integrity extends to the link playpen was invoked through, and so to that link's
/// directory, which can replace it ([spec §11.7]).
///
/// [spec §11.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#117-self-integrity
#[test]
fn a_profile_that_can_write_the_shim_link_refuses() {
    let fx = Fixture::new();
    // The link's own directory as a read-write brought root: the shape an operator reaches for
    // when the shim lives beside the work.
    let shim = Installed::new("claude", |link_dir, policy_dir| {
        json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": link_dir, "mode": "readwrite"}]}},
            "profiles": {"p": {
                "workspaces": ["w"],
                "toolchain": readable(link_dir, policy_dir),
                "prefixes": [link_dir],
            }},
            "shims": {"claude": {"target": os_bin("true"), "kind": "claude"}},
        })
    });
    let root = shim.dir.path().to_owned();
    let output = shim.invoke(&fx, &root, &[]).output().expect("the shim");
    let run = assert_refused(&output, "refusal.integrity.writable");
    let message = fx.record(&run)["refusal"]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(message.contains("shim link"), "{message}");
}

/// Invoked by a bare name, the link is found where the caller's own `PATH` found it: the first
/// entry of that name resolving to this executable.
#[test]
fn a_shim_invoked_by_bare_name_finds_its_link_on_path() {
    let fx = Fixture::new();
    let shim = Installed::new("claude", |link_dir, policy_dir| {
        document(
            fx.root(),
            link_dir,
            policy_dir,
            json!({"claude": {"target": os_bin("true"), "kind": "claude"}}),
        )
    });
    let root = fx.root().to_owned();
    let output = shim.invoke_by_name(&fx, &root).output().expect("the shim");
    succeeded(&output);
}
