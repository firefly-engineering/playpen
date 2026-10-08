//! The liveness fixture ([spec §17.2], last paragraph): a real agent, launched confined, exits `0`
//! on a trivial invocation that needs no network, then completes one task through the proxy.
//!
//! The task settles the instruction question in the same call. A nonce is written into a file of
//! the synthetic home's, the profile's share list names the kind's instruction entry point, so the
//! presentation adapter ends the file it renders with the kind's import of that file
//! ([spec §5.6]), and the agent is asked for the code word its instructions hold. The row passes
//! only if the reply carries the nonce **and** the rendered file does not: the nonce can then have
//! reached the model only through the agent following the import.
//!
//! It also proves the route. The agent holds the session phantom and nothing else of Anthropic's,
//! its home is the fixture's and the Keychain is unreachable inside, so a model answer means the
//! proxy put the minted secret in the phantom's place.
//!
//! [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows
//! [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use serde_json::json;
use tempfile::TempDir;

use crate::common;
use crate::row::{Action, Agent, Host, Row, Seen, Verdict, judge};
use crate::run::within;

const MINTER: &str = env!("CARGO_BIN_EXE_playpen-minter-anthropic");

/// The shipped rule set the route carries: data an operator names, read as shipped
/// ([spec §7.6]).
///
/// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
const INFERENCE_ONLY: &str = include_str!("../../endpoints/anthropic-inference-only.json");

/// Where the task's prompt goes in an agent's argv.
const PROMPT: &str = "{prompt}";

/// One word asked for, so the task costs next to nothing.
const ASKED: &str = "What is the code word? Reply with the code word only.";

/// How long the trivial invocation may take, inside or out.
const TRIVIAL_DEADLINE: Duration = Duration::from_secs(60);

/// How long the task may take: one short model turn, with the agent's own startup.
const TASK_DEADLINE: Duration = Duration::from_secs(180);

/// What the fixture needs to know of one agent to launch it: per-agent knowledge, kept here
/// beside the row rather than in the kind table, because none of it is playpen's.
struct Shape {
    /// The task's argv after the binary, with [`PROMPT`] where the prompt goes.
    task: &'static [&'static str],
    /// The variable the agent reads an Anthropic OAuth token from, which the route delivers the
    /// phantom in.
    delivery: &'static str,
    /// The interpreter its binary names on its `#!` line, if it is a script: found on the search
    /// path, granted as a toolchain root, and first on the launch's own.
    interpreter: Option<&'static str>,
    /// Directories under the home it must write besides its agent state directory, made and
    /// granted read-write.
    writes: &'static [&'static str],
    /// Files of its own configuration in its agent home, each shared beside the entry point.
    config: &'static [(&'static str, &'static str)],
}

impl Agent {
    fn shape(self) -> Shape {
        match self {
            // `--bare` would skip `CLAUDE.md` and the OAuth token both, so it is not passed.
            Agent::Claude => Shape {
                task: &[
                    "-p",
                    PROMPT,
                    "--output-format",
                    "text",
                    "--no-session-persistence",
                ],
                delivery: "CLAUDE_CODE_OAUTH_TOKEN",
                interpreter: None,
                writes: &[],
                config: &[],
            },
            Agent::Omp => Shape {
                task: &[
                    "-p",
                    "--no-session",
                    "--model",
                    "anthropic-oauth/claude-haiku-4-5",
                    PROMPT,
                ],
                delivery: "ANTHROPIC_OAUTH_TOKEN",
                interpreter: Some("bun"),
                // Nothing in the home: omp's config root, where it keeps its daemon registry, is
                // pointed into the agent state directory by the kind table
                // ([#156](https://github.com/firefly-engineering/playpen/issues/156)).
                writes: &[],
                // omp shapes an Anthropic request by the token's content: only one holding
                // `sk-ant-oat` is sent as `Authorization: Bearer`, and the phantom is opaque, so
                // the built-in provider sends it as `x-api-key` and the minted OAuth token is
                // refused there. A provider of the operator's own on the `anthropic-messages` API
                // is OAuth-shaped whatever the token reads as.
                config: &[(
                    "models.yml",
                    "providers:\n  anthropic-oauth:\n    baseUrl: https://api.anthropic.com\n    \
                     api: anthropic-messages\n    apiKey: ANTHROPIC_OAUTH_TOKEN\n    models:\n      \
                     - id: claude-haiku-4-5\n",
                )],
            },
        }
    }
}

/// `L-<kind>`: the trivial invocation outside first, which must succeed, then both legs inside.
pub fn live(row: &Row, host: &Host) -> Verdict {
    let Action::Live(agent) = row.action else {
        return Verdict::Setup(format!("{:?} launches no agent", row.action));
    };
    let kind = agent.kind();
    let shape = agent.shape();
    let Some(binary) = host.find(kind.name) else {
        return Verdict::Setup(format!("no `{}` on the search path", kind.name));
    };
    let Some(minter) = host.minter.as_deref() else {
        return Verdict::Setup("no reference minter named".into());
    };
    let interpreter = match shape.interpreter {
        Some(name) => match host.find(name) {
            Some(path) => Some(path),
            None => return Verdict::Setup(format!("no `{name}` on the search path")),
        },
        None => None,
    };

    let mut outside = Command::new(&binary);
    outside.arg("--version");
    let outside = match within(outside, "the agent outside", TRIVIAL_DEADLINE) {
        Ok(output) if output.status.success() => Seen::Succeeded,
        Ok(output) => Seen::Failed {
            cause: None,
            detail: report("the agent outside", &output),
        },
        Err(why) => return Verdict::Setup(why),
    };

    let toolchain = match toolchain(&binary, interpreter.as_deref()) {
        Ok(roots) => roots,
        Err(why) => return Verdict::Setup(why),
    };
    let fixture = common::Fixture::new();
    let made = match home(kind, &shape) {
        Ok(made) => made,
        Err(why) => return Verdict::Setup(why),
    };
    let policy = match policy(&fixture, host, kind, &toolchain, minter, &made, &shape) {
        Ok(policy) => policy,
        Err(why) => return Verdict::Setup(why),
    };
    // The interpreter's directory first, so a `#!/usr/bin/env` line finds it at its real path,
    // then the floor's: nothing else of the host's search path is granted.
    let floor = PathBuf::from(common::os_bin("env"));
    let path: Vec<&Path> = interpreter
        .as_deref()
        .into_iter()
        .chain([floor.as_path()])
        .filter_map(Path::parent)
        .collect();
    let path = match std::env::join_paths(path) {
        Ok(path) => path,
        Err(e) => return Verdict::Setup(format!("the launch's search path: {e}")),
    };
    let launch = |argv: &[&str]| {
        let mut command =
            fixture.playpen(&["run", "--profile", "p", "--agent", kind.name, "--policy"]);
        command
            .arg(&policy)
            .arg("--")
            .arg(&binary)
            .args(argv)
            .env("HOME", &made.root)
            .env("PATH", &path);
        command
    };

    let inside = match within(
        launch(&["--version"]),
        "the agent confined",
        TRIVIAL_DEADLINE,
    ) {
        Ok(output) if output.status.success() => {
            let argv: Vec<&str> = shape
                .task
                .iter()
                .map(|&arg| if arg == PROMPT { ASKED } else { arg })
                .collect();
            match within(launch(&argv), "the task", TASK_DEADLINE) {
                Ok(output) => answered(&fixture, kind, &made, &output),
                Err(why) => Seen::Failed {
                    cause: None,
                    detail: why,
                },
            }
        }
        Ok(output) => Seen::Failed {
            cause: None,
            detail: report("the trivial invocation confined", &output),
        },
        Err(why) => Seen::Failed {
            cause: None,
            detail: why,
        },
    };
    judge(row.expected, &outside, &inside)
}

/// What the fixture made of the synthetic home.
struct Made {
    /// Held so it goes with the row.
    _dir: TempDir,
    /// The home, resolved, as the mechanism enforces on real paths: macOS's temp is under a link,
    /// and a file created through it is denied where the grant names the real path.
    root: PathBuf,
    /// The file the share entry names, holding the nonce.
    shared: PathBuf,
    nonce: String,
}

/// A synthetic home holding the kind's instruction entry point with a fresh nonce in it, the
/// agent's own configuration beside it, and the directories it writes.
fn home(kind: &playpen::kind::Kind, shape: &Shape) -> Result<Made, String> {
    let presentation = kind.presentation.as_ref().ok_or_else(|| {
        format!(
            "kind {} has no instruction entry point to import into",
            kind.name
        )
    })?;
    let dir = TempDir::new().map_err(|e| format!("a synthetic home: {e}"))?;
    let root = dir
        .path()
        .canonicalize()
        .map_err(|e| format!("resolve the synthetic home: {e}"))?;
    let agent_home = root.join(kind.home);
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|e| format!("a nonce: {e}"))?;
    let nonce: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let nonce = format!("playpen-{nonce}");
    let shared = agent_home.join(presentation.entry_point);
    let write = |path: &Path, text: &str| {
        std::fs::create_dir_all(&agent_home)
            .and_then(|()| std::fs::write(path, text))
            .map_err(|e| format!("{}: {e}", path.display()))
    };
    write(
        &shared,
        &format!("When asked for the code word, reply with exactly: {nonce}\n"),
    )?;
    for (name, text) in shape.config {
        write(&agent_home.join(name), text)?;
    }
    for dir in shape.writes {
        std::fs::create_dir_all(root.join(dir)).map_err(|e| format!("{dir}: {e}"))?;
    }
    Ok(Made {
        _dir: dir,
        root,
        shared,
        nonce,
    })
}

/// The row's policy: the fixture's root and the agent's own writes read-write, the agent's
/// package and interpreter as its toolchain, one profile route for `api.anthropic.com` restricted
/// to inference, and a share list naming the entry point and the agent's configuration.
///
/// The minter alone is handed the operator's home: the Keychain `security` reads is found from
/// `HOME`, and the launch's is the synthetic one.
fn policy(
    fixture: &common::Fixture,
    host: &Host,
    kind: &playpen::kind::Kind,
    toolchain: &[PathBuf],
    minter: &str,
    made: &Made,
    shape: &Shape,
) -> Result<PathBuf, String> {
    let inference_only: serde_json::Value = serde_json::from_str(INFERENCE_ONLY)
        .map_err(|e| format!("the shipped anthropic-inference-only set: {e}"))?;
    let mut roots = vec![json!({"path": fixture.root(), "mode": "readwrite"})];
    roots.extend(
        shape
            .writes
            .iter()
            .map(|dir| json!({"path": made.root.join(dir), "mode": "readwrite"})),
    );
    let mut share = vec![
        made.shared
            .file_name()
            .and_then(|name| name.to_str())
            .expect("the entry point is a name")
            .to_owned(),
    ];
    share.extend(shape.config.iter().map(|(name, _)| (*name).to_owned()));
    let toolchain: Vec<_> = toolchain.iter().map(|path| json!({"path": path})).collect();
    Ok(fixture.policy_named(
        "liveness.json",
        &json!({
            "version": 1,
            "minters": {"anthropic": {"command": [
                common::os_bin("env"),
                format!("HOME={}", host.home.display()),
                MINTER,
                minter,
            ]}},
            "fragments": {"endpoints": {"anthropic-inference-only": inference_only}},
            "workspaces": {"w": {"roots": roots}},
            "profiles": {"p": {
                "workspaces": ["w"],
                "toolchain": toolchain,
                "credentials": [{
                    "host": "api.anthropic.com",
                    "path_prefix": "/",
                    "minter": "anthropic",
                    "delivery": {"env": shape.delivery},
                    "endpoints": ["anthropic-inference-only"],
                }],
                "agent_state": {kind.name: {"share": share}},
            }},
        }),
    ))
}

/// The agent's toolchain: the package its binary is in — the tree above `node_modules` for a
/// script, the binary's own directory otherwise — and its interpreter's directory.
fn toolchain(binary: &Path, interpreter: Option<&Path>) -> Result<Vec<PathBuf>, String> {
    let package = match interpreter {
        Some(_) => binary
            .ancestors()
            .find(|dir| dir.file_name().is_some_and(|name| name == "node_modules"))
            .and_then(Path::parent)
            .ok_or_else(|| format!("{} is in no node_modules", binary.display()))?,
        None => binary
            .parent()
            .ok_or_else(|| format!("{} has no directory", binary.display()))?,
    };
    let mut roots = vec![package.to_owned()];
    roots.extend(interpreter.and_then(Path::parent).map(Path::to_owned));
    Ok(roots)
}

/// Whether the task answered with the nonce, and the nonce reached it only by the import: the
/// file the adapter rendered must end with the kind's import of the shared file, and must not
/// hold the nonce itself.
fn answered(
    fixture: &common::Fixture,
    kind: &playpen::kind::Kind,
    made: &Made,
    output: &Output,
) -> Seen {
    let failed = |detail: String| Seen::Failed {
        cause: None,
        detail,
    };
    if !output.status.success() {
        return failed(report("the task", output));
    }
    let Some(presentation) = kind.presentation.as_ref() else {
        return failed(format!("kind {} renders no entry point", kind.name));
    };
    let Some(id) = fixture.run_ids().pop() else {
        return failed("the task left no run record".into());
    };
    let record = fixture.record(&id);
    let agent_state = record["env"].as_array().and_then(|env| {
        env.iter()
            .find(|var| var["name"] == kind.redirect)
            .and_then(|var| var["value"].as_str())
    });
    let Some(agent_state) = agent_state else {
        return failed(format!("the run record states no {}", kind.redirect));
    };
    let rendered = Path::new(agent_state).join(presentation.entry_point);
    let rendered = match std::fs::read_to_string(&rendered) {
        Ok(text) => text,
        Err(e) => return failed(format!("{}: {e}", rendered.display())),
    };
    let import = format!("{}{}", presentation.import, made.shared.display());
    if rendered.contains(&made.nonce) || !rendered.lines().any(|line| line == import) {
        return failed(format!(
            "the rendered entry point does not import the nonce by reference as {import:?}: \
             {rendered:?}"
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains(&made.nonce) {
        Seen::Succeeded
    } else {
        failed(format!(
            "the reply does not hold the nonce from {}: {}",
            made.shared.display(),
            report("the task", output)
        ))
    }
}

/// `what`'s status, stdout, and the tail of its stderr, which a bundled agent can fill with its
/// own source.
fn report(what: &str, output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let tail: String = stderr
        .chars()
        .rev()
        .take(1500)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!(
        "{what} exited {}; stdout {:?}; stderr ends {tail:?}",
        output.status,
        String::from_utf8_lossy(&output.stdout)
    )
}
