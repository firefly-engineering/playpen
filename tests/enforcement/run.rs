//! Running rows: the bare floor through the floor self-test itself, each policy fixture as one
//! confined launch of the probe, with the same actions run outside first, and each refusal as
//! one invocation playpen declines ([spec §17.1]).
//!
//! [spec §17.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#171-form

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use playpen::capability::CapabilitySet;
use playpen::mechanism::Mechanism;
use playpen::record::Record;
use playpen::self_test::{self, canary_path};

/// The canary under this host's own floor, which every row that launches one names. Said once
/// here rather than at each call: the floor is a host fact the library no longer reads for itself
/// ([#134](https://github.com/firefly-engineering/playpen/issues/134)).
fn canary() -> std::path::PathBuf {
    canary_path(crate::common::dedicated_floor().as_deref())
}
use serde_json::Value;
use tempfile::{NamedTempFile, TempDir};

use crate::common::{self, PROBE};
use crate::row::{
    Action, Bracketed, CANARY, Cause, Checked, Declined, DedicatedFloor, Exchange, Exchanged,
    Expected, Fixture, Host, Invocation, Legs, Listening, Location, OVER_CEILING, Outcome, ROOT,
    Row, Rung, SH, SHIM, Seen, Services, Signalled, Substitution, Target, Traced, Verdict, applies,
    judge, judge_bracket, judge_coverage, judge_refusal, judge_request, judge_unexamined,
    over_ceiling_name,
};
use playpen::refusal::EXIT_REFUSED;

/// Every row's outcome, in table order. `home` is the caller's home directory, where the
/// credential targets live; it is handed in, never read from the environment here.
///
/// Must be called on the process's only thread: the bare floor's canary forks.
pub fn run(rows: &[Row], home: &Path) -> Vec<Outcome> {
    run_on(rows, &Host::at(home))
}

/// [`run`], on a host the caller has read more of than its home: the liveness suite's.
pub fn run_on(rows: &[Row], host: &Host) -> Vec<Outcome> {
    let home = host.home.as_path();
    let mut outcomes: Vec<Option<Outcome>> = rows
        .iter()
        .map(|row| applies(&row.platform, host).err())
        .collect();
    let mut fixtures: Vec<Fixture> = Vec::new();
    for row in rows {
        if !fixtures.contains(&row.fixture) {
            fixtures.push(row.fixture);
        }
    }
    for fixture in fixtures {
        let batch: Vec<usize> = (0..rows.len())
            .filter(|&i| outcomes[i].is_none() && rows[i].fixture == fixture)
            .collect();
        if batch.is_empty() {
            continue;
        }
        let members: Vec<&Row> = batch.iter().map(|&i| &rows[i]).collect();
        let verdicts = match fixture {
            Fixture::BareFloor => members.iter().map(|row| bare_floor(row)).collect(),
            Fixture::ProbeRoot => probe_root(&members, home),
            Fixture::Outside => members.iter().map(|row| refusal(row)).collect(),
            Fixture::NothingGranted => members.iter().map(|row| nothing_granted(row)).collect(),
            Fixture::DescendantDenied => members.iter().map(|row| descendant_denied(row)).collect(),
            Fixture::Toolchain => members.iter().map(|row| toolchain(row)).collect(),
            Fixture::Excluded => members.iter().map(|row| excluded(row)).collect(),
            Fixture::Manifest => members.iter().map(|row| manifest_is_true(row)).collect(),
            Fixture::Shim => members.iter().map(|row| argv_matches(row)).collect(),
            Fixture::CredentialRoute | Fixture::RestrictedRoute => members
                .iter()
                .map(|row| credential_route(row, fixture == Fixture::RestrictedRoute))
                .collect(),
            Fixture::Agent => members
                .iter()
                .map(|row| crate::live::live(row, host))
                .collect(),
        };
        for (i, verdict) in batch.into_iter().zip(verdicts) {
            outcomes[i] = Some(Outcome::Runs(verdict));
        }
    }
    outcomes
        .into_iter()
        .map(|outcome| outcome.expect("every row ran or was set aside"))
        .collect()
}

fn bare_floor(row: &Row) -> Verdict {
    match row.action {
        Action::Canary => judge(row.expected, &canary_outside(), &canary_inside()),
        action => Verdict::Setup(format!(
            "{action:?} needs the probe, and the bare floor admits no grant for it"
        )),
    }
}

/// A row under nothing granted: the canary outside, then `exec`ed by a child that applied an empty
/// capability set.
fn nothing_granted(row: &Row) -> Verdict {
    match row.action {
        Action::Canary => judge(row.expected, &canary_outside(), &canary_ungranted()),
        action => Verdict::Setup(format!(
            "{action:?} needs a grant, and nothing granted admits none"
        )),
    }
}

/// A row under a toolchain of one root made beside its target. The neighbour is read first, on
/// both sides: outside it shows the probe can read the kind of path at all, inside that the
/// toolchain was applied, without which a denial of the target would prove nothing.
fn toolchain(row: &Row) -> Verdict {
    let mut made = Made::default();
    let made_paths = match row.action {
        Action::Read(Target::StaleStorePath) => store_paths(),
        Action::Read(Target::DecoyKeg) => kegs(&mut made),
        action => Err(format!("{action:?} has no toolchain to stand beside")),
    };
    let Beside {
        root,
        neighbour,
        targets,
        _dir,
    } = match made_paths {
        Ok(beside) => beside,
        Err(why) => return Verdict::Setup(why),
    };
    let fixture = common::Fixture::with_toolchain("read", &[root.as_path()]);
    let policy = fixture.policy.clone();
    beside(row, &fixture, &policy, &neighbour, &targets)
}

/// The row's targets, read beside a neighbour the policy grants, outside and then confined under
/// `policy`. The neighbour comes first on both sides: outside it shows the probe can read the kind
/// of path at all, inside that the grant beside the targets was applied, without which a denial of
/// a target would prove nothing.
fn beside(
    row: &Row,
    fixture: &common::Fixture,
    policy: &Path,
    neighbour: &Path,
    targets: &[PathBuf],
) -> Verdict {
    let paths: Vec<String> = match std::iter::once(neighbour)
        .chain(targets.iter().map(PathBuf::as_path))
        .map(utf8)
        .collect()
    {
        Ok(paths) => paths,
        Err(why) => return Verdict::Setup(why),
    };
    let ops: Vec<&str> = paths
        .iter()
        .flat_map(|path| ["read", path.as_str()])
        .collect();
    let outside = Command::new(PROBE)
        .args(&ops)
        .output()
        .expect("run the probe");
    let probe = fixture.probe();
    let mut argv = vec![probe.to_str().expect("a UTF-8 probe path")];
    argv.extend(&ops);
    let inside = fixture
        .run_under(policy, &argv)
        .stdin(Stdio::null())
        .output()
        .expect("run playpen");
    let (outside, inside) = match (observe(outside, paths.len()), observe(inside, paths.len())) {
        (Ok(outside), Ok(inside)) => (outside, inside),
        (Err(why), _) => return Verdict::Setup(format!("outside: {why}")),
        (_, Err(why)) => return Verdict::Fail(format!("inside: {why}")),
    };
    match judge(Expected::Succeeds, &outside[0], &inside[0]) {
        Verdict::Pass => {}
        Verdict::Fail(why) => {
            return Verdict::Fail(format!(
                "the grant beside the target is unreadable inside, so it was not applied: {why}"
            ));
        }
        setup => return setup,
    }
    outside[1..]
        .iter()
        .zip(&inside[1..])
        .map(|(outside, inside)| judge(row.expected, outside, inside))
        .find(|verdict| *verdict != Verdict::Pass)
        .unwrap_or(Verdict::Pass)
}

/// A decoy in a subdirectory the policy excludes from the probe's own root, beside a file the
/// root still grants ([spec §8.4]). Both live in the root's temp directory and go with it.
///
/// [spec §8.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#84-exclusions
fn excluded(row: &Row) -> Verdict {
    if row.action != Action::Read(Target::ExcludedDecoy) {
        return Verdict::Setup(format!("{:?} is not read from an exclusion", row.action));
    }
    let fixture = common::Fixture::with_mode("read");
    let (excluded, neighbour) = (
        fixture.root().join("excluded"),
        fixture.root().join("granted"),
    );
    let decoy = excluded.join("credentials");
    let made = fs::create_dir(&excluded)
        .and_then(|()| fs::write(&decoy, DECOY))
        .and_then(|()| fs::write(&neighbour, DECOY));
    if let Err(e) = made {
        return Verdict::Setup(format!("decoy under {}: {e}", excluded.display()));
    }
    let policy = fixture.policy_named(
        "excluded.json",
        &serde_json::json!({
            "version": 1,
            "workspaces": {"w": {"roots": [
                {"path": fixture.root(), "mode": "read", "exclude": [{"path": excluded}]},
            ]}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
        }),
    );
    beside(row, &fixture, &policy, &neighbour, &[decoy])
}

/// `P-manifest`: **the manifest is true** ([spec §13]). Every path it states is reachable at its
/// stated mode from inside the run it describes, a decoy outside every grant is not, and **every
/// route it states authenticates through the proxy**.
///
/// Two launches of one policy. The first learns the run-scoped paths from the environment, writes
/// into each of them, and copies the manifest out; the paths it printed are then checked against
/// what the manifest said they were, so a manifest naming the wrong scratch or the wrong area
/// fails here rather than misleading an agent. The second probes the paths that outlive a run —
/// the two roots at their two modes, and the persistent area — and the decoy beside them, and
/// issues one request per stated route.
///
/// The route half is **projection-is-true, not the secret's bytes**: ADR 0011 makes the manifest a
/// document that describes without constituting, so what this catches is drift between the stated
/// route table and the live one. Every input to each request — the host, the path prefix, the
/// variable the phantom is delivered in — is read **from the manifest**, so a manifest that stated
/// the wrong prefix or the wrong delivery variable sends a request no route authenticates and
/// fails here. That a secret arrives in the header a phantom came in is `P-endpoint`'s to assert,
/// and it does.
///
/// [spec §13]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#13-the-manifest
fn manifest_is_true(row: &Row) -> Verdict {
    if row.action != Action::ManifestIsTrue {
        return Verdict::Setup(format!("{:?} is not the manifest's own check", row.action));
    }
    // The route half's destination, outside the launch and reclaimed with the row, as every
    // route-bearing row's is.
    let destination = match destination() {
        Ok(destination) => destination,
        Err(why) => return Verdict::Setup(why),
    };
    let fixture = common::Fixture::new();
    let root = match destination.root_in(&fixture) {
        Ok(root) => root,
        Err(why) => return Verdict::Setup(why),
    };
    let (read_only, elsewhere) = match (TempDir::new(), TempDir::new()) {
        (Ok(read_only), Ok(elsewhere)) => (read_only, elsewhere),
        _ => return Verdict::Setup("a directory for the row's roots".into()),
    };
    let readable = |dir: &Path| dir.join("readable");
    let decoy = elsewhere.path().join("credentials");
    let seeded = fs::write(readable(read_only.path()), DECOY)
        .and_then(|()| fs::write(readable(fixture.root()), DECOY))
        .and_then(|()| fs::write(&decoy, DECOY));
    if let Err(e) = seeded {
        return Verdict::Setup(format!("seeding the row's roots: {e}"));
    }
    let policy = fixture.policy_named(
        "manifest.json",
        &serde_json::json!({
            "version": 1,
            "minters": {"m": {"command": [
                common::os_bin("sh"), "-c",
                format!(
                    r#"cat >/dev/null; printf '{{"token":"{ROUTE_SECRET}","expires_at":"2099-01-01T00:00:00Z"}}'"#
                ),
            ]}},
            "workspaces": {"w": {
                "roots": [
                    {"path": fixture.root(), "mode": "readwrite"},
                    {"path": read_only.path(), "mode": "read"},
                ],
                // So the manifest has a route table to be wrong about, as it has areas and roots.
                "credentials": [{
                    "host": "localhost",
                    "path_prefix": ROUTE_PREFIX,
                    "minter": "m",
                    "delivery": {"env": ROUTE_DELIVERY},
                }],
                "areas": {
                    "landing": {"lifetime": "persistent", "concurrency": "shared"},
                    "target": {"lifetime": "ephemeral"},
                },
                "forge": {"org": "firefly-engineering"},
            }},
            "profiles": {"p": {
                "workspaces": ["w"],
                "toolchain": [],
                // So the run can name its own areas without reading the manifest to find them:
                // what the manifest says they are is then an independent statement to check.
                "env": {"set": {
                    "AREA_LANDING": {"area": "w/landing"},
                    "AREA_TARGET": {"area": "w/target"},
                }},
            }},
        }),
    );
    let copied = fixture.root().join("manifest-copy.json");
    let script = format!(
        "set -e\n\
         for d in \"$TMPDIR\" \"$CLAUDE_CONFIG_DIR\" \"$AREA_LANDING\" \"$AREA_TARGET\"; do\n\
         \techo \"$d\"\n\
         \techo written > \"$d/playpen-suite-written\"\n\
         done\n\
         cp \"$PLAYPEN_MANIFEST\" {}\n",
        match utf8(&copied) {
            Ok(path) => path,
            Err(why) => return Verdict::Setup(why),
        }
    );
    let mut launching = fixture.run_under(&policy, &[&common::os_bin("sh"), "-c", &script]);
    launching.stdin(Stdio::null());
    let launched = trusting_only(&mut launching, &root)
        .output()
        .expect("run playpen");
    if !launched.status.success() {
        return Verdict::Fail(format!(
            "the run could not write every path the manifest states: {}, stderr {:?}",
            launched.status,
            String::from_utf8_lossy(&launched.stderr)
        ));
    }
    let stated: Vec<String> = String::from_utf8_lossy(&launched.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    let [scratch, agent_state, landing, target] = match <[String; 4]>::try_from(stated) {
        Ok(four) => four,
        Err(stated) => {
            return Verdict::Fail(format!("the run named {} paths, not 4", stated.len()));
        }
    };
    let manifest: playpen::manifest::Manifest = match fs::read_to_string(&copied)
        .map_err(|e| format!("{e}"))
        .and_then(|text| serde_json::from_str(&text).map_err(|e| format!("{e}")))
    {
        Ok(manifest) => manifest,
        Err(why) => return Verdict::Fail(format!("the manifest the run was given: {why}")),
    };
    // What the manifest said the run-scoped paths were, against what the run found them to be.
    let area = |name: &str| {
        manifest
            .workspaces
            .iter()
            .flat_map(|workspace| &workspace.areas)
            .find(|area| area.name == name)
            .map(|area| area.path.display().to_string())
    };
    for (what, stated, found) in [
        (
            "the run scratch",
            Some(manifest.run_scratch.display().to_string()),
            scratch,
        ),
        (
            "the agent state directory",
            Some(manifest.agent_state.display().to_string()),
            agent_state,
        ),
        ("the persistent area", area("landing"), landing),
        ("the ephemeral area", area("target"), target),
    ] {
        if stated.as_deref() != Some(found.as_str()) {
            return Verdict::Fail(format!(
                "the manifest states {what} at {stated:?}, and the run had it at {found:?}"
            ));
        }
    }
    // The paths that outlive a run, probed at the modes the manifest states them at, with the
    // decoy beside them: what is stated is reachable, and what is not stated is not.
    let mut ops: Vec<(String, &str, Expected)> = Vec::new();
    for workspace in &manifest.workspaces {
        for root in &workspace.roots {
            match utf8(&readable(&root.path)) {
                Ok(path) => ops.push((path, "read", Expected::Succeeds)),
                Err(why) => return Verdict::Setup(why),
            }
            // A `read` root grants read and execute, never write: the stated mode is the whole
            // statement, so a writable `read` root is a false manifest.
            let created = root.path.join("playpen-suite-created");
            let expected = match root.mode {
                playpen::manifest::Mode::Readwrite => Expected::Succeeds,
                playpen::manifest::Mode::Read => Expected::Denial,
            };
            match utf8(&created) {
                Ok(path) => ops.push((path, "write", expected)),
                Err(why) => return Verdict::Setup(why),
            }
        }
    }
    match area("landing").map(|path| Path::new(&path).join("playpen-suite-created")) {
        Some(path) => match utf8(&path) {
            Ok(path) => ops.push((path, "write", Expected::Succeeds)),
            Err(why) => return Verdict::Setup(why),
        },
        None => return Verdict::Fail("the manifest states no persistent area".into()),
    }
    match utf8(&decoy) {
        Ok(path) => ops.push((path, "read", Expected::Denial)),
        Err(why) => return Verdict::Setup(why),
    }
    // The route half: one request per route the manifest states, built from the host, the path
    // prefix and the delivery variable **the manifest named**. A route table stated wrong sends a
    // request no route authenticates, and that is the drift this catches.
    //
    // Outside the same request goes direct, which shows the destination is up and verifiable from
    // this host; inside it goes through the proxy. The leg is a probe argument on both sides.
    let routes = &manifest.network.routes;
    if routes.is_empty() {
        return Verdict::Fail("the manifest states no route, so its route half is vacuous".into());
    }
    let mut route_ops: Vec<RouteOp> = Vec::new();
    for (i, route) in routes.iter().enumerate() {
        let path = format!("{}manifest-{i}", route.path_prefix);
        let authority = format!("{}:{}", route.host, destination.addr.port());
        route_ops.push(RouteOp {
            outside: request_json(Via::Direct, &authority, "GET", &path, &route.delivery_env),
            inside: request_json(Via::Proxy, &authority, "GET", &path, &route.delivery_env),
            path,
            stated: format!("{}{}", route.host, route.path_prefix),
        });
    }

    // The filesystem ops run on both sides; the route ops run as a second invocation of their own,
    // because what makes their outside half hold is the destination's `200` and not merely that
    // the probe reported a request — which is all a filesystem verdict carries.
    let argv: Vec<&str> = ops
        .iter()
        .flat_map(|(path, verb, _)| [*verb, path.as_str()])
        .collect();
    let outside = Command::new(PROBE)
        .args(&argv)
        .output()
        .expect("run the probe");
    let mut routes_outside = Command::new(PROBE);
    trusting_only(&mut routes_outside, &root);
    for op in &route_ops {
        routes_outside.args(["request", op.outside.as_str()]);
    }
    // Outside there is no run and so no phantom; this half shows only that the destination is up
    // and verifiable from this host, which is what it is for.
    for route in routes {
        routes_outside.env(&route.delivery_env, "not-a-token");
    }
    let routes_outside = routes_outside
        .stdin(Stdio::null())
        .output()
        .expect("run the probe");
    let routes_outside = match exchanged(&routes_outside) {
        Ok(answers) if answers.len() == route_ops.len() => answers,
        Ok(answers) => {
            return Verdict::Setup(format!(
                "outside: the probe answered {} of {} route requests: {answers:?}",
                answers.len(),
                route_ops.len()
            ));
        }
        Err(why) => return Verdict::Setup(format!("outside: {why}")),
    };
    // What the destination recorded of the outside half is not the inside half's record.
    destination.forget();
    // Every op must succeed outside, whatever it is asserted to do inside, or the inside proves
    // nothing. The writes made outside are removed again, so each side creates its own.
    let probe = fixture.probe();
    let mut inside_argv = vec![probe.to_str().expect("a UTF-8 probe path")];
    inside_argv.extend(&argv);
    for op in &route_ops {
        inside_argv.extend(["request", op.inside.as_str()]);
    }
    for (path, verb, _) in &ops {
        if *verb == "write" {
            let _ = fs::remove_file(path);
        }
    }
    let mut probing = fixture.run_under(&policy, &inside_argv);
    probing.stdin(Stdio::null());
    let inside = trusting_only(&mut probing, &root)
        .output()
        .expect("run playpen");
    let actions = ops.len() + route_ops.len();
    let (outside, inside) = match (observe(outside, ops.len()), observe(inside, actions)) {
        (Ok(outside), Ok(inside)) => (outside, inside),
        (Err(why), _) => return Verdict::Setup(format!("outside: {why}")),
        (_, Err(why)) => return Verdict::Fail(format!("inside: {why}")),
    };
    let filesystem = ops
        .iter()
        .zip(outside.iter().zip(&inside))
        .map(|((path, verb, expected), (outside, inside))| {
            match judge(*expected, outside, inside) {
                Verdict::Pass => Verdict::Pass,
                Verdict::Fail(why) => Verdict::Fail(format!("{verb} {path}: {why}")),
                Verdict::Setup(why) => Verdict::Setup(format!("{verb} {path}: {why}")),
            }
        })
        .find(|verdict| *verdict != Verdict::Pass);
    if let Some(failed) = filesystem {
        return failed;
    }
    // The route half, judged by what arrived at the destination: a `200` says the legs connected
    // and says nothing about which token went out.
    let received = destination.received();
    let substitution = Substitution {
        secret: ROUTE_SECRET,
        header: ROUTE_HEADER,
    };
    route_ops
        .iter()
        .zip(routes_outside.iter().zip(&inside[ops.len()..]))
        .map(|(op, (outside, inside))| {
            let arrived = received
                .iter()
                .find(|head| head.contains(&format!(" {} HTTP/1.1\r\n", op.path)))
                .cloned();
            // The destination answering `200` is what makes the outside half hold: one that is
            // down, or that this host cannot verify, is a host condition and not a false manifest.
            let outside = match outside {
                Ok(answer) if answer.starts_with("HTTP/1.1 200 ") => Seen::Succeeded,
                Ok(answer) => Seen::Failed {
                    cause: None,
                    detail: format!("the destination answered {answer:?}"),
                },
                Err(why) => Seen::Failed {
                    cause: None,
                    detail: why.clone(),
                },
            };
            let seen = Exchanged {
                proxied: Exchange {
                    answer: match inside {
                        Seen::Succeeded => Ok("the probe reported an answer".into()),
                        Seen::Failed { detail, .. } => Err(detail.clone()),
                    },
                    arrived,
                },
                unbrokered: None,
                detail: format!(
                    "the route the manifest states as {}: the destination received {received:?}",
                    op.stated
                ),
            };
            judge_request(Expected::Authenticated, substitution, &outside, &seen)
        })
        .find(|verdict| *verdict != Verdict::Pass)
        .unwrap_or(Verdict::Pass)
}

/// One request a stated route is checked with: the same request on each leg, the path it asks for,
/// and the route as the manifest stated it, for the report.
struct RouteOp {
    outside: String,
    inside: String,
    path: String,
    stated: String,
}

/// `P-argv`: the injected argv `explain --shim --json` states is the argv the child received
/// ([spec §11.3]).
///
/// A shim installed as an operator installs one — a symlink to the playpen binary, and the policy
/// where the search path finds it. `HOME` names that search path rather than `XDG_CONFIG_HOME`,
/// because `HOME` is in the floor and so means the same thing on both sides of the boundary.
///
/// The target is the floor's shell, printing one argument a line. `sh -c` consumes the first three
/// injected tokens — `-c`, the script, and the name it takes as `$0` — so what the child prints is
/// every injected token after those, then the caller's own.
///
/// [spec §11.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#113-shims
fn argv_matches(row: &Row) -> Verdict {
    if row.action != Action::ArgvMatches {
        return Verdict::Setup(format!("{:?} is not the shim's argv check", row.action));
    }
    /// How many injected tokens `sh -c` consumes before `"$@"` begins.
    const CONSUMED_BY_SH: usize = 3;
    let fixture = common::Fixture::new();
    let (links, home) = match (TempDir::new(), TempDir::new()) {
        (Ok(links), Ok(home)) => (links, home),
        _ => return Verdict::Setup("a directory for the shim and its policy".into()),
    };
    let link = links.path().join("claude");
    let search = home.path().join(".config/playpen");
    let installed = fs::create_dir_all(&search)
        .and_then(|()| std::os::unix::fs::symlink(common::PLAYPEN, &link));
    if let Err(e) = installed {
        return Verdict::Setup(format!("installing the shim: {e}"));
    }
    let playpen_dir = match Path::new(common::PLAYPEN).parent() {
        Some(dir) => dir,
        None => return Verdict::Setup("the playpen binary has no directory".into()),
    };
    // Read-only, so self-integrity passes: nothing a shim launch reaches is writable from inside.
    let document = serde_json::json!({
        "version": 1,
        "workspaces": {"w": {"roots": [{"path": fixture.root(), "mode": "readwrite"}]}},
        "profiles": {"p": {
            "workspaces": ["w"],
            "toolchain": [{"path": &search}, {"path": links.path()}, {"path": playpen_dir}],
            "prefixes": [fixture.root()],
        }},
        "shims": {"claude": {
            "target": common::os_bin("sh"),
            "kind": "claude",
            "flags": ["-c", "printf '%s\\n' \"$@\"", "argv", "--injected", "--and-another"],
        }},
    });
    if let Err(e) = fs::write(search.join("policy.json"), document.to_string()) {
        return Verdict::Setup(format!("writing the policy: {e}"));
    }
    // Outside first: what playpen says it injects, with its provenance.
    let explained = fixture
        .playpen(&["explain", "--shim", "claude", "--json"])
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("PLAYPEN_PROFILE")
        .env("HOME", home.path())
        .output()
        .expect("run playpen explain");
    if !explained.status.success() {
        return Verdict::Setup(format!(
            "explain --shim: {}",
            String::from_utf8_lossy(&explained.stderr)
        ));
    }
    let resolved: Value = match serde_json::from_slice(&explained.stdout) {
        Ok(resolved) => resolved,
        Err(e) => return Verdict::Setup(format!("explain --shim --json: {e}")),
    };
    let Some(stated) = resolved["argv"].as_array() else {
        return Verdict::Fail("explain --shim --json states no argv".into());
    };
    if stated.len() <= CONSUMED_BY_SH {
        return Verdict::Setup(format!(
            "the shim injects too little to assert on: {stated:?}"
        ));
    }
    let tokens: Vec<String> = stated
        .iter()
        .map(|arg| arg["value"].as_str().unwrap_or_default().to_owned())
        .collect();
    // Inside: the same shim, run as the caller runs it, printing what it actually received.
    let mut command = Command::new(&link);
    command
        .arg("--from-the-caller")
        .current_dir(fixture.root())
        .stdin(Stdio::null())
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("PLAYPEN_PROFILE")
        .env("XDG_STATE_HOME", fixture.state_home())
        .env("HOME", home.path());
    let seen = command.output().expect("run the shim");
    if !seen.status.success() {
        return Verdict::Fail(format!(
            "the shim did not launch: {}, stderr {:?}",
            seen.status,
            String::from_utf8_lossy(&seen.stderr)
        ));
    }
    let received: Vec<String> = String::from_utf8_lossy(&seen.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    // The target is `argv[0]`, and `sh -c` swallows the three after it; everything else reached
    // the child, in order, with the caller's own argument last.
    let mut expected = tokens[1 + CONSUMED_BY_SH..].to_vec();
    expected.push("--from-the-caller".into());
    if received == expected {
        Verdict::Pass
    } else {
        Verdict::Fail(format!(
            "explain states {tokens:?}, so the child should have received {expected:?}, and it \
             received {received:?}"
        ))
    }
}

/// The secret the credential-route fixture's minter hands back. Never on a command line and never
/// in the child's environment: the child holds the phantom, and this is what the destination must
/// have received in its place.
const ROUTE_SECRET: &str = "the-real-secret-playpen-injected";

/// The variable this fixture's one route delivers the phantom in. A name of the suite's own, so it
/// collides with nothing playpen writes and nothing a kind sets.
const ROUTE_DELIVERY: &str = "PLAYPEN_SUITE_ROUTE_TOKEN";

/// The header the probe presents the phantom in, and so the header the secret must arrive in:
/// substitution is **in place**, and a proxy that moved it has not done this ([spec §7.3]).
///
/// [spec §7.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#73-session-phantom
const ROUTE_HEADER: &str = "x-api-key";

/// The route's path prefix, which both legs' paths lie under, so each selects the route.
const ROUTE_PREFIX: &str = "/v1/";

/// The path each leg asks for: one per leg, so what arrived at the destination is matched to the
/// leg that sent it by its own request line rather than by arrival order.
const PROXIED_PATH: &str = "/v1/messages";
const BYPASSING_PATH: &str = "/v1/bypassed";
const TUNNELLED_PATH: &str = "/v1/tunnelled";

/// The authority the tunnelled leg names: the **same listener** as every other leg, under the name
/// no route carries, so the proxy opens an opaque `CONNECT` to it rather than intercepting.
///
/// `127.0.0.1` rather than a made-up name because it resolves without the fixture arranging
/// anything, and the destination's leaf carries it as a SAN beside `localhost`.
const UNROUTED_HOST: &str = "127.0.0.1";

/// The one method [`Fixture::RestrictedRoute`]'s rule set allows, on [`PROXIED_PATH`]. The row then
/// asks for that path with [`DENIED_METHOD`], so what the denial turns on is the **method** and not
/// the path: the method is matched exactly, and a request that differs only there is the sharpest
/// instance of it.
const ALLOWED_METHOD: &str = "POST";
const DENIED_METHOD: &str = "GET";

/// A loopback TLS destination the harness stands up **outside** the launch, answering as
/// `localhost` and recording every request head it is sent ([ADR 0016]).
///
/// Outside, because the two-part form wants what arrived observable from outside: a listener inside
/// the sandbox reporting on itself is the probe grading its own homework. `localhost`, because
/// route matching is an exact compare on the authority the `CONNECT` named, and nothing in the
/// proxy can make a name resolve.
///
/// [ADR 0016]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md
struct Destination {
    /// `127.0.0.1:<port>`, whose port every leg's authority carries.
    addr: SocketAddr,
    /// Its own root, in PEM, which the launch's `SSL_CERT_FILE` names. Nothing of the host's trust
    /// store is touched to make this row pass.
    root: String,
    /// Every request head it has received, in arrival order, readable while the run is live.
    received: Arc<Mutex<Vec<String>>>,
    /// Set on drop, and the loop sees it on the connection drop makes.
    stopping: Arc<AtomicBool>,
    /// A second descriptor on the listening socket, held for this value's whole life so the
    /// wake-up connect reaches this socket and not whatever the kernel next hands the port to.
    _held: TcpListener,
    served: Option<std::thread::JoinHandle<()>>,
}

/// Stand up the destination. Its root and leaf are made here and die with the process, so no
/// trust store of the host's is involved on either side.
fn destination() -> Result<Destination, String> {
    let failed = |what: &str, e: rcgen::Error| format!("the destination cannot {what}: {e}");
    let root_key = rcgen::KeyPair::generate().map_err(|e| failed("make a root key", e))?;
    let mut root_params =
        rcgen::CertificateParams::new(Vec::new()).map_err(|e| failed("describe a root", e))?;
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    let root = root_params
        .self_signed(&root_key)
        .map_err(|e| failed("sign a root", e))?;
    let leaf_key = rcgen::KeyPair::generate().map_err(|e| failed("make a leaf key", e))?;
    // Both names for one listener: `localhost`, which the route carries, and `127.0.0.1`, which no
    // route carries, so the same destination is intercepted under one name and tunnelled to under
    // the other.
    let leaf =
        rcgen::CertificateParams::new(vec!["localhost".to_owned(), UNROUTED_HOST.to_owned()])
            .map_err(|e| failed("describe a leaf", e))?
            .signed_by(
                &leaf_key,
                &rcgen::Issuer::from_params(&root_params, &root_key),
            )
            .map_err(|e| failed("sign a leaf", e))?;

    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("the destination's protocol versions: {e}"))?
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone(), root.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            leaf_key.serialize_der(),
        )),
    )
    .map_err(|e| format!("the destination's certificate: {e}"))?;
    // The one protocol the broker speaks, so a client that would have chosen HTTP/2 does not.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);

    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| format!("the destination cannot bind loopback: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("the destination's address: {e}"))?;
    let held = listener
        .try_clone()
        .map_err(|e| format!("a second descriptor on the destination: {e}"))?;
    let received = Arc::new(Mutex::new(Vec::new()));
    let stopping = Arc::new(AtomicBool::new(false));
    let (recording, done) = (Arc::clone(&received), Arc::clone(&stopping));
    let served = std::thread::Builder::new()
        .name("playpen-suite-destination".into())
        .spawn(move || {
            // One connection at a time: the legs are driven in order, so nothing here needs to
            // hold two.
            while let Ok((socket, _)) = listener.accept() {
                if done.load(Ordering::SeqCst) {
                    return;
                }
                let session = match rustls::ServerConnection::new(Arc::clone(&config)) {
                    Ok(session) => session,
                    Err(_) => continue,
                };
                let mut tls = rustls::StreamOwned::new(session, socket);
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while head.len() < 64 * 1024 {
                    match tls.read(&mut byte) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => head.push(byte[0]),
                    }
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                // Recorded only if it is a head at all, so a client that connected and said
                // nothing is not an upstream leg.
                if head.ends_with(b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&head).into_owned();
                    if let Ok(mut recording) = recording.lock() {
                        recording.push(head);
                    }
                }
                let _ = tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                let _ = tls.flush();
            }
        })
        .map_err(|e| format!("the destination cannot serve: {e}"))?;
    Ok(Destination {
        addr,
        root: root.pem(),
        received,
        stopping,
        _held: held,
        served: Some(served),
    })
}

impl Destination {
    /// `host:port` for this destination under `host`, which decides whether a route matches it.
    fn authority(&self, host: &str) -> String {
        format!("{host}:{}", self.addr.port())
    }

    /// Write this destination's root where a launch can name it, and return the path. In the
    /// fixture's own policy directory, which goes with the fixture, so it is reclaimed even on a
    /// run killed before teardown.
    fn root_in(&self, fixture: &common::Fixture) -> Result<PathBuf, String> {
        let root = fixture.policy_dir.path().join("destination-root.pem");
        fs::write(&root, &self.root)
            .map(|()| root.clone())
            .map_err(|e| format!("the destination's root {}: {e}", root.display()))
    }

    /// Every head received so far, and nothing of what a later leg sends.
    fn received(&self) -> Vec<String> {
        self.received
            .lock()
            .map(|received| received.clone())
            .unwrap_or_default()
    }

    /// Forget what has arrived, so the outside half of the assertion is not mistaken for the
    /// inside one: the same request is made outside first, and the destination records it too.
    fn forget(&self) {
        if let Ok(mut received) = self.received.lock() {
            received.clear();
        }
    }
}

/// Name `root` as this one process's whole trust store, the way every Unix TLS client reads it
/// ([ADR 0030]).
///
/// On **one** command and never on the suite: per-suite would narrow every other row's upstream
/// trust and make one row's failure read as another's. `SSL_CERT_DIR` is removed as well, so the
/// store is genuinely *replaced* rather than widened — a proxy trusting only this root cannot pass
/// by having reached something else.
///
/// [ADR 0030]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0030-the-hosts-own-trust-store-is-what-the-host-says-it-is.md
fn trusting_only<'a>(command: &'a mut Command, root: &Path) -> &'a mut Command {
    command
        .env("SSL_CERT_FILE", root)
        .env_remove("SSL_CERT_DIR")
}

impl Drop for Destination {
    /// Reclaimed with the row: the listener closes and the thread ends. Woken with a connection of
    /// its own rather than by `shutdown`, which Linux honours on a listener and Darwin does not.
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(served) = self.served.take() {
            let _ = served.join();
        }
    }
}

/// `P-endpoint`, `P-open-bypass`, `N-endpoint` and `N-endpoint-no-leg` ([spec §17.2]): a live
/// confined launch with one credential route, and a loopback TLS destination outside it.
///
/// `restricted` puts an endpoint rule set on the route, allowing [`ALLOWED_METHOD`] on
/// [`PROXIED_PATH`] and nothing else.
///
/// The outside half is the same request made directly, which must succeed: a destination that is
/// down, or one this host cannot verify, is a setup failure and not a boundary regression. What it
/// recorded of that is then forgotten, so the inside half's record is the inside half's alone.
///
/// [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows
fn credential_route(row: &Row, restricted: bool) -> Verdict {
    let Action::Request(legs) = row.action else {
        return Verdict::Setup(format!("{:?} issues no request", row.action));
    };
    let destination = match destination() {
        Ok(destination) => destination,
        Err(why) => return Verdict::Setup(why),
    };
    let (method, path) = match restricted {
        true => (DENIED_METHOD, PROXIED_PATH),
        false => ("GET", PROXIED_PATH),
    };
    let fixture = common::Fixture::with_mode("read");
    let root = match destination.root_in(&fixture) {
        Ok(root) => root,
        Err(why) => return Verdict::Setup(why),
    };
    let endpoints = match restricted {
        true => serde_json::json!(["suite-restricted"]),
        false => serde_json::json!([]),
    };
    let policy = fixture.policy_named(
        "credential-route.json",
        &serde_json::json!({
            "version": 1,
            // Answers at once, and its stdin is drained: a minter is handed the scope on stdin.
            "minters": {"m": {"command": [
                common::os_bin("sh"), "-c",
                format!(
                    r#"cat >/dev/null; printf '{{"token":"{ROUTE_SECRET}","expires_at":"2099-01-01T00:00:00Z"}}'"#
                ),
            ]}},
            "fragments": {"endpoints": {
                "suite-restricted": [{"method": ALLOWED_METHOD, "path": PROXIED_PATH}],
            }},
            "workspaces": {"w": {"roots": [{"path": fixture.root(), "mode": "read"}]}},
            "profiles": {"p": {
                "workspaces": ["w"],
                "toolchain": [],
                "credentials": [{
                    "host": "localhost",
                    "path_prefix": ROUTE_PREFIX,
                    "minter": "m",
                    "delivery": {"env": ROUTE_DELIVERY},
                    "endpoints": endpoints,
                }],
            }},
        }),
    );

    // Outside: the same request, direct, with the destination's root as this process's only trust.
    // It must succeed, whatever the row asserts inside.
    let outside_op = request_op(&destination, Via::Direct, "localhost", method, path);
    let mut outside = Command::new(PROBE);
    outside
        .args(["request", &outside_op])
        // Outside there is no run and so no phantom. The destination answers whatever it is sent,
        // so this half shows only that it is up and verifiable, which is what it is for.
        .env(ROUTE_DELIVERY, "not-a-token")
        .stdin(Stdio::null());
    let outside = trusting_only(&mut outside, &root)
        .output()
        .expect("run the probe");
    let outside = match exchanged(&outside) {
        Ok(answers) => match answers.first() {
            Some(Ok(answer)) if answer.starts_with("HTTP/1.1 200 ") => Seen::Succeeded,
            Some(Ok(answer)) => Seen::Failed {
                cause: None,
                detail: format!("the destination answered {answer:?}"),
            },
            Some(Err(why)) => Seen::Failed {
                cause: None,
                detail: why.clone(),
            },
            None => Seen::Failed {
                cause: None,
                detail: "the probe made no request".into(),
            },
        },
        Err(why) => return Verdict::Setup(format!("outside: {why}")),
    };
    destination.forget();

    // Inside: the legs the row drives, in one confined launch. `SSL_CERT_FILE` is set on **this
    // launch** and never on the suite, and it *replaces* the store rather than extending it, so a
    // broker trusting only this root cannot pass by having reached something else ([ADR 0030]).
    let mut ops = vec![request_op(
        &destination,
        Via::Proxy,
        "localhost",
        method,
        path,
    )];
    // The second leg of a pair, which the broker does not broker. `Bypassing` goes around the
    // proxy; `Tunnelled` goes through it to the name no route carries, so it opens an opaque
    // `CONNECT` and the destination's own certificate is what the child has to verify.
    let unbrokered_path = match legs {
        Legs::Proxied => None,
        Legs::ProxiedAndBypassing => {
            ops.push(request_op(
                &destination,
                Via::Direct,
                "localhost",
                "GET",
                BYPASSING_PATH,
            ));
            Some(BYPASSING_PATH)
        }
        Legs::ProxiedAndTunnelled => {
            ops.push(request_op(
                &destination,
                Via::Proxy,
                UNROUTED_HOST,
                "GET",
                TUNNELLED_PATH,
            ));
            Some(TUNNELLED_PATH)
        }
    };
    let probe = fixture.probe();
    let mut argv = vec![probe.to_str().expect("a UTF-8 probe path").to_owned()];
    for op in &ops {
        argv.push("request".to_owned());
        argv.push(op.clone());
    }
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let mut inside = fixture.run_under(&policy, &argv);
    inside.stdin(Stdio::null());
    let inside = trusting_only(&mut inside, &root)
        .output()
        .expect("run playpen");
    let answers = match exchanged(&inside) {
        Ok(answers) if answers.len() == ops.len() => answers,
        Ok(answers) => {
            return Verdict::Fail(format!(
                "the probe answered {} of {} requests: {answers:?}",
                answers.len(),
                ops.len()
            ));
        }
        Err(why) => return Verdict::Fail(format!("inside: {why}")),
    };
    // What arrived, matched to the leg that sent it by its own request line rather than by arrival
    // order: the two legs ask for two paths for exactly this.
    let received = destination.received();
    let arrived = |path: &str| {
        received
            .iter()
            .find(|head| head.contains(&format!(" {path} HTTP/1.1\r\n")))
            .cloned()
    };
    let seen = Exchanged {
        proxied: Exchange {
            answer: answers[0].clone(),
            arrived: arrived(PROXIED_PATH),
        },
        unbrokered: unbrokered_path.and_then(|path| {
            answers.get(1).map(|answer| Exchange {
                answer: answer.clone(),
                arrived: arrived(path),
            })
        }),
        detail: format!(
            "answers {answers:?}; the destination received {received:?}; playpen {}, stderr {:?}",
            inside.status,
            String::from_utf8_lossy(&inside.stderr)
        ),
    };
    judge_request(
        row.expected,
        Substitution {
            secret: ROUTE_SECRET,
            header: ROUTE_HEADER,
        },
        &outside,
        &seen,
    )
}

/// Which leg a request op takes, mirroring the probe's own argument.
#[derive(Clone, Copy)]
enum Via {
    Proxy,
    Direct,
}

impl Via {
    /// The spelling the probe's own `Via` deserializes.
    fn named(self) -> &'static str {
        match self {
            Via::Proxy => "proxy",
            Via::Direct => "direct",
        }
    }
}

/// One `request` operand for the probe: JSON, because a request takes more operands than a
/// positional list could be read back from.
///
/// `delivery` names the **variable**, never the value: no token belongs on a command line, where
/// the host's process table can read it.
fn request_op(destination: &Destination, via: Via, host: &str, method: &str, path: &str) -> String {
    request_json(
        via,
        &destination.authority(host),
        method,
        path,
        ROUTE_DELIVERY,
    )
}

/// As [`request_op`], for a caller that has the authority and the delivery variable already — the
/// manifest's route half reads both out of the manifest rather than from this fixture's constants.
fn request_json(via: Via, authority: &str, method: &str, path: &str, delivery: &str) -> String {
    serde_json::json!({
        "via": via.named(),
        "method": method,
        "authority": authority,
        "path": path,
        "header": ROUTE_HEADER,
        "delivery": delivery,
    })
    .to_string()
}

/// The answer each `request` verdict carried, in order. A probe that broke voids them all.
fn exchanged(output: &Output) -> Result<Vec<Result<String, String>>, String> {
    if !output.status.success() {
        return Err(format!(
            "the probe broke: {}, stderr {:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| {
            let verdict: Value =
                serde_json::from_str(line).map_err(|e| format!("verdict {line:?}: {e}"))?;
            // A malformed verdict is the harness's fault, never the boundary's: an answer
            // defaulted to empty would read as a destination that said nothing.
            match (verdict["ok"].as_bool(), verdict["answer"].as_str()) {
                (Some(true), Some(answer)) => Ok(Ok(answer.to_owned())),
                (Some(true), None) => Err(format!("verdict {line:?} carries no `answer`")),
                (Some(false), _) => Ok(Err(verdict["detail"].as_str().unwrap_or(line).to_owned())),
                (None, _) => Err(format!("verdict {line:?} has no `ok`")),
            }
        })
        .collect()
}

/// What a toolchain row made: the root its toolchain grants, a file under it, and the targets
/// beside it that the grant must not reach.
struct Beside {
    root: PathBuf,
    neighbour: PathBuf,
    targets: Vec<PathBuf>,
    /// Where the trees the store copied were built, removed with the row.
    _dir: Option<TempDir>,
}

/// Two store paths: a closure the toolchain grants, and beside it a stale `home-manager-files`
/// generation holding `.ssh/config`. Both are content-addressed copies of trees made here, so the
/// row never writes over anything of the host's, and the store collects them when unrooted.
fn store_paths() -> Result<Beside, String> {
    let dir = TempDir::new().map_err(|e| format!("store sources: {e}"))?;
    let tree = |name: &str, file: &str| -> Result<PathBuf, String> {
        let tree = dir.path().join(name);
        let path = tree.join(file);
        fs::create_dir_all(path.parent().expect("a parent")).map_err(|e| format!("{e}"))?;
        fs::write(&path, DECOY).map_err(|e| format!("{}: {e}", path.display()))?;
        let output = Command::new("nix-store")
            .arg("--add")
            .arg(&tree)
            .output()
            .map_err(|e| format!("nix-store --add: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "nix-store --add {}: {}",
                tree.display(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(PathBuf::from(
            String::from_utf8_lossy(&output.stdout).trim(),
        ))
    };
    let closure = tree("playpen-suite-closure", "granted")?;
    let stale = tree("home-manager-files", ".ssh/config")?;
    Ok(Beside {
        neighbour: closure.join("granted"),
        root: closure,
        targets: vec![stale.join(".ssh/config")],
        _dir: Some(dir),
    })
}

/// The keg a toolchain row grants, and the decoy keg beside it.
const KEGS: [&str; 2] = ["playpen-decoy-granted", "playpen-decoy-keg"];

/// Two manufactured kegs laid out as Homebrew lays out its own — `Cellar/<keg>/<version>`, with
/// `opt/<keg>` a relative link to it — each holding only its decoy marker. The toolchain grants
/// the first through its `opt` link, as a keg list does; the second's marker is the target.
fn kegs(made: &mut Made) -> Result<Beside, String> {
    let prefix = crate::row::homebrew_prefix().ok_or("no Homebrew prefix")?;
    let mut markers = Vec::new();
    for keg in KEGS {
        let link = prefix.join("opt").join(keg);
        let cellar = prefix.join("Cellar").join(keg);
        reclaim_keg(&link, &cellar, made)?;
        if link.symlink_metadata().is_ok() {
            return Err(format!("{} is the host's", link.display()));
        }
        decoy_dir_at(&cellar, made)?;
        decoy_dir_at(&cellar.join("0"), made)?;
        decoy_file(&cellar.join("0").join(DECOY_MARKER), made)?;
        std::os::unix::fs::symlink(Path::new("../Cellar").join(keg).join("0"), &link)
            .map_err(|e| format!("link {}: {e}", link.display()))?;
        made.0.push(link.clone());
        markers.push(link.join(DECOY_MARKER));
    }
    let root = prefix.join("opt").join(KEGS[0]);
    let decoy = markers.pop().expect("two kegs");
    Ok(Beside {
        root,
        neighbour: markers.pop().expect("two kegs"),
        targets: vec![decoy],
        _dir: None,
    })
}

/// Remove a manufactured keg a killed run left behind: the `opt` link only when it points at
/// exactly the keg's decoy version, and the cellar only as far as it holds nothing but decoys.
fn reclaim_keg(link: &Path, cellar: &Path, made: &Made) -> Result<(), String> {
    let ours = link
        .file_name()
        .map(|keg| Path::new("../Cellar").join(keg).join("0"));
    if fs::read_link(link).ok() == ours && ours.is_some() && !made.0.iter().any(|p| p == link) {
        fs::remove_file(link).map_err(|e| format!("reclaim {}: {e}", link.display()))?;
    }
    reclaim_dir(&cellar.join("0"), Some(DECOY_MARKER), made)?;
    reclaim_dir(cellar, None, made)
}

fn descendant_denied(row: &Row) -> Verdict {
    match row.action {
        Action::PullDenials => match pull_denials() {
            Ok((outside, inside)) => judge(row.expected, &outside, &inside),
            Err(why) => Verdict::Setup(why),
        },
        action => Verdict::Setup(format!(
            "{action:?} does not pull denials, and this fixture only makes them"
        )),
    }
}

/// How long the platform's log may take to show a denial before the row is a setup failure: a
/// log that slow says nothing about the command, and the row must end rather than hang.
#[cfg(target_os = "macos")]
const LOG_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// How far back the outside half looks for the decoy's denial, as `log show --last` takes it. Its
/// own reach, never the window `explain` printed: a window cut too narrow is the command's defect
/// and must fail the row, where a window shared with the outside half reads as a host that never
/// logged the denial ([#142](https://github.com/firefly-engineering/playpen/issues/142)). The
/// decoy's path is unique to this run, so reaching back further admits nothing else.
#[cfg(target_os = "macos")]
const LOG_LOOKBACK: &str = "5m";

/// A confined shell forks the probe, which is denied a read of a decoy outside every grant. The
/// outside half is the platform's log showing that denial at all, found by the decoy's path over
/// [`LOG_LOOKBACK`]; the inside half is the command `explain --run` prints returning it, from a
/// process that is not the child ([#124](https://github.com/firefly-engineering/playpen/issues/124)).
/// An error is a fixture that could not be made, before either half could be observed.
#[cfg(target_os = "macos")]
fn pull_denials() -> Result<(Seen, Seen), String> {
    let failed = |detail: String| Seen::Failed {
        cause: None,
        detail,
    };
    let decoy = NamedTempFile::new()
        .and_then(|mut decoy| {
            std::io::Write::write_all(&mut decoy, DECOY.as_bytes())?;
            Ok(decoy)
        })
        .map_err(|e| format!("decoy: {e}"))?;
    // Logged as the kernel resolved it, through macOS's `/var` link.
    let path = decoy
        .path()
        .canonicalize()
        .map_err(|e| format!("the decoy's path: {e}"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("the decoy's name: {path:?}"))?
        .to_owned();
    let path = utf8(&path)?;
    let denied = format!("deny(1) file-read-data {path}");

    let fixture = common::Fixture::with_mode("read");
    let probe = fixture.probe();
    // `; true` keeps the shell from replacing itself with the probe, so the probe is forked.
    let script = format!("'{}' read '{path}'; true", probe.display());
    // The shell's `; true` makes any other exit playpen's own: a launch that never ran the probe
    // denied nothing, and the log would be polled for a denial that cannot come.
    let ran = fixture
        .run(&[&common::os_bin("sh"), "-c", &script])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("run playpen: {e}"))
        .and_then(|ran| succeeded(ran, "playpen running the probe"))?;
    let run = fixture
        .run_ids()
        .pop()
        .ok_or_else(|| format!("no record: {ran:?}"))?;
    let replay = fixture
        .playpen(&["explain", "--run", &run, "--json"])
        .output()
        .map_err(|e| format!("run playpen explain: {e}"))?;
    let replay: Value =
        serde_json::from_slice(&replay.stdout).map_err(|e| format!("explain --json: {e}"))?;
    let (Some(command), Some(child)) = (replay["denials"].as_str(), replay["pid"].as_i64()) else {
        return Err(format!("no denials command or pid: {replay}"));
    };

    // Outside: found by the decoy's path over the harness's own reach, nothing the run set.
    let sandbox = |needle: &str| {
        format!(
            "/usr/bin/log show --last {LOG_LOOKBACK} --predicate 'sender == \"Sandbox\" AND \
             eventMessage CONTAINS \"{needle}\"'"
        )
    };
    let by_path = sandbox(&path);
    let deadline = std::time::Instant::now() + LOG_DEADLINE;
    loop {
        // A `log show` that fails is polled again, not taken as the answer: the deadline decides.
        let shown = shell(&by_path, SHELL_DEADLINE)?;
        if shown.as_ref().is_ok_and(|shown| shown.contains(&denied)) {
            break;
        }
        if std::time::Instant::now() > deadline {
            // What the probe itself reported tells a read that was never denied from a denial
            // never logged; the decoy's name alone tells one logged under another path or
            // operation from none.
            let by_name = sandbox(&name);
            let never = format!(
                "the log never showed `{denied}` within {LOG_DEADLINE:?}; the probe reported \
                 {:?}; `{by_path}` last showed {shown:?}; `{by_name}` shows {:?}",
                String::from_utf8_lossy(&ran.stdout).trim_end(),
                shell(&by_name, SHELL_DEADLINE)?
            );
            return Ok((failed(never), failed(String::new())));
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Inside: the command as printed, and the line it returns is a descendant's. A command that
    // fails is the command `explain` printed failing, which is the row's to fail, not the fixture's.
    let inside = match shell(command, SHELL_DEADLINE)? {
        Err(why) => failed(why),
        Ok(pulled) => match pulled.lines().find(|line| line.contains(&denied)) {
            Some(line) if !line.contains(&format!("({child})")) => Seen::Succeeded,
            Some(line) => failed(format!(
                "the denial is the child's own, not a descendant's: {line}"
            )),
            None => failed(format!("`{command}` does not return `{denied}`")),
        },
    };
    Ok((Seen::Succeeded, inside))
}

/// The row is `n/a` on Linux, which has no log tag to pull by yet
/// ([#98](https://github.com/firefly-engineering/playpen/issues/98)).
#[cfg(target_os = "linux")]
fn pull_denials() -> Result<(Seen, Seen), String> {
    unreachable!("P-denial-tree is n/a on Linux")
}

/// How long one command `P-denial-tree` runs may take before it is taken as wedged. Each call's
/// own bound: [`LOG_DEADLINE`] bounds the polling between calls, not a call that never returns.
/// No longer than it, so one wedged call cannot outlast the row's whole budget.
pub const SHELL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// `command`'s stdout, run by the shell as a user pasting it would. A command that fails is an
/// inner error carrying its stderr, never the empty output it happened to print. One still running
/// after `deadline` is killed with its whole tree, and is an outer error naming it: a wedged `log`
/// says nothing about the row, and must end it as a setup failure rather than hang the suite
/// ([#147](https://github.com/firefly-engineering/playpen/issues/147)).
pub fn shell(
    command: &str,
    deadline: std::time::Duration,
) -> Result<Result<String, String>, String> {
    let mut shell = Command::new(common::os_bin("sh"));
    shell.args(["-c", command]);
    let what = format!("`{command}`");
    let output = within(shell, &what, deadline)?;
    Ok(succeeded(output, &what).map(|output| String::from_utf8_lossy(&output.stdout).into_owned()))
}

/// `command`'s output, with stdin closed. One still running after `deadline` is killed with its
/// whole tree, and is an error naming it as `what`.
pub fn within(
    mut command: Command,
    what: &str,
    deadline: std::time::Duration,
) -> Result<Output, String> {
    // Files rather than pipes: a pipe must be drained while the child runs, which takes a thread,
    // and this suite stays single-threaded.
    let capture = |e: std::io::Error| format!("capture {what}: {e}");
    let (mut stdout, mut stderr) = (
        tempfile::tempfile().map_err(capture)?,
        tempfile::tempfile().map_err(capture)?,
    );
    // A group of its own, so the kill reaches whatever it forked.
    let mut child = command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone().map_err(capture)?)
        .stderr(stderr.try_clone().map_err(capture)?)
        .process_group(0)
        .spawn()
        .map_err(|e| format!("run {what}: {e}"))?;
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("wait on {what}: {e}"))?
        {
            break status;
        }
        if started.elapsed() > deadline {
            // SAFETY: the group is the child's own, made by `process_group(0)` above.
            unsafe { libc::killpg(child.id() as libc::pid_t, libc::SIGKILL) };
            let _ = child.wait();
            return Err(format!(
                "{what} was still running after {deadline:?}, and was killed"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let read = |file: &mut File| -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        std::io::Seek::rewind(file)
            .and_then(|()| file.read_to_end(&mut bytes))
            .map_err(|e| format!("read {what}'s output: {e}"))?;
        Ok(bytes)
    };
    Ok(Output {
        status,
        stdout: read(&mut stdout)?,
        stderr: read(&mut stderr)?,
    })
}

/// `output`, if `what` exited successfully; otherwise an error naming its status and stderr.
fn succeeded(output: Output, what: &str) -> Result<Output, String> {
    if output.status.success() {
        return Ok(output);
    }
    Err(format!(
        "{what} failed, {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim_end()
    ))
}

/// A refusal row, under a fixture of its own so its state directory holds this run alone.
fn refusal(row: &Row) -> Verdict {
    match row.action {
        Action::Refuse(invocation) => judge_refusal(row.expected, &decline(invocation)),
        Action::CheckDocument => judge_unexamined(row.expected, &check_document()),
        Action::TraceBrackets => judge_bracket(row.expected, &bracketed()),
        // Over the whole table, whichever rows this run was handed.
        Action::CoverCodes => {
            judge_coverage(row.expected, crate::rows::ROWS, crate::row::UNPROVOKED)
        }
        action => Verdict::Setup(format!(
            "{action:?} runs under a boundary, and a refusal has none"
        )),
    }
}

/// The first argument that makes the suite run as playpen on a mechanism that offers nothing
/// ([`as_playpen_offering_nothing`]). The second stands in for `XDG_STATE_HOME`.
pub const AS_PLAYPEN_OFFERING_NOTHING: &str = "--as-playpen-offering-nothing";

/// The first argument that makes the suite run as playpen with the denial trace's ladder reading
/// facts of the row's choosing ([`as_playpen_tracing`]). The second names the [`Rung`] that
/// fails, the third stands in for `XDG_STATE_HOME`.
pub const AS_PLAYPEN_TRACING: &str = "--as-playpen-tracing";

/// The suite, re-run as playpen with the **real** denial-trace ladder reading the facts `rung`
/// describes ([spec §14.5]). Everything else is what `src/main.rs` does.
///
/// Only the facts are replaced, never the ladder: its order, its codes and its sentences are the
/// shipped ones, and a host with all four preconditions could provoke none of them otherwise.
///
/// [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials
#[cfg(target_os = "linux")]
pub fn as_playpen_tracing(
    mut args: impl Iterator<Item = OsString>,
    cwd: std::io::Result<PathBuf>,
) -> i32 {
    let named = args.next().expect("the rung the ladder fails at");
    let named = named.to_str().expect("a UTF-8 rung");
    // `NO_RUNG` is the other half of the bracketing pair: every precondition holds, both passes
    // of the self-test deliver, and the trace is vouched for.
    let rung = match named {
        NO_RUNG => None,
        named => Some(Rung::parse(named).expect("a rung of the ladder")),
    };
    let state = playpen::record::state_dir(args.next(), None);
    let argv = std::iter::once(OsString::from("playpen")).chain(args);
    let host = playpen::launch::Host {
        cwd,
        policies: playpen::policy::SearchPath::of(Vec::new()),
        state,
        profile: None,
        executable: std::env::current_exe(),
        env: Vec::new(),
        floor: crate::common::dedicated_floor(),
    };
    playpen::launch::main(
        argv,
        host,
        playpen::mechanism::Mechanism::probe,
        move |file, workspace, _| playpen::trace::open_with(facts(rung), file, workspace),
    )
}

/// The facts the ladder reads for `rung`: everything above it holds, and this one does not.
///
/// A delivering channel is spelled with an empty domain, which a record carrying no `domain=`
/// field would also give: what the self-test is asked is whether the channel delivers, and the
/// domain is only what keeps its own denial out of the run's trace.
#[cfg(target_os = "linux")]
fn facts(rung: Option<Rung>) -> playpen::trace::Facts {
    use playpen::trace::{Channel, Facts};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let delivers = || Channel::Delivers {
        domain: String::new(),
    };
    let mut facts = Facts {
        abi: Ok(playpen::trace::LOGGING_ABI),
        backend_logs: true,
        readable: Box::new(|| Ok(())),
        self_test: std::sync::Arc::new(move |_| delivers()),
    };
    match rung {
        None => {}
        Some(Rung::KernelAbi) => facts.abi = Ok(playpen::trace::LOGGING_ABI - 1),
        Some(Rung::LandlockInactive) => facts.abi = Err(libc::EOPNOTSUPP),
        Some(Rung::BackendNoLogging) => facts.backend_logs = false,
        Some(Rung::NoJournalAccess) => {
            facts.readable = Box::new(|| Err("no journal files were opened".to_string()));
        }
        Some(Rung::ChannelSilent) => facts.self_test = std::sync::Arc::new(|_| Channel::Silent),
        Some(Rung::ChannelLossy) => facts.self_test = std::sync::Arc::new(|_| Channel::Lossy),
        // The channel delivers on the pass that opens the trace and is silent on the pass that
        // brackets it, which is the flood that made journald drop its audit input mid-run.
        Some(Rung::SilentAfterTheRun) => {
            let passes = AtomicUsize::new(0);
            facts.self_test =
                std::sync::Arc::new(move |_| match passes.fetch_add(1, Ordering::Relaxed) {
                    0 => delivers(),
                    _ => Channel::Silent,
                });
        }
    }
    facts
}

/// The rung name that fails nothing: the vouched half of [`Bracketed`].
pub const NO_RUNG: &str = "none";

/// The suite, re-run by [`decline`], as playpen: what `src/main.rs` does, with the state directory
/// from `args` rather than the environment, and the mechanism probe replaced by one that offers
/// nothing. Returns the status to exit with.
pub fn as_playpen_offering_nothing(
    mut args: impl Iterator<Item = OsString>,
    cwd: std::io::Result<PathBuf>,
) -> i32 {
    let state = playpen::record::state_dir(args.next(), None);
    let argv = std::iter::once(OsString::from("playpen")).chain(args);
    // The row always names its policy, so no location of the host's own is ever searched.
    let host = playpen::launch::Host {
        cwd,
        state,
        policies: playpen::policy::SearchPath::of(Vec::new()),
        profile: None,
        executable: std::env::current_exe(),
        env: Vec::new(),
        floor: crate::common::dedicated_floor(),
    };
    playpen::launch::main(
        argv,
        host,
        || Mechanism::new("a mechanism offering nothing", &[]),
        // This row refuses at step 7's first check, so the trace's seam is never reached.
        |_, _, _| panic!("no flag asked for a trace"),
    )
}

/// Invoke playpen as `invocation` says, with the fixture's own state directory handed to it,
/// and read back the record its refusal line names.
fn decline(invocation: Invocation) -> Declined {
    let fixture = common::Fixture::with_mode("read");
    // Where this invocation's records land. Usually the fixture's own state directory, but a row
    // may move it, which is the whole point of `StateReachable`.
    let mut runs = fixture.runs();
    // What an invocation made that must outlive playpen's run.
    let mut held: Vec<TempDir> = Vec::new();
    // A run of the suite's own holding what this one is refused for, let go once it is.
    let mut holder = None;
    let mut command = match invocation {
        Invocation::Usage => fixture.playpen(&["run"]),
        Invocation::MissingCapability => {
            let suite = std::env::current_exe().expect("the suite's own executable");
            let mut command = Command::new(suite);
            command
                .arg(AS_PLAYPEN_OFFERING_NOTHING)
                .arg(fixture.state_home())
                .args(["run", "--profile", "p", "--agent", "claude", "--policy"])
                .arg(&fixture.policy)
                .args([OsStr::new("--"), canary().as_os_str()])
                .current_dir(fixture.root());
            command
        }
        Invocation::Policy(document) => {
            let policy = fixture.policy_dir.path().join("policy.yaml");
            fs::write(&policy, substituted(document, &fixture)).expect("write policy");
            fixture.run_under(&policy, &[canary().to_str().expect("utf-8 path")])
        }
        Invocation::WritablePolicy => {
            let policy = fixture.root().join("policy.json");
            let document = serde_json::json!({
                "version": 1,
                "workspaces": {"w": {"roots": [{"path": fixture.root(), "mode": "readwrite"}]}},
                "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
            });
            fs::write(&policy, document.to_string()).expect("write policy");
            let mut command =
                fixture.playpen(&["run", "--profile", "p", "--agent", "claude", "--policy"]);
            command.arg(&policy).arg("--").arg(canary());
            command
        }
        Invocation::OverCeiling => {
            let tools = TempDir::new().expect("toolchain roots");
            let toolchain: Vec<Value> = (0..OVER_CEILING)
                .map(|i| {
                    let root = tools.path().join(over_ceiling_name(i));
                    fs::create_dir(&root).expect("toolchain root");
                    serde_json::json!({"path": root})
                })
                .collect();
            held.push(tools);
            let policy = fixture.policy_dir.path().join("over-ceiling.json");
            let document = serde_json::json!({
                "version": 1,
                "workspaces": {"w": {"roots": [{"path": fixture.root(), "mode": "read"}]}},
                "profiles": {"p": {"workspaces": ["w"], "toolchain": toolchain}},
            });
            fs::write(&policy, document.to_string()).expect("write policy");
            let mut command =
                fixture.playpen(&["run", "--profile", "p", "--agent", "claude", "--policy"]);
            command.arg(&policy).arg("--").arg(canary());
            command
        }
        // The real ladder, reading facts no host would present ([spec §14.5]).
        #[cfg(target_os = "linux")]
        Invocation::TraceDenials(rung) => {
            let trace = fixture.policy_dir.path().join("denials.trace");
            as_playpen_tracing_command(&fixture, rung.name(), &trace)
        }
        #[cfg(not(target_os = "linux"))]
        Invocation::TraceDenials(_) => {
            // A row carrying this is scoped to Linux, so it is `n/a` elsewhere and never gets
            // here; the arm exists so the match is exhaustive on either platform.
            fixture.playpen(&["run"])
        }
        Invocation::StateReachable => {
            let inside = fixture.root().join("state");
            runs = inside.join("playpen/runs");
            let mut command = fixture.run(&[canary().to_str().expect("utf-8 path")]);
            command.env("XDG_STATE_HOME", &inside);
            command
        }
        Invocation::Locate(location) => {
            let named = |policy: &Path| {
                let mut command =
                    fixture.playpen(&["run", "--profile", "p", "--agent", "claude", "--policy"]);
                command.arg(policy).arg("--").arg(canary());
                command
            };
            match location {
                Location::Absent => named(&fixture.policy_dir.path().join("absent.yaml")),
                Location::Directory => named(fixture.policy_dir.path()),
                Location::BothFormats => {
                    let config = TempDir::new().expect("config home");
                    let at = config.path().join("playpen");
                    fs::create_dir(&at).expect("policy location");
                    let document = fs::read(&fixture.policy).expect("the fixture's policy");
                    for name in ["policy.yaml", "policy.json"] {
                        fs::write(at.join(name), &document).expect("write policy");
                    }
                    let mut command =
                        fixture.playpen(&["run", "--profile", "p", "--agent", "claude"]);
                    command
                        .arg("--")
                        .arg(canary())
                        .env("XDG_CONFIG_HOME", config.path());
                    held.push(config);
                    command
                }
            }
        }
        Invocation::Shim(document) => {
            let (command, installed) = shim(&substituted(document, &fixture), &fixture);
            held.extend(installed);
            command
        }
        Invocation::UnfoundLink => {
            let document = format!(
                "version: 1\n\
                 workspaces:\n  w: {{ roots: [{{ path: \"{ROOT}\", mode: read }}] }}\n\
                 profiles:\n  p: {{ workspaces: [w], toolchain: [] }}\n\
                 shims:\n  {SHIM}: {{ target: \"{CANARY}\", kind: claude, profile: p }}\n"
            );
            let (mut command, installed) = shim(&substituted(&document, &fixture), &fixture);
            held.extend(installed);
            // A `PATH` lookup leaves the bare name; this `PATH` holds no entry leading to it.
            command.arg0(SHIM).env("PATH", fixture.policy_dir.path());
            command
        }
        Invocation::CwdOutside => fixture.run_from(
            fixture.policy_dir.path(),
            &[canary().to_str().expect("utf-8 path")],
        ),
        Invocation::AbsentTarget => {
            let absent = fixture.root().join("absent");
            fixture.run(&[absent.to_str().expect("utf-8 path")])
        }
        Invocation::HeldArea => {
            let policy = fixture.policy_dir.path().join("held.json");
            let document = serde_json::json!({
                "version": 1,
                "workspaces": {"w": {
                    "roots": [{"path": fixture.root(), "mode": "read"}],
                    // `exclusive` is the default.
                    "areas": {"landing": {"lifetime": "persistent"}},
                }},
                "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
            });
            fs::write(&policy, document.to_string()).expect("write policy");
            holder = Some(hold(&fixture, &policy));
            fixture.run_under(&policy, &[canary().to_str().expect("utf-8 path")])
        }
        Invocation::ScratchBlocked => {
            let state = fixture.state_home().join("playpen");
            fs::create_dir_all(&state).expect("state directory");
            fs::write(state.join("scratch"), "").expect("a file where the scratch goes");
            fixture.run(&[canary().to_str().expect("utf-8 path")])
        }
        Invocation::NoProcesses => {
            let mut command = fixture.run(&[canary().to_str().expect("utf-8 path")]);
            // SAFETY: setrlimit is async-signal-safe, and touches nothing of the parent's.
            unsafe {
                command.pre_exec(|| {
                    let none = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    match libc::setrlimit(libc::RLIMIT_NPROC, &none) {
                        0 => Ok(()),
                        _ => Err(std::io::Error::last_os_error()),
                    }
                })
            };
            command
        }
        Invocation::Floor(state) => {
            let floor = TempDir::new().expect("dedicated floor");
            if state == DedicatedFloor::CanaryUnrunnable {
                let bin = floor.path().join("bin");
                fs::create_dir(&bin).expect("the floor's bin");
                fs::write(
                    floor.path().join("closure"),
                    format!("{}\n", floor.path().display()),
                )
                .expect("the floor's closure");
                // Not executable, so its `exec` fails however the floor is applied.
                fs::write(bin.join("true"), "").expect("the floor's canary");
            }
            let mut command = fixture.run(&[canary().to_str().expect("utf-8 path")]);
            command.env(playpen::floor::FLOOR_ENV, floor.path());
            held.push(floor);
            command
        }
        Invocation::NoTrustedRoots => {
            let policy = fixture.policy_dir.path().join("policy.yaml");
            fs::write(&policy, substituted(MINTED, &fixture)).expect("write policy");
            let store = fixture.policy_dir.path().join("empty.pem");
            fs::write(&store, "").expect("an empty trust store");
            let mut command = fixture.run_under(&policy, &[canary().to_str().expect("utf-8 path")]);
            // Replaced rather than extended, and the other variable that would extend it gone.
            command
                .env("SSL_CERT_FILE", &store)
                .env_remove("SSL_CERT_DIR");
            command
        }
        Invocation::UnknownRun => {
            // Well formed, so it is the ring that does not hold it rather than the id that fails
            // to parse.
            fixture.playpen(&["explain", "--run", "01ARZ3NDEKTSV4RRFFQ69G5FAV"])
        }
    };
    let output = command.stdin(Stdio::null()).output().expect("run playpen");
    let released = holder.map(release);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let text = match stderr.lines().collect::<Vec<_>>().as_slice() {
        [line] => (*line).to_owned(),
        _ => String::new(),
    };
    let line = refusal_line(&text);
    let recorded = line.as_ref().and_then(|(_, run)| {
        let bytes = fs::read(runs.join(format!("{}.json", run.as_ref()?))).ok()?;
        // A record that does not parse as one is no record.
        let record: Record = serde_json::from_slice(&bytes).ok()?;
        Some(record.refusal.map(|refusal| refusal.code))
    });
    let ring = fs::read_dir(&runs)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .count();
    drop(held);
    Declined {
        status: output.status.code(),
        line,
        text,
        recorded,
        ring,
        detail: match released {
            Some(holder) => format!("{}, stderr {stderr:?}; {holder}", output.status),
            None => format!("{}, stderr {stderr:?}", output.status),
        },
    }
}

/// `document` with [`ROOT`], [`SH`] and [`CANARY`] replaced by what they name for `fixture`.
fn substituted(document: &str, fixture: &common::Fixture) -> String {
    document
        .replace(ROOT, fixture.root().to_str().expect("utf-8 path"))
        .replace(SH, &common::os_bin("sh"))
        .replace(CANARY, canary().to_str().expect("utf-8 path"))
}

/// The policy [`Invocation::NoTrustedRoots`] runs under: one profile route, whose minter answers.
const MINTED: &str = "\
version: 1
minters:
  m: { command: [\"{sh}\", -c, 'printf \"{\\\"token\\\":\\\"t\\\",\\\"expires_at\\\":\\\"2099-01-01T00:00:00Z\\\"}\"'] }
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p:
    workspaces: [w]
    toolchain: []
    credentials:
      - { host: api.example, path_prefix: /, minter: m, delivery: { env: PLAYPEN_SUITE_TOKEN } }
";

/// playpen installed as the shim [`SHIM`]: a link to the binary in a directory of its own, and a
/// home whose search-path location holds `document`. The command invokes the link by its path
/// from inside `fixture`'s root, under its state directory, with the chain left to the working
/// directory. Returns it with the directories it needs kept.
fn shim(document: &str, fixture: &common::Fixture) -> (Command, [TempDir; 2]) {
    let links = TempDir::new().expect("link directory");
    let link = links.path().join(SHIM);
    std::os::unix::fs::symlink(common::PLAYPEN, &link).expect("shim link");
    let home = TempDir::new().expect("home");
    let location = home.path().join(".config/playpen");
    fs::create_dir_all(&location).expect("policy location");
    fs::write(location.join("policy.yaml"), document).expect("write policy");
    let mut command = Command::new(&link);
    command
        .current_dir(fixture.root())
        .env_remove("XDG_CONFIG_HOME")
        .env_remove(playpen::select::ENV)
        .env("XDG_STATE_HOME", fixture.state_home())
        .env("HOME", home.path());
    (command, [links, home])
}

/// How long the run [`hold`] starts may take to claim what it holds.
const HOLD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// A run of the canary's shell under `policy`, waiting on its stdin, once it holds its capability
/// set: the claim is made before that, so whatever the policy makes exclusive is held. A run that
/// never gets there is returned all the same, and the refusal it was meant to provoke is then
/// whatever the second launch meets instead.
fn hold(fixture: &common::Fixture, policy: &Path) -> std::process::Child {
    let before = fixture.run_ids();
    // `read` fails at end of file, which is how the hold is let go.
    let child = fixture
        .run_under(policy, &[&common::os_bin("sh"), "-c", "read _ || :"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the holding run");
    let started = std::time::Instant::now();
    while started.elapsed() < HOLD_DEADLINE {
        let launched = fixture
            .run_ids()
            .into_iter()
            .filter(|id| !before.contains(id))
            .any(|id| {
                fs::read(fixture.runs().join(format!("{id}.json")))
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                    .is_some_and(|record| record["capabilities"].is_object())
            });
        if launched {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    child
}

/// Let the run [`hold`] started go, and say how it ended.
fn release(mut holder: std::process::Child) -> String {
    drop(holder.stdin.take());
    match holder.wait_with_output() {
        Ok(output) => format!(
            "the holding run {}, stderr {:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(e) => format!("the holding run could not be waited for: {e}"),
    }
}

/// The suite, re-run as playpen with `--trace-denials <trace>` and the ladder reading `rung`'s
/// facts. `fixture` owns the policy and the state directory, so the run's record is where
/// [`decline`] and [`traced`] look for it.
fn as_playpen_tracing_command(fixture: &common::Fixture, rung: &str, trace: &Path) -> Command {
    let suite = std::env::current_exe().expect("the suite's own executable");
    let mut command = Command::new(suite);
    command
        .arg(AS_PLAYPEN_TRACING)
        .arg(rung)
        .arg(fixture.state_home())
        .args([
            "run",
            "--profile",
            "p",
            "--agent",
            "claude",
            "--trace-denials",
        ])
        .arg(trace)
        .arg("--policy")
        .arg(&fixture.policy)
        .args([OsStr::new("--"), canary().as_os_str()])
        .current_dir(fixture.root());
    command
}

/// Both halves of the bracketing assertion, each a traced launch of the canary: one whose channel
/// self-test delivers on both passes, and one that is silent on the second ([spec §14.5]).
///
/// [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials
fn bracketed() -> Bracketed {
    Bracketed {
        vouched: traced(NO_RUNG),
        silenced: traced(Rung::SilentAfterTheRun.name()),
    }
}

/// One traced launch, and what it left in its record and in its trace file.
fn traced(rung: &str) -> Traced {
    let fixture = common::Fixture::with_mode("read");
    let trace = fixture.policy_dir.path().join("denials.trace");
    let output = as_playpen_tracing_command(&fixture, rung, &trace)
        .stdin(Stdio::null())
        .output()
        .expect("run playpen");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The record is the run's own, found by the one record the fixture's ring holds: this
    // launch does not refuse, so there is no refusal line naming its id.
    let record = fs::read_dir(fixture.runs())
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .find_map(|path| {
            let bytes = fs::read(&path).ok()?;
            serde_json::from_slice::<Record>(&bytes).ok()
        });
    let written = fs::read_to_string(&trace).unwrap_or_default();
    Traced {
        status: output.status.code(),
        traced: record
            .as_ref()
            .is_some_and(|record| record.denial_trace.is_some()),
        unverified: record
            .as_ref()
            .and_then(|record| record.denial_trace_unverified.clone()),
        // The operator may never read the record, so the file says it too.
        file_says_unverified: written.contains("# playpen: unverified:"),
        detail: format!("{}, stderr {stderr:?}, trace {written:?}", output.status),
    }
}

/// The code and run id of a refusal line `playpen: <code>: <sentence> — run <id>` ([spec §14.3]).
///
/// [spec §14.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#143-the-refusal-line
/// `playpen check` of a policy whose one root is absent, with the filesystem and without it.
fn check_document() -> Checked {
    let fixture = common::Fixture::with_mode("read");
    let absent = fixture.root().join("absent");
    let policy = fixture.policy_dir.path().join("absent-root.json");
    let document = serde_json::json!({
        "version": 1,
        "workspaces": {"w": {"roots": [{"path": absent, "mode": "read"}]}},
        "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
    });
    fs::write(&policy, document.to_string()).expect("write policy");
    let check = |extra: &[&str]| {
        let mut command = fixture.playpen(&["check", "--policy"]);
        command.arg(&policy).args(extra).stdin(Stdio::null());
        command.output().expect("run playpen check")
    };
    let examined = check(&[]);
    let unexamined = check(&["--no-filesystem"]);
    let stderr = String::from_utf8_lossy(&examined.stderr);
    let code = match stderr.lines().collect::<Vec<_>>().as_slice() {
        [line] => line
            .strip_prefix("playpen: ")
            .and_then(|rest| rest.split_once(": "))
            .map(|(code, _)| code.to_owned()),
        _ => None,
    };
    Checked {
        examined: code.filter(|_| examined.status.code() == Some(EXIT_REFUSED)),
        unexamined_silent_success: unexamined.status.success()
            && unexamined.stdout.is_empty()
            && unexamined.stderr.is_empty(),
        detail: format!(
            "with the filesystem {}, stderr {stderr:?}; without it {}, stderr {:?}",
            examined.status,
            unexamined.status,
            String::from_utf8_lossy(&unexamined.stderr)
        ),
    }
}

fn refusal_line(line: &str) -> Option<(String, Option<String>)> {
    let (code, _) = line.strip_prefix("playpen: ")?.split_once(": ")?;
    let run = line.rsplit_once(" — run ").map(|(_, run)| run.to_owned());
    Some((code.to_owned(), run))
}

fn canary_outside() -> Seen {
    let canary = canary();
    let named = canary.display();
    let status = Command::new(&canary)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(status) if status.success() => Seen::Succeeded,
        Ok(status) => Seen::Failed {
            cause: None,
            detail: format!("{named}: {status}"),
        },
        Err(err) => Seen::Failed {
            cause: err.raw_os_error().map(Cause::Errno),
            detail: format!("{named}: {err}"),
        },
    }
}

/// The floor self-test, called as the launch calls it: one implementation, two callers.
fn canary_inside() -> Seen {
    // A fault is a defect, never a verdict on the floor, so it fails the suite outright.
    match self_test::floor(
        crate::common::dedicated_floor().as_deref(),
        |fault, canary| panic!("the floor self-test faulted on canary {canary}: {fault}"),
    ) {
        Ok(()) => Seen::Succeeded,
        Err(refusal) => Seen::Failed {
            cause: None,
            detail: refusal.to_string(),
        },
    }
}

/// The canary `exec`ed under an empty capability set, by a throwaway child the suite forks
/// itself. Not through the self-test, which reports a failed `exec` as playpen's refusal: this
/// row is judged by the kernel's errno ([ADR 0029]).
///
/// Must be called on the process's only thread: the child allocates between `fork` and `exec`.
///
/// [ADR 0029]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0029-the-backend-grants-only-what-the-policy-asked-for.md
fn canary_ungranted() -> Seen {
    let canary = canary();
    let named = canary.display().to_string();
    let path = CString::new(canary.into_os_string().into_vec()).expect("no NUL in a path");
    // Close-on-exec, so an `exec` that succeeds closes the child's end with nothing on it.
    let (mut report, reporter) = std::io::pipe().expect("the report pipe");
    // SAFETY: plain fork; the child only applies the backend and `exec`s, never returning.
    let pid = match unsafe { libc::fork() } {
        -1 => panic!("fork: {}", std::io::Error::last_os_error()),
        0 => exec_ungranted(&path, reporter),
        pid => pid,
    };
    drop(reporter);
    let mut said = Vec::new();
    // A pipe that fails mid-read is taken for what it delivered; the wait reports the rest.
    let _ = report.read_to_end(&mut said);
    let mut status = 0;
    // SAFETY: `status` is a valid out-pointer for the duration of the call.
    while unsafe { libc::waitpid(pid, &mut status, 0) } == -1 {
        let err = std::io::Error::last_os_error();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::Interrupted,
            "waitpid: {err}"
        );
    }
    match said.split_first() {
        Some((b'E', errno)) => {
            let errno = i32::from_le_bytes(errno.try_into().expect("an errno"));
            Seen::Failed {
                cause: Some(Cause::Errno(errno)),
                detail: format!("exec {named}: {}", std::io::Error::from_raw_os_error(errno)),
            }
        }
        Some((_, refused)) => Seen::Failed {
            cause: None,
            detail: format!(
                "the backend refused an empty capability set: {}",
                String::from_utf8_lossy(refused)
            ),
        },
        None if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 => Seen::Succeeded,
        None => Seen::Failed {
            cause: None,
            detail: format!("{named} ran, then ended with wait status {status:#x}"),
        },
    }
}

/// In the throwaway child: apply an empty capability set, `exec` the canary, and report why not.
fn exec_ungranted(path: &CStr, mut reporter: std::io::PipeWriter) -> ! {
    let report = match playpen::backend::apply(&CapabilitySet::default(), None) {
        Ok(()) => {
            let argv = [path.as_ptr(), std::ptr::null()];
            // SAFETY: `path` and `argv` are NUL-terminated and outlive the call.
            unsafe { libc::execv(path.as_ptr(), argv.as_ptr()) };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            [&b"E"[..], &errno.to_le_bytes()].concat()
        }
        Err(refusal) => [&b"R"[..], refusal.to_string().as_bytes()].concat(),
    };
    let _ = reporter.write_all(&report);
    // SAFETY: `_exit` skips the parent's atexit handlers, which must not run twice.
    unsafe { libc::_exit(127) }
}

/// One row's action made concrete on this host, with whatever the fixture made for it.
struct Prepared {
    /// The probe's verb and operand, once per path the target names; one verdict each.
    ops: Vec<[String; 2]>,
    /// Files the action creates, which must not survive the inside half.
    created: Vec<PathBuf>,
    /// A descriptor both halves inherit, open on a decoy credential.
    inherited: Option<File>,
    _decoys: Vec<NamedTempFile>,
    _decoy_dir: Option<TempDir>,
    _peer: Option<Running>,
}

/// What the fixture started for a row, stopped when dropped.
enum Running {
    Process(std::process::Child),
    /// Closed by its own drop; held only to keep it listening.
    #[cfg(target_os = "linux")]
    Socket {
        _listener: std::os::unix::net::UnixListener,
    },
    /// A pathname socket, with the directory it was bound in: both go on drop, so a killed run
    /// costs one stale directory under the host temp and never a permanent one.
    PathSocket {
        _listener: std::os::unix::net::UnixListener,
        _dir: TempDir,
    },
}

impl Drop for Running {
    fn drop(&mut self) {
        match self {
            Running::Process(child) => {
                // Best effort: the decoy only waits, and a kill that fails leaves nothing to reap.
                let _ = child.kill();
                let _ = child.wait();
            }
            #[cfg(target_os = "linux")]
            Running::Socket { .. } => {}
            Running::PathSocket { .. } => {}
        }
    }
}

/// Start `signalled` outside every boundary, and name it as the probe's operand.
fn start(signalled: Signalled) -> Result<(Running, String), String> {
    match signalled {
        Signalled::DecoyProcess => {
            let child = Command::new(common::os_bin("sleep"))
                .arg("300")
                .stdin(Stdio::null())
                .spawn()
                .map_err(|e| format!("decoy process: {e}"))?;
            let pid = child.id().to_string();
            Ok((Running::Process(child), pid))
        }
    }
}

/// Bind `listening` outside every boundary, and name it as the probe's operand.
fn listen(listening: Listening) -> Result<(Running, String), String> {
    match listening {
        #[cfg(target_os = "linux")]
        Listening::DecoyAbstractSocket => {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::{SocketAddr, UnixListener};
            // Unique to this run, so no other process's socket is ever the one reached.
            let name = format!("playpen-decoy-{}", std::process::id());
            let listener = SocketAddr::from_abstract_name(name.as_bytes())
                .and_then(|addr| UnixListener::bind_addr(&addr))
                .map_err(|e| format!("decoy abstract socket {name}: {e}"))?;
            Ok((
                Running::Socket {
                    _listener: listener,
                },
                name,
            ))
        }
        #[cfg(not(target_os = "linux"))]
        Listening::DecoyAbstractSocket => Err("abstract unix sockets exist on Linux only".into()),
        Listening::DecoyUnixSocket => {
            use std::os::unix::net::UnixListener;
            // A directory of its own under the host temp, which no grant reaches (`N-hosttemp`),
            // so the socket is outside every grant however the fixture's root moves.
            let dir = TempDir::new().map_err(|e| format!("decoy socket directory: {e}"))?;
            let path = dir.path().join("oracle.sock");
            let listener = UnixListener::bind(&path)
                .map_err(|e| format!("decoy unix socket {}: {e}", path.display()))?;
            let name = path
                .to_str()
                .ok_or_else(|| format!("decoy unix socket {} is not UTF-8", path.display()))?
                .to_owned();
            Ok((
                Running::PathSocket {
                    _listener: listener,
                    _dir: dir,
                },
                name,
            ))
        }
    }
}

/// Paths the fixture made outside, removed in reverse order when the batch is done. One per batch,
/// so a directory made for one row (`~/.ssh`) outlives the decoys other rows made inside it.
#[derive(Default)]
struct Made(Vec<PathBuf>);

impl Drop for Made {
    fn drop(&mut self) {
        for path in self.0.iter().rev() {
            // Best effort: a decoy that cannot be removed is reported by nothing else either. The
            // entry itself decides, so a link to a directory is removed as the link it is.
            let is_dir = path.symlink_metadata().is_ok_and(|meta| meta.is_dir());
            let _ = if is_dir {
                fs::remove_dir(path)
            } else {
                fs::remove_file(path)
            };
        }
    }
}

/// The number an inherited descriptor is handed over under: high, because a confined child's
/// startup can open descriptors of its own, which take the lowest free numbers and could land on
/// a low one once playpen has closed it.
const INHERITED: RawFd = 99;

/// What a decoy at a real credential path holds: inert in the file's own syntax, and naming its
/// author, should a killed run leave it behind
/// ([#118](https://github.com/firefly-engineering/playpen/issues/118)).
pub const DECOY: &str = "# playpen enforcement-suite decoy, safe to delete\n";

/// The decoy key's name. `ssh` tries only its default identity names, so a leftover is never
/// offered as a key.
pub const SSH_KEY_DECOY: &str = "id_playpen-decoy";

/// The file marking a decoy directory as one, holding [`DECOY`].
pub const DECOY_MARKER: &str = "playpen-decoy";

/// `root` is the probe's granted root, where a target reached through a link puts its links.
fn prepare(action: Action, home: &Path, root: &Path, made: &mut Made) -> Result<Prepared, String> {
    let mut decoys = Vec::new();
    let mut decoy_dir = None;
    let mut target = |target: Target| -> Result<Vec<PathBuf>, String> {
        match target {
            Target::SshKey => ssh_key(home, made).map(|key| vec![key]),
            Target::SshConfig => {
                let ssh = ssh_dir(home, made)?;
                decoy_file(&ssh.join("config"), made).map(|config| vec![config])
            }
            Target::Aws => {
                let aws = home.join(".aws");
                reclaim_dir(&aws, Some(DECOY_MARKER), made)?;
                if aws.symlink_metadata().is_err() {
                    // Marked, so a decoy a killed run leaves behind names its author.
                    decoy_dir_at(&aws, made)?;
                    decoy_file(&aws.join(DECOY_MARKER), made)?;
                }
                Ok(vec![aws])
            }
            Target::Npmrc => decoy_file(&home.join(".npmrc"), made).map(|npmrc| vec![npmrc]),
            Target::HostTemp => host_temp()?
                .into_iter()
                .map(|dir| {
                    let decoy = tempfile::Builder::new()
                        .prefix("playpen-decoy")
                        .tempfile_in(&dir)
                        .map_err(|e| format!("decoy in {}: {e}", dir.display()))?;
                    let path = decoy.path().to_owned();
                    decoys.push(decoy);
                    Ok(path)
                })
                .collect(),
            Target::DecoyDir => {
                let dir = TempDir::new().map_err(|e| format!("decoy directory: {e}"))?;
                Ok(vec![decoy_dir.insert(dir).path().to_owned()])
            }
            Target::StaleStorePath | Target::DecoyKeg | Target::ExcludedDecoy => Err(format!(
                "{target:?} stands beside a toolchain, and the probe's root has none"
            )),
            Target::LinkedCredentials => {
                let key = ssh_key(home, made)?;
                let ssh = ssh_dir(home, made)?;
                let config = decoy_file(&ssh.join("config"), made)?;
                let npmrc = decoy_file(&home.join(".npmrc"), made)?;
                // Inside the root's temp directory, so the links go with it.
                [("id", key), ("config", config), ("npmrc", npmrc)]
                    .into_iter()
                    .map(|(name, credential)| {
                        let link = root.join(format!("link-to-{name}"));
                        std::os::unix::fs::symlink(&credential, &link)
                            .map_err(|e| format!("link {}: {e}", link.display()))?;
                        Ok(link)
                    })
                    .collect()
            }
        }
    };
    let each = |verb: &str, paths: Vec<PathBuf>| -> Result<Vec<[String; 2]>, String> {
        paths
            .iter()
            .map(|path| Ok([verb.to_owned(), utf8(path)?]))
            .collect()
    };
    let mut created = Vec::new();
    let mut inherited = None;
    let mut peer = None;
    let ops = match action {
        Action::Canary => {
            return Err(
                "the canary runs under the bare floor alone, never beside the probe".into(),
            );
        }
        Action::Refuse(_) | Action::CheckDocument | Action::CoverCodes => {
            return Err("a refusal has no boundary for the probe to run under".into());
        }
        Action::TraceBrackets => {
            return Err("a bracketed trace drives two launches of its own, never the probe".into());
        }
        Action::ArgvMatches => {
            return Err("a shim's argv is read from the child's own stdout, not the probe".into());
        }
        Action::ManifestIsTrue => {
            return Err(
                "the manifest's own check builds its ops from the manifest it was given".into(),
            );
        }
        Action::PullDenials => {
            return Err("pulling denials needs the probe forked, never launched directly".into());
        }
        Action::Request(_) => {
            return Err(
                "a credential route's own fixture builds its request ops, and the probe's root \
                 has no route"
                    .into(),
            );
        }
        Action::Live(_) => {
            return Err("a liveness row launches the agent, never the probe".into());
        }
        Action::Read(t) => each("read", target(t)?)?,
        Action::List(t) => each("list", target(t)?)?,
        Action::Create(t) => {
            created = target(t)?.iter().map(|dir| dir.join("planted")).collect();
            each("write", created.clone())?
        }
        Action::ReadInherited => {
            let credential = NamedTempFile::new()
                .and_then(|mut decoy| {
                    std::io::Write::write_all(&mut decoy, DECOY.as_bytes())?;
                    Ok(decoy)
                })
                .map_err(|e| format!("decoy credential: {e}"))?;
            let fd = credential
                .reopen()
                .map_err(|e| format!("decoy credential: {e}"))?;
            let op = ["read-fd".to_owned(), INHERITED.to_string()];
            inherited = Some(fd);
            decoys.push(credential);
            vec![op]
        }
        Action::LookUp(services) => services_named(services)
            .iter()
            .map(|service| ["look-up".to_owned(), (*service).to_owned()])
            .collect(),
        Action::Signal(signalled) => {
            let (running, pid) = start(signalled)?;
            peer = Some(running);
            vec![["signal".to_owned(), pid]]
        }
        Action::Connect(listening) => {
            let (running, name) = listen(listening)?;
            peer = Some(running);
            vec![[listening.verb().to_owned(), name]]
        }
    };
    Ok(Prepared {
        ops,
        created,
        inherited,
        _decoys: decoys,
        _decoy_dir: decoy_dir,
        _peer: peer,
    })
}

fn services_named(services: Services) -> &'static [&'static str] {
    match services {
        // Plain `com.apple.securityd` and `com.apple.SecurityServer.xpc` resolve to no service
        // outside on macOS 26, so naming them would make the row a setup failure.
        Services::Keychain => &[
            "com.apple.SecurityServer",
            "com.apple.securityd.xpc",
            "com.apple.securityd.general",
            "com.apple.securityd.ckks",
            "com.apple.securityd.sos",
            "com.apple.securityd.aps",
        ],
    }
}

fn utf8(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{} is not UTF-8", path.display()))
}

/// The host's temp directories, each of which must exist: a missing one is a setup failure, not
/// a smaller host temp. Resolved, because the mechanism enforces on the resolved path: through
/// macOS's `/tmp` link a read would also need the link, and a grant of `/private/tmp` alone
/// would go unseen.
fn host_temp() -> Result<Vec<PathBuf>, String> {
    [PathBuf::from("/tmp"), PathBuf::from("/var/tmp")]
        .into_iter()
        .chain(user_temp_dir()?)
        .map(|dir| {
            dir.canonicalize()
                .map_err(|e| format!("host temp {}: {e}", dir.display()))
        })
        .collect()
}

/// macOS's per-user temp under `/var/folders/…`, as `confstr` reports it to every tool that asks.
#[cfg(target_os = "macos")]
fn user_temp_dir() -> Result<Option<PathBuf>, String> {
    use std::os::unix::ffi::OsStrExt;

    let failed = || format!("confstr: {}", std::io::Error::last_os_error());
    // SAFETY: a null buffer of length 0 asks confstr for the size it needs, terminator included.
    let len = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, std::ptr::null_mut(), 0) };
    if len == 0 {
        return Err(failed());
    }
    let mut buf = vec![0u8; len];
    // SAFETY: `buf` is valid for writes of `len` bytes, the length passed.
    if unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr().cast(), len) } == 0 {
        return Err(failed());
    }
    let path = std::ffi::CStr::from_bytes_until_nul(&buf).map_err(|e| format!("confstr: {e}"))?;
    Ok(Some(PathBuf::from(std::ffi::OsStr::from_bytes(
        path.to_bytes(),
    ))))
}

/// Linux has no per-user temp of its own.
#[cfg(target_os = "linux")]
fn user_temp_dir() -> Result<Option<PathBuf>, String> {
    Ok(None)
}

/// `~/.ssh`, made with the mode ssh demands if the host has none. The decoys the rows put in it
/// are reclaimed first, then the directory itself if that leaves it empty.
fn ssh_dir(home: &Path, made: &mut Made) -> Result<PathBuf, String> {
    let ssh = home.join(".ssh");
    for name in [SSH_KEY_DECOY, "config"] {
        reclaim_file(&ssh.join(name), made)?;
    }
    reclaim_dir(&ssh, None, made)?;
    decoy_dir_at(&ssh, made)
}

/// Whether `path` is a decoy: a regular file whose entire content is [`DECOY`]. Never a prefix or
/// a line within a larger file, which could be a host's own file the suite once wrote beside.
fn is_decoy(path: &Path) -> bool {
    path.symlink_metadata().is_ok_and(|meta| meta.is_file())
        && fs::read(path).is_ok_and(|content| content == DECOY.as_bytes())
}

/// Remove `path` if it is a decoy a killed run left behind, so the host is not taken to have it
/// ([spec §17.1]). One this run made is still in use.
///
/// [spec §17.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#171-form
fn reclaim_file(path: &Path, made: &Made) -> Result<(), String> {
    if made.0.iter().any(|p| p == path) || !is_decoy(path) {
        return Ok(());
    }
    fs::remove_file(path).map_err(|e| format!("reclaim {}: {e}", path.display()))
}

/// Remove the directory `path` if a killed run left it behind as a decoy: holding nothing but
/// `marker`, itself a decoy, or nothing at all where there is no marker. Never recursive, so a
/// directory that has since gained anything of the host's survives.
fn reclaim_dir(path: &Path, marker: Option<&str>, made: &Made) -> Result<(), String> {
    if made.0.iter().any(|p| p == path) || !path.symlink_metadata().is_ok_and(|meta| meta.is_dir())
    {
        return Ok(());
    }
    let failed = |e: std::io::Error| format!("reclaim {}: {e}", path.display());
    let entries: Vec<_> = fs::read_dir(path)
        .map_err(failed)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<_, _>>()
        .map_err(failed)?;
    match (marker, entries.as_slice()) {
        (None, []) => {}
        (Some(marker), [only]) if only == marker && is_decoy(&path.join(marker)) => {
            fs::remove_file(path.join(marker)).map_err(failed)?;
        }
        _ => return Ok(()),
    }
    fs::remove_dir(path).map_err(failed)
}

/// `path` as the host has it, else a decoy file there; a decoy a killed run left there is
/// reclaimed first. A dangling symlink counts as the host's: it is never written through, and
/// nothing is ever appended to a file that exists.
fn decoy_file(path: &Path, made: &mut Made) -> Result<PathBuf, String> {
    reclaim_file(path, made)?;
    if path.symlink_metadata().is_err() {
        File::options()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut decoy| std::io::Write::write_all(&mut decoy, DECOY.as_bytes()))
            .map_err(|e| format!("decoy {}: {e}", path.display()))?;
        made.0.push(path.to_owned());
    }
    Ok(path.to_owned())
}

/// `path` as the host has it, else an empty owner-only decoy directory there: the smallest write
/// a decoy can make, and inert if left behind.
fn decoy_dir_at(path: &Path, made: &mut Made) -> Result<PathBuf, String> {
    if path.symlink_metadata().is_err() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|e| format!("decoy {}: {e}", path.display()))?;
        made.0.push(path.to_owned());
    }
    Ok(path.to_owned())
}

/// The host's own `~/.ssh/id_*` private key if it has one; else a decoy in its place, so the
/// row exercises the same path resolution on a fresh runner.
/// A host with a key of its own is left untouched: nothing is written and nothing reclaimed.
fn ssh_key(home: &Path, made: &mut Made) -> Result<PathBuf, String> {
    let ssh = home.join(".ssh");
    if let Ok(entries) = fs::read_dir(&ssh) {
        let mut keys: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| is_private_key(path) && path.is_file() && !is_decoy(path))
            .collect();
        keys.sort();
        if let Some(key) = keys.into_iter().next() {
            return Ok(key);
        }
    }
    decoy_file(&ssh_dir(home, made)?.join(SSH_KEY_DECOY), made)
}

fn is_private_key(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("id_") && !name.ends_with(".pub"))
}

/// Every row of the probe-root fixture, under one confined launch.
fn probe_root(rows: &[&Row], home: &Path) -> Vec<Verdict> {
    // Read-only: the probe's root is a stated perturbation, and the smallest one that runs it.
    // Made first, so a target reached through a link can put the link in it.
    let fixture = common::Fixture::with_mode("read");
    let mut made = Made::default();
    let prepared: Vec<Result<Prepared, String>> = rows
        .iter()
        .map(|row| prepare(row.action, home, fixture.root(), &mut made))
        .collect();
    let ops: Vec<&String> = prepared
        .iter()
        .flatten()
        .flat_map(|p| p.ops.iter().flatten())
        .collect();
    let actions = prepared.iter().flatten().map(|p| p.ops.len()).sum();
    // With no action on its command line the probe would only print its usage.
    if actions == 0 {
        return prepared
            .into_iter()
            .map(|p| Verdict::Setup(p.err().unwrap_or_default()))
            .collect();
    }
    let inherited: Vec<RawFd> = prepared
        .iter()
        .flatten()
        .filter_map(|p| p.inherited.as_ref().map(File::as_raw_fd))
        .collect();
    if inherited.len() > 1 {
        return vec![
            Verdict::Setup(format!("one descriptor is inherited, as {INHERITED}"));
            rows.len()
        ];
    }

    let mut outside = Command::new(PROBE);
    outside.args(&ops);
    inherit(&mut outside, &inherited);
    let outside = observe(outside.output().expect("run the probe"), actions);
    // The outside half created what it was asked to; the inside half must find it absent.
    for created in prepared.iter().flatten().flat_map(|p| &p.created) {
        let _ = fs::remove_file(created);
    }
    let probe = fixture.probe();
    let mut argv = vec![probe.to_str().expect("a UTF-8 probe path")];
    argv.extend(ops.iter().map(|op| op.as_str()));
    let mut inside = fixture.run(&argv);
    inside.stdin(Stdio::null());
    inherit(&mut inside, &inherited);
    let inside = observe(inside.output().expect("run playpen"), actions);

    let mut seen = match (outside, inside) {
        (Ok(outside), Ok(inside)) => outside.into_iter().zip(inside),
        (Err(why), _) => return vec![Verdict::Setup(format!("outside: {why}")); rows.len()],
        (_, Err(why)) => return vec![Verdict::Fail(format!("inside: {why}")); rows.len()],
    };
    rows.iter()
        .zip(&prepared)
        .map(|(row, prepared)| {
            let prepared = match prepared {
                Ok(prepared) => prepared,
                Err(why) => return Verdict::Setup(why.clone()),
            };
            // Every path the target names is judged; the row holds only if each one does.
            let verdicts: Vec<Verdict> = prepared
                .ops
                .iter()
                .map(|_| {
                    let (outside, inside) = seen.next().expect("one verdict per action");
                    judge(row.expected, &outside, &inside)
                })
                .collect();
            if let Some(failed) = verdicts.into_iter().find(|v| *v != Verdict::Pass) {
                return failed;
            }
            match prepared.created.iter().find(|created| created.exists()) {
                Some(created) => Verdict::Fail(format!("{} was created inside", created.display())),
                None => Verdict::Pass,
            }
        })
        .collect()
}

/// Hand the descriptor in `fds`, if any, to the spawned process as [`INHERITED`], without
/// close-on-exec. When it already is that number, `dup2` changes nothing and its close-on-exec
/// flag survives, so it is cleared.
fn inherit(command: &mut Command, fds: &[RawFd]) {
    let Some(&source) = fds.first() else {
        return;
    };
    // SAFETY: dup2 and fcntl are async-signal-safe; the descriptor is open in the forked child.
    unsafe {
        command.pre_exec(move || {
            let done = if source == INHERITED {
                libc::fcntl(INHERITED, libc::F_SETFD, 0)
            } else {
                libc::dup2(source, INHERITED)
            };
            match done {
                -1 => Err(std::io::Error::last_os_error()),
                _ => Ok(()),
            }
        });
    }
}

/// The probe's verdicts, one per action. A probe that broke voids them all: the exit code says
/// only whether it ran.
fn observe(output: Output, actions: usize) -> Result<Vec<Seen>, String> {
    if !output.status.success() {
        return Err(format!(
            "the probe broke: {}, stderr {:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let seen = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(seen)
        .collect::<Result<Vec<_>, _>>()?;
    if seen.len() != actions {
        return Err(format!(
            "{} verdicts for {actions} actions: {seen:?}",
            seen.len()
        ));
    }
    Ok(seen)
}

fn seen(line: &str) -> Result<Seen, String> {
    let verdict: Value =
        serde_json::from_str(line).map_err(|e| format!("verdict {line:?}: {e}"))?;
    match verdict["ok"].as_bool() {
        Some(true) => Ok(Seen::Succeeded),
        Some(false) => {
            let field = |name: &str| verdict[name].as_i64().and_then(|n| i32::try_from(n).ok());
            Ok(Seen::Failed {
                cause: field("errno")
                    .map(Cause::Errno)
                    .or_else(|| field("kr").map(Cause::Bootstrap)),
                detail: line.to_owned(),
            })
        }
        None => Err(format!("verdict {line:?} has no `ok`")),
    }
}
