//! `playpen-minter-anthropic`, the reference minters for Anthropic ([spec §7.5]), run as playpen
//! runs a minter: through [`playpen::minter::mint`]. The Keychain is a fake `security` and the
//! credential file a temporary one, so no test reaches the operator's own keystore.
//!
//! [spec §7.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#75-subscription-logins

mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use playpen::code::Code;
use playpen::minter::{Destination, Minted, Request, instant, mint};
use playpen::policy::Minter;
use serde_json::json;

const BIN: &str = env!("CARGO_BIN_EXE_playpen-minter-anthropic");
const SECRET: &str = "sk-ant-oat01-s3cret-never-in-a-message";
const REFRESH: &str = "sk-ant-ort01-refresh-never-read";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
}

/// Run the minter as playpen does, on a profile route to Anthropic.
fn minted(args: &[&str]) -> Result<Minted, playpen::refusal::Refusal> {
    let mut command = vec![BIN.to_owned()];
    command.extend(args.iter().map(|arg| (*arg).to_owned()));
    mint(
        "anthropic",
        &Minter {
            command,
            revoke: None,
            timeout: None,
        },
        &Request::new(
            Destination {
                host: "api.anthropic.com".into(),
                path_prefix: "/".into(),
            },
            None,
        ),
    )
}

/// Run the minter directly, with only `env` in its environment and `stdin` on its stdin.
fn direct(args: &[&str], env: &[(&str, &Path)], stdin: &str) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the minter runs");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("stdin is written");
    child.wait_with_output().expect("the minter exits")
}

const REQUEST: &str =
    r#"{"version":1,"route":{"host":"api.anthropic.com","path_prefix":"/"},"scope":null}"#;

/// A fake `security` in `dir`: it appends its argv to `argv`, keeps what `-i` is handed in
/// `stdin`, and answers `find-generic-password` with the file `item`, or `errSecItemNotFound`.
fn fake_security(dir: &Path) -> PathBuf {
    let path = dir.join("security");
    // `cat` by the path the floor holds it at: the minter runs with an empty environment, and the
    // default search path of `sh` does not hold it on every host (NixOS).
    let cat = common::os_bin("cat");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\n\
             d={}\n\
             printf '%s\\n' \"$*\" >> \"$d/argv\"\n\
             case \"$1\" in\n\
             -i) {cat} > \"$d/stdin\" ;;\n\
             find-generic-password) {cat} \"$d/item\" 2>/dev/null || exit 44 ;;\n\
             esac\n",
            dir.display()
        ),
    )
    .expect("the fake is written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

/// The host login as Claude Code stores it, expiring at `expires_at_ms`.
fn host_login(expires_at_ms: u64) -> String {
    json!({"claudeAiOauth": {
        "accessToken": SECRET,
        "refreshToken": REFRESH,
        "expiresAt": expires_at_ms,
        "scopes": ["user:inference", "user:profile"],
        "subscriptionType": "max",
    }})
    .to_string()
}

/// `store` writes the token from stdin, never from argv, with a year's `expires_at`, and
/// `setup-token` returns it as the stored grant.
#[test]
fn a_stored_setup_token_is_minted_with_its_expiry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("config/playpen/grant.json");
    let file = file.to_str().expect("utf-8");
    let stored = direct(&["store", "--file", file], &[], &format!("{SECRET}\n"));
    assert!(stored.status.success(), "{stored:?}");
    let mode = std::fs::metadata(file)
        .expect("stored")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let minted = minted(&["setup-token", "--file", file]).expect("minted");
    assert_eq!(minted.secret(), SECRET);
    let expires = instant(&minted.expires_at).expect("RFC 3339");
    let year = 365 * 86_400;
    assert!(
        (now() + year - 60..=now() + year).contains(&expires),
        "{}",
        minted.expires_at
    );
}

/// On the Keychain, `store` hands the item to `security -i` on stdin, and `setup-token` reads it
/// back by service.
#[test]
fn a_setup_token_goes_through_security_and_never_its_argv() {
    let dir = tempfile::tempdir().expect("tempdir");
    let security = fake_security(dir.path());
    let security = security.to_str().expect("utf-8");
    let at = ["--service", "my-grant", "--security", security];
    let stored = direct(&[&["store"][..], &at].concat(), &[], SECRET);
    assert!(stored.status.success(), "{stored:?}");
    let argv = std::fs::read_to_string(dir.path().join("argv")).expect("argv");
    assert_eq!(argv, "-i\n");
    let line = std::fs::read_to_string(dir.path().join("stdin")).expect("stdin");
    let hex = line
        .strip_prefix("add-generic-password -U -a \"playpen\" -s \"my-grant\" -X \"")
        .and_then(|rest| rest.strip_suffix("\"\n"))
        .unwrap_or_else(|| panic!("not an add-generic-password line: {line}"));
    let value: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("hex"))
        .collect();
    std::fs::write(dir.path().join("item"), [&value[..], b"\n"].concat()).expect("item");
    let minted = minted(&[&["setup-token"][..], &at].concat()).expect("minted");
    assert_eq!(minted.secret(), SECRET);
    let argv = std::fs::read_to_string(dir.path().join("argv")).expect("argv");
    assert_eq!(argv, "-i\nfind-generic-password -s my-grant -w\n");
}

/// `host-login` returns the access token and its expiry as they are stored, and writes nothing:
/// not the file, and no lock beside it, which is where a refresh would start.
#[test]
fn the_host_login_is_read_and_never_refreshed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join(".credentials.json");
    let expires = now() + 3600;
    let login = host_login(expires * 1000 + 250);
    std::fs::write(&file, &login).expect("login");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400)).expect("chmod");
    let modified = std::fs::metadata(&file)
        .and_then(|m| m.modified())
        .expect("mtime");
    let minted = minted(&["host-login", "--file", file.to_str().expect("utf-8")]).expect("minted");
    assert_eq!(minted.secret(), SECRET);
    assert_eq!(instant(&minted.expires_at), Some(expires));
    assert!(
        minted.expires_at.ends_with(".250Z"),
        "{}",
        minted.expires_at
    );
    assert_eq!(std::fs::read_to_string(&file).expect("login"), login);
    assert_eq!(
        std::fs::metadata(&file)
            .and_then(|m| m.modified())
            .expect("mtime"),
        modified
    );
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("dir")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    assert_eq!(entries, [".credentials.json"]);
}

/// Claude Code 2.1.288 stores a fractional `expiresAt`, and the login is read all the same, its
/// expiry truncated to the millisecond
/// ([#106](https://github.com/firefly-engineering/playpen/issues/106)).
#[test]
fn a_fractional_expiry_is_read_to_the_millisecond() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join(".credentials.json");
    let expires = now() + 3600;
    let login = host_login(expires * 1000 + 250).replace(
        &format!("{}", expires * 1000 + 250),
        &format!("{}.0049", expires * 1000 + 250),
    );
    assert!(login.contains(".0049"), "{login}");
    std::fs::write(&file, &login).expect("login");
    let minted = minted(&["host-login", "--file", file.to_str().expect("utf-8")]).expect("minted");
    assert_eq!(minted.secret(), SECRET);
    assert!(
        minted.expires_at.ends_with(".250Z"),
        "{}",
        minted.expires_at
    );
}

/// An expired host login fails rather than being refreshed, and says so without the token.
#[test]
fn an_expired_host_login_fails_rather_than_refresh() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join(".credentials.json");
    std::fs::write(&file, host_login((now() - 60) * 1000)).expect("login");
    let file = file.to_str().expect("utf-8");
    let refusal = minted(&["host-login", "--file", file]).expect_err("expired");
    assert_eq!(refusal.code, Code::MinterFailed);
    let output = direct(&["host-login", "--file", file], &[], REQUEST);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("expired at"), "{stderr}");
    assert!(stderr.contains("run `claude` on the host"), "{stderr}");
    assert!(
        !stderr.contains("s3cret") && !stderr.contains("refresh-never"),
        "{stderr}"
    );
}

/// A malformed item exits non-zero, and its message says where it broke but never quotes it,
/// even where serde's own message would.
#[test]
fn a_malformed_item_fails_without_its_secret() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("item.json");
    let file_arg = file.to_str().expect("utf-8");
    for (minter, item) in [
        (
            "setup-token",
            format!(r#"{{"token":"{SECRET}","expires_at":"soon"}}"#),
        ),
        ("setup-token", format!(r#"{{"token":"{SECRET}""#)),
        (
            "setup-token",
            format!(r#"{{"token":"{SECRET}","expires_at":7}}"#),
        ),
        ("setup-token", SECRET.to_owned()),
        (
            "host-login",
            format!(r#"{{"claudeAiOauth":{{"accessToken":"{SECRET}","expiresAt":"{SECRET}"}}}}"#),
        ),
        (
            "host-login",
            format!(r#"{{"claudeAiOauth":{{"accessToken":"{SECRET}"#),
        ),
    ] {
        std::fs::write(&file, &item).expect("item");
        let output = direct(&[minter, "--file", file_arg], &[], REQUEST);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{minter} took {item}");
        assert!(output.stdout.is_empty(), "{minter} answered {item}");
        assert!(stderr.contains(file_arg), "{stderr}");
        assert!(
            !stderr.contains("s3cret"),
            "{minter} quoted {item}: {stderr}"
        );
        let refusal = minted(&[minter, "--file", file_arg]).expect_err("malformed");
        assert_eq!(refusal.code, Code::MinterFailed);
        assert!(
            !refusal.message().contains("s3cret"),
            "{}",
            refusal.message()
        );
    }
}

/// With no item named, `host-login` reads where Claude Code keeps its login: its own Keychain
/// item on macOS.
#[cfg(target_os = "macos")]
#[test]
fn the_host_login_is_claude_codes_own_keychain_item() {
    let dir = tempfile::tempdir().expect("tempdir");
    let security = fake_security(dir.path());
    std::fs::write(dir.path().join("item"), host_login((now() + 3600) * 1000)).expect("item");
    let security = security.to_str().expect("utf-8");
    let output = direct(&["host-login", "--security", security], &[], REQUEST);
    assert!(output.status.success(), "{output:?}");
    let argv = std::fs::read_to_string(dir.path().join("argv")).expect("argv");
    assert_eq!(
        argv,
        "find-generic-password -s Claude Code-credentials -w\n"
    );
    // Under a config directory of its own, Claude Code hashes it into the service name.
    let output = direct(
        &["host-login", "--security", security],
        &[("CLAUDE_CONFIG_DIR", dir.path())],
        REQUEST,
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--service"));
}

/// With no item named, `host-login` reads where Claude Code keeps its login: its credential file,
/// under `CLAUDE_CONFIG_DIR` where that is set and `~/.claude` where it is not.
#[cfg(not(target_os = "macos"))]
#[test]
fn the_host_login_is_claude_codes_own_credential_file() {
    let home = tempfile::tempdir().expect("tempdir");
    let default = home.path().join(".claude");
    let config = home.path().join("elsewhere");
    std::fs::create_dir_all(&default).expect("dir");
    std::fs::create_dir_all(&config).expect("dir");
    std::fs::write(
        default.join(".credentials.json"),
        r#"{"claudeAiOauth":{"accessToken":"default","expiresAt":99999999999999}}"#,
    )
    .expect("login");
    std::fs::write(
        config.join(".credentials.json"),
        host_login((now() + 3600) * 1000),
    )
    .expect("login");
    let output = direct(&["host-login"], &[("HOME", home.path())], REQUEST);
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains(r#""token":"default""#));
    let output = direct(
        &["host-login"],
        &[
            ("HOME", home.path()),
            ("CLAUDE_CONFIG_DIR", config.as_path()),
        ],
        REQUEST,
    );
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains(SECRET));
}
