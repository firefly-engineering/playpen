//! `playpen-minter-anthropic`: the reference minters for Anthropic ([spec §7.5]). playpen models no
//! service, so this is a separate executable an operator names in a policy's `minters:` `command`,
//! never something `playpen` runs on its own.
//!
//! - `setup-token` is the reference minter: a keystore lookup of the dedicated, non-refreshing
//!   grant `claude setup-token` mints (one year, scoped `user:inference`), held in the operator's
//!   own item — never Claude Code's. `store` puts it there.
//! - `host-login` is the fallback: it returns the host login's current access token, read-only.
//!
//! **Neither ever refreshes.** Anthropic refresh tokens are single-use, so a minter that refreshes
//! without writing back logs the host out within one access-token lifetime ([ADR 0018], amended
//! by [#33]). `host-login` never deserializes the refresh token, and never writes or locks
//! anything: a lapsed token is a failure, and the host agent refreshes its own login.
//!
//! The keystore is the Keychain on macOS, through `/usr/bin/security`, and a file on Linux;
//! `--service` or `--file` names either one on any platform. What comes off it is held in
//! [`Zeroizing`], and no message quotes it: a parse error says where, never what.
//!
//! [spec §7.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#75-subscription-logins
//! [ADR 0018]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0018-playpen-authenticates-outside-the-boundary.md
//! [#33]: https://github.com/firefly-engineering/playpen/issues/33

use std::ffi::OsString;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use playpen::explain::timestamp;
use playpen::minter::{VERSION, instant};

/// The operator's own Keychain item for the setup-token grant, on macOS.
const SETUP_TOKEN_SERVICE: &str = "playpen-anthropic-setup-token";

/// Claude Code's own Keychain item for its login, as Claude Code 2.1.288 names it when neither
/// `CLAUDE_CONFIG_DIR` nor `CLAUDE_SECURESTORAGE_CONFIG_DIR` is set.
const HOST_LOGIN_SERVICE: &str = "Claude Code-credentials";

/// The account `store` files its Keychain item under: `security` requires one, and a lookup goes
/// by service alone.
const KEYCHAIN_ACCOUNT: &str = "playpen";

/// How long `claude setup-token` says its grant lives: one year, counted from when it is stored.
const SETUP_TOKEN_LIFE_S: u64 = 365 * 86_400;

/// The longest line `security -i` reads from stdin, which is the limit Claude Code holds its own
/// writes to.
const SECURITY_LINE_MAX: usize = 4032;

/// `security`'s exit status for an item that is not there (`errSecItemNotFound`).
const SECURITY_NOT_FOUND: i32 = 44;

#[derive(Parser)]
#[command(
    version,
    about = "playpen's reference minters for Anthropic. Never refreshes."
)]
struct Cli {
    #[command(subcommand)]
    command: Mint,
}

#[derive(Subcommand)]
enum Mint {
    /// Return the stored `claude setup-token` grant as `{token, expires_at}`.
    SetupToken(At),
    /// Read a `claude setup-token` token from stdin and store it, expiring in 365 days.
    Store(At),
    /// Return the host login's current access token, read-only. Never refreshes.
    HostLogin(At),
}

/// Where the item is. Neither flag: the Keychain on macOS, a file on Linux.
#[derive(Args)]
struct At {
    /// The Keychain item's service.
    #[arg(long, conflicts_with = "file")]
    service: Option<String>,
    /// A file holding the item.
    #[arg(long)]
    file: Option<PathBuf>,
    /// The `security` that reaches the Keychain.
    #[arg(long, default_value = "/usr/bin/security")]
    security: PathBuf,
}

/// The environment this reads, read once in `main` and handed down.
struct Env {
    home: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
    claude_config_dir: Option<OsString>,
    claude_securestorage_config_dir: Option<OsString>,
}

/// One keystore item.
enum Item {
    Keychain { security: PathBuf, service: String },
    File(PathBuf),
}

impl fmt::Display for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keychain { service, .. } => write!(f, "Keychain item {service:?}"),
            Self::File(path) => write!(f, "file {}", path.display()),
        }
    }
}

/// The setup-token item, and the minter's answer: the contract's `{token, expires_at}`.
#[derive(Serialize, Deserialize)]
struct Grant<T> {
    token: T,
    expires_at: String,
}

/// Claude Code's stored login. Only the two fields read are named: the refresh token is skipped
/// over, never held.
#[derive(Deserialize)]
struct HostLogin {
    #[serde(rename = "claudeAiOauth")]
    oauth: Oauth,
}

#[derive(Deserialize)]
struct Oauth {
    #[serde(rename = "accessToken")]
    access_token: String,
    /// Milliseconds since the epoch.
    #[serde(rename = "expiresAt")]
    expires_at: u64,
}

/// What a minter is handed: only the version is read, since neither minter's answer depends on
/// the route.
#[derive(Deserialize)]
struct Request {
    version: u32,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let nonempty = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
    let env = Env {
        home: nonempty("HOME").map(PathBuf::from),
        xdg_config_home: nonempty("XDG_CONFIG_HOME").map(PathBuf::from),
        claude_config_dir: nonempty("CLAUDE_CONFIG_DIR"),
        // Set but empty means something to Claude Code, so it is kept as it is.
        claude_securestorage_config_dir: std::env::var_os("CLAUDE_SECURESTORAGE_CONFIG_DIR"),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    match run(cli.command, &env, now) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("playpen-minter-anthropic: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(mint: Mint, env: &Env, now: u64) -> Result<(), String> {
    match mint {
        Mint::SetupToken(at) => {
            request()?;
            let item = item(at, |security| setup_token_item(security, env))?;
            let grant: Grant<String> = parse(&item.read()?, &item, "{token, expires_at}")?;
            let token = Zeroizing::new(grant.token);
            let expires = instant(&grant.expires_at).ok_or_else(|| {
                format!("{item} holds an expires_at that is not an RFC 3339 timestamp")
            })?;
            usable(
                &token,
                expires,
                now,
                &item,
                "run `claude setup-token` and store it again",
            )?;
            answer(&token, &grant.expires_at)
        }
        Mint::Store(at) => {
            let item = item(at, |security| setup_token_item(security, env))?;
            let mut read = Zeroizing::new(String::new());
            std::io::stdin()
                .read_to_string(&mut read)
                .map_err(|e| format!("cannot read the token from stdin: {e}"))?;
            let token = read.trim();
            if token.is_empty() || token.contains(char::is_whitespace) {
                return Err("stdin does not hold one token: pipe in the token alone".into());
            }
            let expires_at = timestamp((now + SETUP_TOKEN_LIFE_S) * 1000);
            let value = Zeroizing::new(
                serde_json::to_vec(&Grant {
                    token,
                    expires_at: expires_at.clone(),
                })
                .map_err(|e| format!("cannot encode the grant: {e}"))?,
            );
            item.write(&value)?;
            eprintln!("stored the grant in {item}, expiring {expires_at}");
            Ok(())
        }
        Mint::HostLogin(at) => {
            request()?;
            let item = item(at, |security| host_login_item(security, env))?;
            let login: HostLogin = parse(&item.read()?, &item, "a Claude Code login")?;
            let token = Zeroizing::new(login.oauth.access_token);
            let expires_ms = login.oauth.expires_at;
            usable(
                &token,
                expires_ms / 1000,
                now,
                &item,
                "run `claude` on the host, which refreshes its own login",
            )?;
            answer(&token, &timestamp(expires_ms))
        }
    }
}

/// Read the request off stdin, whole: answering before it is read would close the pipe playpen
/// is still writing to.
fn request() -> Result<(), String> {
    let mut text = Vec::new();
    std::io::stdin()
        .read_to_end(&mut text)
        .map_err(|e| format!("cannot read the request from stdin: {e}"))?;
    let request: Request = serde_json::from_slice(&text)
        .map_err(|e| format!("stdin does not hold a minter request: {e}"))?;
    if request.version != VERSION {
        return Err(format!(
            "speaks minter contract version {VERSION}, and was handed version {}",
            request.version
        ));
    }
    Ok(())
}

/// The item `at` names, or the default one where it names none.
fn item(at: At, default: impl FnOnce(PathBuf) -> Result<Item, String>) -> Result<Item, String> {
    match (at.service, at.file) {
        (Some(service), _) => Ok(Item::Keychain {
            security: at.security,
            service,
        }),
        (None, Some(path)) => Ok(Item::File(path)),
        (None, None) => default(at.security),
    }
}

/// The operator's own item for the setup-token grant.
fn setup_token_item(security: PathBuf, env: &Env) -> Result<Item, String> {
    if cfg!(target_os = "macos") {
        return Ok(Item::Keychain {
            security,
            service: SETUP_TOKEN_SERVICE.into(),
        });
    }
    let config = env
        .xdg_config_home
        .clone()
        .or_else(|| env.home.as_ref().map(|home| home.join(".config")))
        .ok_or("neither XDG_CONFIG_HOME nor HOME is set: name the file with --file")?;
    Ok(Item::File(
        config.join("playpen/anthropic-setup-token.json"),
    ))
}

/// Where Claude Code 2.1.288 keeps its login: the Keychain on macOS, and `.credentials.json` in
/// its secure-storage directory on Linux.
fn host_login_item(security: PathBuf, env: &Env) -> Result<Item, String> {
    let securestorage = env.claude_securestorage_config_dir.as_ref();
    if cfg!(target_os = "macos") {
        // Claude Code suffixes the service with a hash of whichever directory is set.
        let suffixed = match securestorage {
            Some(dir) => !dir.is_empty(),
            None => env.claude_config_dir.is_some(),
        };
        if suffixed {
            return Err(format!(
                "with CLAUDE_CONFIG_DIR or CLAUDE_SECURESTORAGE_CONFIG_DIR set, Claude Code names \
                 its Keychain item {HOST_LOGIN_SERVICE:?} plus a hash of that directory: name it \
                 with --service"
            ));
        }
        return Ok(Item::Keychain {
            security,
            service: HOST_LOGIN_SERVICE.into(),
        });
    }
    // Set but empty means `~/.claude`, whatever `CLAUDE_CONFIG_DIR` says.
    let dir = match securestorage {
        Some(dir) if !dir.is_empty() => Some(dir),
        Some(_) => None,
        None => env.claude_config_dir.as_ref(),
    }
    .map(PathBuf::from)
    .or_else(|| env.home.as_ref().map(|home| home.join(".claude")))
    .ok_or("HOME is not set: name the file with --file")?;
    Ok(Item::File(dir.join(".credentials.json")))
}

impl Item {
    fn read(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        match self {
            Self::File(path) => std::fs::read(path)
                .map(Zeroizing::new)
                .map_err(|e| format!("cannot read {self}: {e}")),
            Self::Keychain { security, service } => {
                let mut child = Command::new(security)
                    .args(["find-generic-password", "-s", service, "-w"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("cannot run {}: {e}", security.display()))?;
                let mut value = Zeroizing::new(Vec::new());
                let read = child
                    .stdout
                    .take()
                    .map(|mut stdout| stdout.read_to_end(&mut value));
                let status = child
                    .wait()
                    .map_err(|e| format!("cannot wait for {}: {e}", security.display()))?;
                match status.code() {
                    Some(0) => {}
                    Some(SECURITY_NOT_FOUND) => return Err(format!("there is no {self}")),
                    _ => return Err(format!("cannot read {self}: security exited with {status}")),
                }
                if let Some(Err(e)) = read {
                    return Err(format!("cannot read {self}: {e}"));
                }
                // `-w` ends the password with a newline.
                if value.last() == Some(&b'\n') {
                    value.pop();
                }
                Ok(value)
            }
        }
    }

    /// Replace the item with `value`, which never reaches an argv.
    fn write(&self, value: &[u8]) -> Result<(), String> {
        match self {
            Self::File(path) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
                }
                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|e| format!("cannot open {self}: {e}"))?;
                // `mode` applies only to a file it creates.
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .and_then(|()| file.write_all(value))
                    .map_err(|e| format!("cannot write {self}: {e}"))
            }
            Self::Keychain { security, service } => {
                // `security -i` reads the command from stdin, so the secret is on no command line;
                // hex, so nothing in it needs quoting.
                if service.contains(|c: char| c == '"' || c == '\\' || c.is_control()) {
                    return Err(format!("{self} has a service security -i cannot quote"));
                }
                let hex: Zeroizing<String> =
                    Zeroizing::new(value.iter().map(|byte| format!("{byte:02x}")).collect());
                let line = Zeroizing::new(format!(
                    "add-generic-password -U -a \"{KEYCHAIN_ACCOUNT}\" -s \"{service}\" -X \"{}\"\n",
                    *hex
                ));
                if line.len() > SECURITY_LINE_MAX {
                    return Err(format!("the token is too long to store in {self}"));
                }
                let mut child = Command::new(security)
                    .arg("-i")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .spawn()
                    .map_err(|e| format!("cannot run {}: {e}", security.display()))?;
                let written = child
                    .stdin
                    .take()
                    .map(|mut stdin| stdin.write_all(line.as_bytes()));
                let status = child
                    .wait()
                    .map_err(|e| format!("cannot wait for {}: {e}", security.display()))?;
                match written {
                    Some(Ok(())) if status.success() => Ok(()),
                    Some(Err(e)) => Err(format!("cannot write {self}: {e}")),
                    _ => Err(format!(
                        "cannot write {self}: security exited with {status}"
                    )),
                }
            }
        }
    }
}

/// `bytes` as `T`, or an error that says where it broke and never what it read: serde's own
/// message can quote the value it choked on, which here is a secret.
fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8], item: &Item, what: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|e| {
        format!(
            "{item} does not hold {what}: {:?} error at line {}, column {}",
            e.classify(),
            e.line(),
            e.column()
        )
    })
}

/// Refuse a token that is missing or already expired: neither minter can do anything about it,
/// and handing it over would launch a run that fails at its first request.
fn usable(token: &str, expires: u64, now: u64, item: &Item, renew: &str) -> Result<(), String> {
    if token.is_empty() {
        return Err(format!("{item} holds no token: {renew}"));
    }
    if expires <= now {
        return Err(format!(
            "the token in {item} expired at {}: {renew}",
            timestamp(expires * 1000)
        ));
    }
    Ok(())
}

/// Write the contract's `{token, expires_at}` to stdout.
fn answer(token: &str, expires_at: &str) -> Result<(), String> {
    let out = Zeroizing::new(
        serde_json::to_vec(&Grant {
            token,
            expires_at: expires_at.to_owned(),
        })
        .map_err(|e| format!("cannot encode the answer: {e}"))?,
    );
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&out)
        .and_then(|()| stdout.flush())
        .map_err(|e| format!("cannot write the answer: {e}"))
}
