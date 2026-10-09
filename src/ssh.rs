//! SSH transport — shells out to the system `ssh` binary.
//!
//! Inherits known_hosts and key permissions from the host. v0.1 keeps
//! key-management code at zero by relying on the operator-managed key path.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

use crate::ctx::CallCtx;
use crate::error_class::{Classify, ErrorClass};
use crate::inventory::{HostConfig, RequestIdEnv};
use crate::vault::VaultClient;
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

impl ExecOutput {
    pub fn ok(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }
}

/// Remote command used when sudo needs a password.
///
/// Both the password and the real command travel over stdin: sudo reads
/// the first line as the password (`-S`, no prompt via `-p ''`), then a
/// root `sh -s` reads the command from the remainder. Two properties
/// matter:
///
/// - **Nothing secret on a command line.** This string (with the
///   request ID spliced in, see [`with_request_id`]) is all `ps` can
///   see, on prompto's host or on the target.
/// - **sudo reads stdin before anything else runs.** Splicing the
///   caller's command in as shell text (`sudo -S -- {cmd}`) would let
///   `x & cat` background sudo with its stdin detached while `cat` reads
///   the password, and `true; cat` would leak it whenever sudo had cached
///   credentials and skipped reading stdin. `-k` forces sudo to ignore
///   any cached credentials and consume the line every time, and
///   wrapping the command in `sh -s` means none of it executes until
///   sudo has authenticated.
///
/// `-k` does nothing against a NOPASSWD rule: sudo then never reads the
/// password line, and the root shell gets it as its first command
/// (`sh: 1: <password>: not found` on stderr, or the first line of a
/// `file_write`). So sudo runs a guard first: it reads one line and
/// demands [`SUDO_MARKER`], which is only the next line if sudo took the
/// password. Otherwise it exits [`SUDO_GUARD_EXIT`] without echoing what
/// it read or running anything. The guard is single-quoted on the remote
/// command line, so it must never contain `'` or `!` (csh history-expands
/// `!` even inside single quotes).
///
/// Also avoids remote quoting entirely, which matters because the login
/// shell on some BSD hosts is csh.
pub const SUDO_STDIN_SHELL: &str = "sudo -k -S -p '' -- sh -c '\
IFS= read -r l; [ \"$l\" = prompto-sudo-ok ] || { echo \"prompto: sudo did not read the password - \
this host has a passwordless sudo rule, drop its sudo_password_vault_path\" >&2; exit 97; }; \
exec \"$@\"' prompto-sudo sh -s";

/// Line sent right after the password; see [`SUDO_STDIN_SHELL`].
pub const SUDO_MARKER: &str = "prompto-sudo-ok";

/// Exit status of the guard when sudo did not read the password.
pub const SUDO_GUARD_EXIT: i32 = 97;

/// [`SUDO_STDIN_SHELL`] with a prompto-built `cmd` in place of `sh -s`.
pub fn sudo_guarded(cmd: &str) -> String {
    let prefix = SUDO_STDIN_SHELL
        .strip_suffix("sh -s")
        .expect("ends with sh -s");
    format!("{prefix}{cmd}")
}

/// Environment variable carrying the call's request ID to the remote
/// command, so host-side logs can be joined with prompto's.
pub const REQUEST_ID_ENV: &str = "PROMPTO_REQUEST_ID";

/// Shell text exporting [`REQUEST_ID_ENV`], put in front of every remote
/// command on hosts whose [`RequestIdEnv`] is `export`. That is the
/// default where the login shell is known to be POSIX-ish (sh, bash, zsh:
/// Linux and macOS). Elsewhere the default is `setenv`: on
/// FreeBSD/OPNsense the login shell may be csh, which has no `export`,
/// and Windows has no POSIX shell at all. Those hosts get the ID only
/// through `-o SetEnv` (needs `AcceptEnv PROMPTO_*`) or the vault sudo
/// path. `off` hosts get nothing: a key restricted by `command=`, rrsync
/// or git-shell sees the whole command line and rejects the prefix.
///
/// `sudo -n` resets the environment, so a passwordless-sudo command sees
/// the variable only if the host's sudoers has
/// `Defaults env_keep += "PROMPTO_REQUEST_ID"`. prompto deliberately does
/// not wrap the caller's command in `env …` there: a sudoers rule that
/// allows only specific commands would then stop matching. The vault
/// sudo path runs prompto's own root `sh`, so it sets the variable
/// itself (see [`with_request_id`]).
///
/// `rid` must be a ULID (Crockford base32): it is spliced in unquoted.
pub fn request_id_export(mode: RequestIdEnv, rid: &str) -> Option<String> {
    match mode {
        RequestIdEnv::Export => Some(format!("export {REQUEST_ID_ENV}={rid}; ")),
        RequestIdEnv::Setenv | RequestIdEnv::Off => None,
    }
}

/// `cmd` run under `env PROMPTO_REQUEST_ID=<id>`, for the slot after the
/// sudo guard's `exec "$@"` — the root side of the vault sudo path, where
/// sudo has already reset the environment. Plain words, so the login
/// shell (even csh) passes them through untouched. `cmd` unchanged on
/// `off` hosts.
pub fn with_request_id(ctx: &CallCtx, host: &HostConfig, cmd: &str) -> String {
    match host.request_id_env() {
        RequestIdEnv::Off => cmd.to_string(),
        RequestIdEnv::Export | RequestIdEnv::Setenv => {
            format!("env {REQUEST_ID_ENV}={} {cmd}", ctx.request_id())
        }
    }
}

#[derive(Clone, Debug)]
pub struct SshClient {
    pub ssh_bin: PathBuf,
    pub default_timeout: Duration,
    pub connect_timeout: Duration,
    vault: Option<Arc<VaultClient>>,
}

impl SshClient {
    pub fn new(ssh_bin: PathBuf, default_timeout: Duration) -> Self {
        Self {
            ssh_bin,
            default_timeout,
            connect_timeout: Duration::from_secs(5),
            vault: None,
        }
    }

    /// Enable vault-backed sudo for hosts that declare
    /// `sudo_password_vault_path`.
    pub fn with_vault(mut self, vault: Arc<VaultClient>) -> Self {
        self.vault = Some(vault);
        self
    }

    /// Run an arbitrary remote command.
    ///
    /// With `sudo`, a host carrying `sudo_password_vault_path` gets the
    /// stdin-fed password path (see [`SUDO_STDIN_SHELL`]); every other
    /// host gets `sudo -n`, which fails fast instead of hanging on a TTY
    /// prompt when there's no passwordless rule.
    ///
    /// The remote side gets [`REQUEST_ID_ENV`]; see [`request_id_export`]
    /// for how, and where it does not reach.
    pub async fn exec(
        &self,
        ctx: &CallCtx,
        host: &HostConfig,
        cmd: &str,
        cmd_timeout: Option<Duration>,
        sudo: bool,
    ) -> Result<ExecOutput> {
        if cmd.trim().is_empty() {
            crate::fail!(InvalidArgs, "empty command");
        }
        if sudo {
            if let Some(pw) = self.sudo_password(host).await? {
                let input = sudo_stdin_payload(&pw, cmd.as_bytes());
                let remote = sudo_guarded(&with_request_id(ctx, host, "sh -s"));
                return self
                    .run(ctx, host, &remote, Some(&input), cmd_timeout)
                    .await;
            }
            return self
                .run(ctx, host, &format!("sudo -n -- {cmd}"), None, cmd_timeout)
                .await;
        }
        self.run(ctx, host, cmd, None, cmd_timeout).await
    }

    /// Run a remote command and feed `stdin_bytes` into its stdin. Used by
    /// `script::run` and `file_write` to pipe content through SSH without
    /// going through shell-argument quoting hell.
    ///
    /// With `sudo` on a vault-backed host, the password and marker lines
    /// are prepended for `sudo -S` and the guard (see [`SUDO_STDIN_SHELL`]),
    /// and the content follows for the command. `cmd` lands after the
    /// guard's `exec "$@"`, so it must be a simple command that prompto
    /// built itself (`tee -- <validated path>`, `<interpreter> -`), never
    /// caller-supplied shell text.
    pub async fn exec_stdin(
        &self,
        ctx: &CallCtx,
        host: &HostConfig,
        cmd: &str,
        stdin_bytes: &[u8],
        cmd_timeout: Option<Duration>,
        sudo: bool,
    ) -> Result<ExecOutput> {
        if cmd.trim().is_empty() {
            crate::fail!(InvalidArgs, "empty command");
        }
        if sudo {
            if let Some(pw) = self.sudo_password(host).await? {
                let mut input = sudo_preamble(&pw);
                input.extend_from_slice(stdin_bytes);
                let remote = sudo_guarded(&with_request_id(ctx, host, cmd));
                return self
                    .run(ctx, host, &remote, Some(&input), cmd_timeout)
                    .await;
            }
            let remote = format!("sudo -n -- {cmd}");
            return self
                .run(ctx, host, &remote, Some(stdin_bytes), cmd_timeout)
                .await;
        }
        self.run(ctx, host, cmd, Some(stdin_bytes), cmd_timeout)
            .await
    }

    /// The host's sudo password from vault, if it declares one. Every
    /// failure is classified `vault`: nothing has run on the host yet.
    async fn sudo_password(&self, host: &HostConfig) -> Result<Option<String>> {
        self.fetch_sudo_password(host)
            .await
            .class(crate::error_class::ErrorClass::Vault)
    }

    async fn fetch_sudo_password(&self, host: &HostConfig) -> Result<Option<String>> {
        let Some(path) = host.sudo_password_vault_path.as_deref() else {
            return Ok(None);
        };
        let vault = self.vault.as_ref().context(
            "host declares sudo_password_vault_path but prompto has no vault configured \
             (set PROMPTO_VAULT_TOKEN)",
        )?;
        let field = host
            .sudo_password_vault_field
            .as_deref()
            .unwrap_or("password");
        let pw = vault.kv2_field(path, field).await?;
        // sudo -S takes the first line as the password. A newline inside
        // it would hand the remainder to the root shell as a command.
        if pw.is_empty() || pw.contains(['\n', '\r']) {
            bail!(
                "vault {path:?}/{field:?} is empty or multi-line; refusing to use it as a sudo password"
            );
        }
        // The guard can't tell the password from the marker.
        if pw == SUDO_MARKER {
            bail!("vault {path:?}/{field:?} equals the sudo marker; refusing it");
        }
        Ok(Some(pw))
    }

    /// The one place that spawns ssh.
    async fn run(
        &self,
        ctx: &CallCtx,
        host: &HostConfig,
        remote: &str,
        stdin_bytes: Option<&[u8]>,
        cmd_timeout: Option<Duration>,
    ) -> Result<ExecOutput> {
        use tokio::io::AsyncWriteExt;

        let mut command = Command::new(&self.ssh_bin);
        command
            .args(self.ssh_args(ctx, host, remote))
            .stdin(if stdin_bytes.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let dur = cmd_timeout.unwrap_or(self.default_timeout);
        let mut child = command
            .spawn()
            .context("spawn ssh")
            .class(ErrorClass::Internal)?;

        if let (Some(bytes), Some(mut stdin)) = (stdin_bytes, child.stdin.take()) {
            if let Err(e) = stdin.write_all(bytes).await {
                return Ok(ExecOutput {
                    stdout: String::new(),
                    // The io::Error, never the bytes — they may hold a password.
                    stderr: format!("ssh stdin write failed: {e}"),
                    exit_code: None,
                    timed_out: false,
                });
            }
            // Drop closes the pipe so the remote side sees EOF.
            drop(stdin);
        }

        match timeout(dur, child.wait_with_output()).await {
            Ok(Ok(out)) => Ok(ExecOutput {
                stdout: String::from_utf8_lossy(&out.stdout).to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
                exit_code: out.status.code(),
                timed_out: false,
            }),
            Ok(Err(e)) => Err(e)
                .context("ssh wait_with_output")
                .class(ErrorClass::Internal),
            Err(_) => Ok(ExecOutput {
                stdout: String::new(),
                stderr: format!("ssh command timed out after {}s", dur.as_secs()),
                exit_code: None,
                timed_out: true,
            }),
        }
    }

    /// ssh's argv for one call: options, target, then the remote command
    /// with the request ID exported in front of it.
    fn ssh_args(&self, ctx: &CallCtx, host: &HostConfig, remote: &str) -> Vec<OsString> {
        let rid = ctx.request_id();
        let mode = host.request_id_env();
        let remote = match request_id_export(mode, &rid) {
            Some(export) => format!("{export}{remote}"),
            None => remote.to_string(),
        };
        let mut args = vec![
            OsString::from("-o"),
            "BatchMode=yes".into(),
            "-o".into(),
            format!("ConnectTimeout={}", self.connect_timeout.as_secs().max(1)).into(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
        ];
        if mode != RequestIdEnv::Off {
            // Delivered only where the host's sshd has `AcceptEnv
            // PROMPTO_*`, silently dropped elsewhere. It is the only
            // route on `setenv` hosts, where the export prefix is skipped.
            args.push("-o".into());
            args.push(format!("SetEnv={REQUEST_ID_ENV}={rid}").into());
        }
        args.extend([
            "-i".into(),
            host.ssh_key.clone().into_os_string(),
            "-p".into(),
            host.ssh_port.to_string().into(),
            format!("{}@{}", host.ssh_user, host.ip).into(),
            "--".into(),
            remote.into(),
        ]);
        args
    }
}

/// Password line, then the marker line the guard in [`SUDO_STDIN_SHELL`] checks for.
fn sudo_preamble(password: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(password.len() + SUDO_MARKER.len() + 2);
    v.extend_from_slice(password.as_bytes());
    v.push(b'\n');
    v.extend_from_slice(SUDO_MARKER.as_bytes());
    v.push(b'\n');
    v
}

/// stdin for [`SUDO_STDIN_SHELL`]: the password line, the marker line,
/// then the command for the root shell.
pub fn sudo_stdin_payload(password: &str, cmd: &[u8]) -> Vec<u8> {
    let mut v = sudo_preamble(password);
    v.extend_from_slice(cmd);
    v.push(b'\n');
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The remote command in password mode is a fixed string: no part of
    /// the caller's command and no part of the password may reach ssh's
    /// argv, where `ps` on either machine could read it. Reverting to
    /// `sudo -S -- {cmd}` reintroduces the `x & cat` / cached-credential
    /// leaks described on SUDO_STDIN_SHELL.
    #[test]
    fn sudo_stdin_shell_is_fixed_and_forces_a_fresh_read() {
        assert!(SUDO_STDIN_SHELL.starts_with("sudo -k -S -p '' -- sh -c '"));
        assert!(
            SUDO_STDIN_SHELL.ends_with("' prompto-sudo sh -s"),
            "command must come from stdin"
        );
        assert!(SUDO_STDIN_SHELL.contains(SUDO_MARKER));
        assert!(SUDO_STDIN_SHELL.contains(&format!("exit {SUDO_GUARD_EXIT};")));
    }

    #[test]
    fn guard_survives_single_quoting_and_csh() {
        let body = guard_body();
        assert!(!body.contains('\''), "would close the remote single quotes");
        assert!(
            !body.contains('!'),
            "csh history-expands ! inside single quotes"
        );
        assert!(!body.contains('\n'), "csh rejects newlines in quoted words");
    }

    #[test]
    fn sudo_payload_is_password_marker_then_command() {
        let p = sudo_stdin_payload("pw", b"id -un");
        assert_eq!(p, b"pw\nprompto-sudo-ok\nid -un\n");
    }

    #[test]
    fn sudo_guarded_swaps_only_the_command() {
        let r = sudo_guarded("tee -- /etc/x >/dev/null");
        assert_eq!(
            r,
            SUDO_STDIN_SHELL.replace(
                "prompto-sudo sh -s",
                "prompto-sudo tee -- /etc/x >/dev/null"
            )
        );
    }

    /// The `sh -c` body, unquoted as the remote shell would.
    fn guard_body() -> &'static str {
        let start = SUDO_STDIN_SHELL.find("sh -c '").unwrap() + "sh -c '".len();
        let end = SUDO_STDIN_SHELL.rfind("' prompto-sudo").unwrap();
        &SUDO_STDIN_SHELL[start..end]
    }

    /// Run the guard locally under /bin/sh with `stdin`, as root's shell
    /// would after sudo, and with `sh -s` as the guarded command.
    fn run_guard(stdin: &[u8]) -> std::process::Output {
        use std::io::Write;
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", guard_body(), "prompto-sudo", "sh", "-s"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    }

    /// sudo took the password line: the guard sees the marker and the
    /// command runs.
    #[test]
    fn guard_runs_the_command_after_sudo_consumed_the_password() {
        let payload = sudo_stdin_payload("hunter2-canary", b"echo ran");
        // sudo -S eats the password line; the root shell sees the rest.
        let after_sudo = &payload["hunter2-canary\n".len()..];
        let out = run_guard(after_sudo);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "ran\n");
    }

    /// NOPASSWD: sudo never read stdin, so the guard reads the password
    /// itself. It must refuse, run nothing, and never print the password.
    #[test]
    fn guard_refuses_and_hides_password_under_nopasswd() {
        let out = run_guard(&sudo_stdin_payload("hunter2-canary", b"echo ran"));
        assert_eq!(out.status.code(), Some(SUDO_GUARD_EXIT), "{out:?}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stdout.contains("ran"), "command must not run");
        assert!(
            !stdout.contains("hunter2") && !stderr.contains("hunter2"),
            "leaked: {out:?}"
        );
        assert!(stderr.contains("passwordless sudo rule"), "{stderr}");
    }

    /// csh has no `export`: prefixing it there would turn every command
    /// on an OPNsense box into a "Command not found" plus whatever the
    /// rest does. Only `export` mode gets it, and that is the default only
    /// on platforms with a known POSIX login shell (see below).
    #[test]
    fn request_id_export_only_in_export_mode() {
        assert_eq!(
            request_id_export(RequestIdEnv::Export, "01ABC").as_deref(),
            Some("export PROMPTO_REQUEST_ID=01ABC; ")
        );
        for m in [RequestIdEnv::Setenv, RequestIdEnv::Off] {
            assert_eq!(request_id_export(m, "01ABC"), None);
        }
    }

    fn host(extra: &str) -> HostConfig {
        let toml = format!(
            "[host.h]\nip = \"192.0.2.5\"\nssh_user = \"u\"\nssh_key = \"/dev/null\"\n{extra}\n"
        );
        crate::inventory::Inventory::from_toml_str(&toml)
            .unwrap()
            .get("h")
            .unwrap()
            .clone()
    }

    /// ssh's argv for `remote` on a host configured with `extra`.
    fn argv(extra: &str) -> (Vec<String>, String) {
        let ctx = CallCtx::new(None);
        let client = SshClient::new("ssh".into(), Duration::from_secs(5));
        let args = client
            .ssh_args(&ctx, &host(extra), "uptime")
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        (args, ctx.request_id())
    }

    /// Unset `request_id_env` keeps today's behaviour: export + SetEnv on
    /// POSIX platforms, SetEnv alone on the others.
    #[test]
    fn request_id_env_defaults_follow_the_platform() {
        for (extra, export) in [
            ("", true),
            ("platform = \"macos\"", true),
            ("platform = \"freebsd\"", false),
            ("platform = \"windows\"", false),
        ] {
            let (args, rid) = argv(extra);
            assert!(
                args.contains(&format!("SetEnv=PROMPTO_REQUEST_ID={rid}")),
                "{extra}: {args:?}"
            );
            let want = if export {
                format!("export PROMPTO_REQUEST_ID={rid}; uptime")
            } else {
                "uptime".to_string()
            };
            assert_eq!(args.last().unwrap(), &want, "{extra}");
        }
    }

    /// `setenv` on a Linux host drops the prefix; `export` on FreeBSD
    /// (bash as login shell) adds it.
    #[test]
    fn request_id_env_overrides_the_platform_default() {
        let (args, rid) = argv("request_id_env = \"setenv\"");
        assert_eq!(args.last().unwrap(), "uptime");
        assert!(args.contains(&format!("SetEnv=PROMPTO_REQUEST_ID={rid}")));

        let (args, rid) = argv("platform = \"freebsd\"\nrequest_id_env = \"export\"");
        assert_eq!(
            args.last().unwrap(),
            &format!("export PROMPTO_REQUEST_ID={rid}; uptime")
        );
    }

    /// `off`: the command line is exactly the caller's, and no SetEnv —
    /// a `command=`/rrsync key must see nothing prompto added.
    #[test]
    fn request_id_env_off_adds_nothing() {
        let (args, _) = argv("request_id_env = \"off\"");
        assert_eq!(args.last().unwrap(), "uptime");
        assert!(
            !args.iter().any(|a| a.contains("PROMPTO_REQUEST_ID")),
            "{args:?}"
        );
        let ctx = CallCtx::new(None);
        assert_eq!(
            with_request_id(&ctx, &host("request_id_env = \"off\""), "sh -s"),
            "sh -s"
        );
    }

    /// The root shell on the vault path sees the ID even though sudo
    /// reset the environment: run the guard as root's shell would, with
    /// `with_request_id` in the guarded slot and an emptied environment.
    #[test]
    fn guard_passes_the_request_id_to_the_root_shell() {
        use std::io::Write;
        let ctx = CallCtx::new(None);
        let guarded = with_request_id(&ctx, &host(""), "sh -s");
        let mut child = std::process::Command::new("/bin/sh")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg("-c")
            .arg(guard_body())
            .arg("prompto-sudo")
            .args(guarded.split(' '))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"prompto-sudo-ok\necho $PROMPTO_REQUEST_ID\n")
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("{}\n", ctx.request_id()),
            "{out:?}"
        );
    }

    #[test]
    fn ok_requires_zero_exit_and_no_timeout() {
        let mut o = ExecOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(0),
            timed_out: false,
        };
        assert!(o.ok());
        o.exit_code = Some(1);
        assert!(!o.ok());
        o.exit_code = Some(0);
        o.timed_out = true;
        assert!(!o.ok());
        o.timed_out = false;
        o.exit_code = None;
        assert!(!o.ok());
    }
}
