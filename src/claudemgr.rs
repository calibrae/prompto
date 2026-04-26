//! Wrappers around the `claude mcp …` CLI on remote clients.
//!
//! prompto's host doesn't necessarily carry a `claude` binary, but other
//! machines in the inventory often do (npm-installed on macOS, etc.). Each
//! tool here just shells out to `claude mcp …` over SSH using the existing
//! [`SshClient`].
//!
//! Affects the on-disk `~/.claude.json` of the targeted client. *Does not
//! reconnect any currently-running session* — interactive Claude Code
//! sessions cache their MCP config and only re-handshake on `/mcp` or
//! restart. Maximum effect is on stateless callers like `claude -p` (every
//! invocation re-reads the config), which is exactly the Telegram-via-
//! claudecli use case.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::inventory::HostConfig;
use crate::ssh::SshClient;

/// Validate args that flow into the remote `claude mcp …` invocation. The
/// command is assembled and interpolated server-side, so reject anything
/// that could break out of the argv. Mirror the rule used for VM names —
/// alphanumerics + `_`/`-`/`.`/`:`/`/`/`@` are enough for plausible MCP
/// names, scopes, and URLs without opening shell injection.
pub fn validate_token(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("{field} is empty");
    }
    if value.len() > 256 {
        bail!("{field} too long");
    }
    let ok = value.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '_' | '-' | '.' | ':' | '/' | '@' | '?' | '=' | '&' | '%' | '+'
            )
    });
    if !ok {
        bail!("{field} {value:?} contains illegal characters");
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    User,
    Project,
    Local,
}

impl Scope {
    pub fn as_arg(&self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::Project => "project",
            Scope::Local => "local",
        }
    }
}

/// Default timeout for `claude mcp` calls. The CLI is fast; 10 s is a
/// generous ceiling that catches a hanging SSH pipe but doesn't make
/// agents wait on a happy-path call.
fn cmd_timeout() -> Duration {
    Duration::from_secs(10)
}

/// Build the `PATH=… claude mcp …` shell command. We prepend a sane PATH
/// because non-interactive SSH on macOS doesn't load the user's shell rc.
fn wrap(remote: &str) -> String {
    format!(
        r#"PATH="$HOME/.local/bin:$HOME/.npm-global/bin:/opt/homebrew/bin:/usr/local/bin:$PATH" {remote}"#
    )
}

pub async fn list(ssh: &SshClient, host: &HostConfig) -> Result<String> {
    let cmd = wrap("claude mcp list");
    let res = ssh.exec(host, &cmd, Some(cmd_timeout()), false).await?;
    if !res.ok() {
        bail!(
            "claude mcp list failed (exit={:?}): {}",
            res.exit_code,
            res.stderr.trim()
        );
    }
    Ok(res.stdout)
}

pub async fn get(ssh: &SshClient, host: &HostConfig, name: &str) -> Result<String> {
    validate_token("name", name)?;
    let cmd = wrap(&format!("claude mcp get {name}"));
    let res = ssh.exec(host, &cmd, Some(cmd_timeout()), false).await?;
    if !res.ok() {
        bail!(
            "claude mcp get {name} failed (exit={:?}): {}",
            res.exit_code,
            res.stderr.trim()
        );
    }
    Ok(res.stdout)
}

pub async fn add(
    ssh: &SshClient,
    host: &HostConfig,
    name: &str,
    transport: &str,
    url_or_cmd: &str,
    scope: Scope,
) -> Result<String> {
    validate_token("name", name)?;
    validate_token("transport", transport)?;
    validate_token("url_or_cmd", url_or_cmd)?;
    let cmd = wrap(&format!(
        "claude mcp add --transport {transport} --scope {} {name} {url_or_cmd}",
        scope.as_arg()
    ));
    let res = ssh.exec(host, &cmd, Some(cmd_timeout()), false).await?;
    if !res.ok() {
        bail!(
            "claude mcp add {name} failed (exit={:?}): {} / {}",
            res.exit_code,
            res.stdout.trim(),
            res.stderr.trim()
        );
    }
    Ok(format!("{}\n{}", res.stdout.trim(), res.stderr.trim())
        .trim()
        .to_string())
}

pub async fn remove(
    ssh: &SshClient,
    host: &HostConfig,
    name: &str,
    scope: Scope,
) -> Result<String> {
    validate_token("name", name)?;
    let cmd = wrap(&format!(
        "claude mcp remove --scope {} {name}",
        scope.as_arg()
    ));
    let res = ssh.exec(host, &cmd, Some(cmd_timeout()), false).await?;
    if !res.ok() {
        bail!(
            "claude mcp remove {name} failed (exit={:?}): {}",
            res.exit_code,
            res.stderr.trim()
        );
    }
    Ok(res.stdout.trim().to_string())
}

/// Restart claudecli (the Telegram bridge) on a host. Best-effort: tries
/// `systemctl --user restart claudecli` first, then falls back to
/// re-spawning the tmux session if that fails. Caller should accept either
/// form of success.
pub async fn restart_claudecli(ssh: &SshClient, host: &HostConfig) -> Result<String> {
    // Try systemd --user first.
    let cmd1 = "systemctl --user restart claudecli 2>&1 && echo OK_SYSTEMD || true";
    let r1 = ssh.exec(host, cmd1, Some(cmd_timeout()), false).await?;
    if r1.stdout.contains("OK_SYSTEMD") {
        return Ok("restarted via systemctl --user".to_string());
    }
    // Fallback: kill any existing tmux session named "claudecli" and respawn it.
    let cmd2 = wrap(
        r#"tmux kill-session -t claudecli 2>/dev/null; \
           tmux new-session -d -s claudecli "cd ~/Developer/perso/claudecli && npm start" 2>&1 \
           && echo OK_TMUX || echo FAIL"#,
    );
    let r2 = ssh.exec(host, &cmd2, Some(cmd_timeout()), false).await?;
    if r2.stdout.contains("OK_TMUX") {
        Ok("restarted via tmux".to_string())
    } else {
        bail!(
            "could not restart claudecli (systemd: {}, tmux: {})",
            r1.stderr.trim(),
            r2.stderr.trim()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_token_accepts_normal_inputs() {
        validate_token("name", "memqdrant").unwrap();
        validate_token("url", "http://192.0.2.3:6335/mcp").unwrap();
        validate_token("name", "my-server.v2").unwrap();
        validate_token("name", "user@host:port").unwrap();
    }

    #[test]
    fn validate_token_rejects_shell_injection() {
        assert!(validate_token("name", "x; rm -rf /").is_err());
        assert!(validate_token("name", "x`whoami`").is_err());
        assert!(validate_token("name", "x$(id)").is_err());
        assert!(validate_token("name", "x|cat").is_err());
        assert!(validate_token("name", "x>foo").is_err());
        assert!(validate_token("name", "x\nfoo").is_err());
        assert!(validate_token("name", "").is_err());
        assert!(validate_token("name", " ").is_err());
        assert!(validate_token("name", &"x".repeat(300)).is_err());
    }

    #[test]
    fn scope_arg_is_lowercase() {
        assert_eq!(Scope::User.as_arg(), "user");
        assert_eq!(Scope::Project.as_arg(), "project");
        assert_eq!(Scope::Local.as_arg(), "local");
    }
}
