//! Central authorization: the one gate every tool call passes before it
//! touches a host.
//!
//! Until v0.11 each handler did its own `inv.require*` inline, and only
//! three of them (`ssh_exec`, `ssh_batch`, `ssh_sudo_exec`) remembered
//! the self-targeting guard — `bash_exec`, `file_write` and friends
//! reached the caller's own box unguarded. [`authorize`] does the checks
//! in one place, in a fixed order, and returns classified refusals:
//!
//! 1. the host exists (`unknown_host`);
//! 2. it carries the capability the tool needs (`refused_capability`);
//! 3. it is not the caller's own machine, unless the tool is listed in
//!    [`self_target_exemption`] (`refused_self_target`);
//! 4. *(E3)* the agent's policy grants this tool on this host;
//! 5. *(E6)* a valid ticket accompanies the call where policy demands one.
//!
//! Steps 4 and 5 do not exist yet; the comments in [`authorize`] and
//! [`authorize_tool`] mark where they go.

use crate::ctx::CallCtx;
use crate::error_class::{ClassifiedError, ErrorClass};
use crate::inventory::{Capability, HostConfig, Inventory};

/// What a tool needs from its target host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Need {
    /// The host must exist; no capability. For tools that only read the
    /// inventory or probe from the outside (`host_status`, `port_scan`).
    Lookup,
    /// The host must grant this capability.
    Cap(Capability),
}

/// A host the call may use, as resolved from the inventory.
#[derive(Clone, Debug)]
pub struct Authorized {
    /// Inventory name, with any alias resolved.
    pub canonical: String,
    pub host: HostConfig,
}

/// Tools allowed to target the caller's own machine, and why. Every
/// other tool — including any tool added later and not listed here — is
/// refused when the target's IP is the caller's IP.
///
/// The guard exists because an agent asking prompto to reach its own box
/// is either wasting a round trip (it has a local shell) or escaping its
/// local sandbox: prompto's session runs as the inventory's `ssh_user`,
/// with sudo where granted, sidestepping whatever confines the agent
/// (and, on prompto's own host, prompto's systemd hardening). The tools
/// below either never log into the host, or are a documented
/// self-management path with no caller-supplied command.
pub fn self_target_exemption(tool: &str) -> Option<&'static str> {
    Some(match tool {
        // No login on the host: a WOL packet, TCP connects, or the
        // inventory. Waking a running box is a no-op; probing your own
        // ports *from prompto* is a legitimate reachability check that
        // a local shell cannot do.
        "host_wake" => "sends a WOL packet; never logs into the host",
        "host_status" => "TCP connect to the SSH port; never logs in",
        "port_scan" => "TCP connects from prompto's vantage point; never logs in",
        "inventory_get_host" => "reads the inventory only",
        // A claude_admin client managing its own Claude Code is what the
        // mcp_* family is for: mcp_reconnect_hint tells an agent behind
        // claudecli to call mcp_restart_claudecli on its own client, and
        // to run mcp_status on it first. These run fixed, prompto-built
        // commands with no caller-supplied shell text.
        //
        // mcp_add / mcp_remove are deliberately NOT here: registering a
        // stdio MCP server is registering a command that the next Claude
        // session runs, i.e. persistence on the caller's own box outside
        // its sandbox.
        "mcp_list" | "mcp_get" | "mcp_status" => {
            "read-only view of the client's own Claude Code MCP config"
        }
        "mcp_restart_claudecli" => {
            "documented self-restart path for claudecli (see mcp_reconnect_hint)"
        }
        _ => return None,
    })
}

/// Authorize `tool` against `host_name` for the call described by `ctx`.
///
/// On success returns the resolved host (cloned out of the snapshot, so
/// callers don't hold the inventory borrow). On failure returns a
/// [`ClassifiedError`] whose message keeps the wording the inline checks
/// used ("unknown host", "lacks capability", "calling agent's own host").
pub fn authorize(
    inv: &Inventory,
    ctx: &CallCtx,
    tool: &str,
    host_name: &str,
    need: Need,
) -> Result<Authorized, ClassifiedError> {
    let host = match need {
        Need::Lookup => inv.get(host_name),
        Need::Cap(cap) => inv.require(host_name, cap),
    }
    .map_err(|e| {
        let class = if inv.get(host_name).is_err() {
            ErrorClass::UnknownHost
        } else {
            ErrorClass::RefusedCapability
        };
        ClassifiedError::refused(class, e)
    })?;

    // `caller_ip` is None only on transports without addresses (stdio,
    // tests); that is the one way to skip the comparison. `ip` is an
    // `IpAddr`, so inventory content can never make it incomparable.
    if let Some(caller) = ctx.caller_ip
        && caller == host.ip
        && self_target_exemption(tool).is_none()
    {
        return Err(ClassifiedError::refused(
            ErrorClass::RefusedSelfTarget,
            format!(
                "refused: target {host_name:?} is the calling agent's own host (source IP {caller}). \
                 Use your local shell tool instead — routing a same-host call through prompto \
                 wastes a round trip and bypasses any local sandboxing."
            ),
        ));
    }

    // E3 seam: policy check (ctx.agent × tool × canonical host) goes
    // here, refusing with `refused_policy` and naming the rule.
    // E6 seam: ticket verification goes here, after policy has said
    // whether one is required.

    Ok(Authorized {
        canonical: inv.canonical(host_name).unwrap_or(host_name).to_string(),
        host: host.clone(),
    })
}

/// Authorize a tool that targets no host (`inventory_list`,
/// `prompto_gain`, `mcp_reconnect_hint`). Nothing to check today; it is
/// called anyway so that every tool passes through this module.
pub fn authorize_tool(_ctx: &CallCtx, _tool: &str) -> Result<(), ClassifiedError> {
    // E3 seam: tool-level policy (agent × tool, no host) goes here.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const INV: &str = r#"
[host.alpha]
ip = "192.0.2.12"
ssh_user = "u"
ssh_key = "/dev/null"
aliases = ["a"]
capabilities = ["exec"]

[host.bravo]
ip = "192.0.2.13"
ssh_user = "u"
ssh_key = "/dev/null"
capabilities = []
"#;

    fn inv() -> Inventory {
        Inventory::from_toml_str(INV).unwrap()
    }

    fn ctx(ip: Option<&str>) -> CallCtx {
        CallCtx::new(ip.map(|s| s.parse().unwrap()))
    }

    fn class(r: Result<Authorized, ClassifiedError>) -> ErrorClass {
        r.expect_err("expected a refusal").class
    }

    #[test]
    fn allows_and_resolves_alias_to_canonical() {
        let a = authorize(
            &inv(),
            &ctx(Some("10.0.0.1")),
            "ssh_exec",
            "a",
            Need::Cap(Capability::Exec),
        )
        .unwrap();
        assert_eq!(a.canonical, "alpha");
    }

    #[test]
    fn unknown_host_is_classified() {
        let r = authorize(&inv(), &ctx(None), "ssh_exec", "nope", Need::Lookup);
        assert_eq!(class(r), ErrorClass::UnknownHost);
    }

    #[test]
    fn missing_capability_is_classified() {
        let r = authorize(
            &inv(),
            &ctx(None),
            "ssh_exec",
            "bravo",
            Need::Cap(Capability::Exec),
        );
        let e = r.unwrap_err();
        assert_eq!(e.class, ErrorClass::RefusedCapability);
        assert!(e.message.contains("lacks capability"), "{}", e.message);
    }

    #[test]
    fn self_target_is_refused_for_an_unlisted_tool() {
        let r = authorize(
            &inv(),
            &ctx(Some("192.0.2.12")),
            "bash_exec",
            "alpha",
            Need::Cap(Capability::Exec),
        );
        let e = r.unwrap_err();
        assert_eq!(e.class, ErrorClass::RefusedSelfTarget);
        assert!(e.message.contains("calling agent's own host"));
    }

    /// Fail closed: a tool nobody thought about is guarded.
    #[test]
    fn unknown_tool_names_are_not_exempt() {
        assert!(self_target_exemption("some_future_tool").is_none());
        let r = authorize(
            &inv(),
            &ctx(Some("192.0.2.12")),
            "some_future_tool",
            "alpha",
            Need::Lookup,
        );
        assert_eq!(class(r), ErrorClass::RefusedSelfTarget);
    }

    #[test]
    fn exempt_tools_may_target_the_caller() {
        authorize(
            &inv(),
            &ctx(Some("192.0.2.12")),
            "host_status",
            "alpha",
            Need::Lookup,
        )
        .unwrap();
    }

    #[test]
    fn capability_is_checked_before_self_target() {
        let r = authorize(
            &inv(),
            &ctx(Some("192.0.2.13")),
            "ssh_exec",
            "bravo",
            Need::Cap(Capability::Exec),
        );
        assert_eq!(class(r), ErrorClass::RefusedCapability);
    }

    #[test]
    fn no_caller_ip_skips_only_the_self_target_check() {
        authorize(
            &inv(),
            &ctx(None),
            "ssh_exec",
            "alpha",
            Need::Cap(Capability::Exec),
        )
        .unwrap();
    }
}
