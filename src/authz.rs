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
//! 3. it is not the caller's own machine (`refused_self_target`) —
//!    **unconditionally**: no tool is exempt, and no policy (E3) or
//!    ticket (E6) can grant it;
//! 4. *(E3)* the agent's policy grants this tool on this host;
//! 5. *(E6)* a valid ticket accompanies the call where policy demands one.
//!
//! Steps 4 and 5 do not exist yet; the comments in [`authorize`] and
//! [`authorize_tool`] mark where they go. They come *after* step 3 on
//! purpose: the self-target guard is not a policy dimension, so nothing
//! a policy says can reach the code that would skip it.
//!
//! The only way to resolve a host without the guard is [`lookup`], for
//! tools that read the inventory and never contact the host
//! (`inventory_get_host`). There is no tool-name table: a new tool that
//! contacts a host calls [`authorize`] like every other one, and is
//! guarded without anyone having to remember it.

use crate::ctx::CallCtx;
use crate::error_class::{ClassifiedError, ErrorClass};
use crate::inventory::{Capability, HostConfig, Inventory};

/// What a tool needs from its target host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Need {
    /// The host must exist; no capability. For tools that contact the
    /// host without logging in (`host_status`, `port_scan`). Still
    /// self-target guarded.
    Exists,
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

/// Resolve `host_name` and check `need`, classifying the refusal.
fn resolve(inv: &Inventory, host_name: &str, need: Need) -> Result<Authorized, ClassifiedError> {
    let host = match need {
        Need::Exists => inv.get(host_name),
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
    Ok(Authorized {
        canonical: inv.canonical(host_name).unwrap_or(host_name).to_string(),
        host: host.clone(),
    })
}

/// Authorize `tool` against `host_name` for the call described by `ctx`.
/// Every tool that contacts a host — logs in, execs, copies files, sends
/// a packet or opens a TCP connection to it — goes through here.
///
/// On success returns the resolved host (cloned out of the snapshot, so
/// callers don't hold the inventory borrow). On failure returns a
/// [`ClassifiedError`] ("unknown host", "lacks capability", or the
/// self-target refusal, which tells the agent to use its local shell).
pub fn authorize(
    inv: &Inventory,
    ctx: &CallCtx,
    _tool: &str,
    host_name: &str,
    need: Need,
) -> Result<Authorized, ClassifiedError> {
    let target = resolve(inv, host_name, need)?;

    // `caller_ip` is None only on transports without addresses (stdio,
    // tests); that is the one way to skip the comparison. `ip` is an
    // `IpAddr`, so inventory content can never make it incomparable.
    // Both sides are canonicalized: an IPv4 client seen through a
    // dual-stack socket (or a proxy) as `::ffff:a.b.c.d` is the same
    // machine as `a.b.c.d`, and a plain `==` says it is not.
    if let Some(caller) = ctx.caller_ip
        && caller.to_canonical() == target.host.ip.to_canonical()
    {
        return Err(ClassifiedError::refused(
            ErrorClass::RefusedSelfTarget,
            format!(
                "refused_self_target: you are calling from {} ({}) — prompto never acts on \
                 the caller's own machine; run this in your local shell instead.",
                target.canonical,
                caller.to_canonical()
            ),
        ));
    }

    // E3 seam: policy check (ctx.agent × tool × canonical host) goes
    // here, refusing with `refused_policy` and naming the rule. Policy
    // can only narrow: it runs after the self-target guard and has no
    // way to undo it.
    // E6 seam: ticket verification goes here, after policy has said
    // whether one is required.

    Ok(target)
}

/// Resolve a host for a tool that only reads its inventory entry and
/// never contacts it (`inventory_get_host`). No self-target guard,
/// because nothing reaches the machine. Do not use this for anything
/// that opens a connection to the host — use [`authorize`].
pub fn lookup(
    inv: &Inventory,
    _ctx: &CallCtx,
    _tool: &str,
    host_name: &str,
) -> Result<Authorized, ClassifiedError> {
    // E3 seam: tool-level policy for inventory reads goes here.
    resolve(inv, host_name, Need::Exists)
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
        let r = authorize(&inv(), &ctx(None), "ssh_exec", "nope", Need::Exists);
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
    fn self_target_is_refused_with_an_actionable_message() {
        let r = authorize(
            &inv(),
            &ctx(Some("192.0.2.12")),
            "bash_exec",
            "a",
            Need::Cap(Capability::Exec),
        );
        let e = r.unwrap_err();
        assert_eq!(e.class, ErrorClass::RefusedSelfTarget);
        assert_eq!(
            e.message,
            "refused_self_target: you are calling from alpha (192.0.2.12) — prompto never \
             acts on the caller's own machine; run this in your local shell instead."
        );
    }

    /// No exemptions: tools that only probe from the outside are refused
    /// too, and so is a tool nobody has thought about yet.
    #[test]
    fn self_target_is_refused_for_every_tool() {
        for tool in [
            "host_status",
            "port_scan",
            "host_wake",
            "mcp_restart_claudecli",
            "some_future_tool",
        ] {
            let r = authorize(
                &inv(),
                &ctx(Some("192.0.2.12")),
                tool,
                "alpha",
                Need::Exists,
            );
            assert_eq!(class(r), ErrorClass::RefusedSelfTarget, "{tool}");
        }
    }

    /// `::ffff:a.b.c.d` is the IPv4 client `a.b.c.d` as a dual-stack
    /// socket or a proxy reports it; a plain `==` would let it through.
    #[test]
    fn ipv4_mapped_caller_is_the_same_machine() {
        let r = authorize(
            &inv(),
            &ctx(Some("::ffff:192.0.2.12")),
            "ssh_exec",
            "alpha",
            Need::Cap(Capability::Exec),
        );
        let e = r.unwrap_err();
        assert_eq!(e.class, ErrorClass::RefusedSelfTarget);
        assert!(e.message.contains("(192.0.2.12)"), "{}", e.message);
    }

    /// The other side: an inventory that spells the host's IP mapped.
    #[test]
    fn ipv4_mapped_inventory_ip_is_the_same_machine() {
        let inv = Inventory::from_toml_str(
            r#"
[host.mapped]
ip = "::ffff:192.0.2.12"
ssh_user = "u"
ssh_key = "/dev/null"
capabilities = ["exec"]
"#,
        )
        .unwrap();
        let r = authorize(
            &inv,
            &ctx(Some("192.0.2.12")),
            "ssh_exec",
            "mapped",
            Need::Cap(Capability::Exec),
        );
        assert_eq!(class(r), ErrorClass::RefusedSelfTarget);
    }

    #[test]
    fn a_different_caller_is_not_self_targeting() {
        for caller in ["192.0.2.13", "::ffff:192.0.2.13", "2001:db8::12"] {
            authorize(
                &inv(),
                &ctx(Some(caller)),
                "ssh_exec",
                "alpha",
                Need::Cap(Capability::Exec),
            )
            .unwrap_or_else(|e| panic!("{caller}: {}", e.message));
        }
    }

    /// `lookup` never contacts the host, so the caller may read its own
    /// inventory entry; existence is still checked.
    #[test]
    fn lookup_skips_the_guard_but_not_existence() {
        let a = lookup(&inv(), &ctx(Some("192.0.2.12")), "inventory_get_host", "a").unwrap();
        assert_eq!(a.canonical, "alpha");
        let r = lookup(&inv(), &ctx(None), "inventory_get_host", "nope");
        assert_eq!(class(r), ErrorClass::UnknownHost);
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
