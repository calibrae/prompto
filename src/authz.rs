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
//! 4. the agent's policy grants this tool on this host (`refused_policy`)
//!    — only when policy is on, i.e. `PROMPTO_AUTH` is `optional` or
//!    `required` (see `crate::policy`);
//! 5. where the granting rule has `approval = "ticket" | "human"`, the
//!    call carries a valid ticket for exactly this call
//!    (`crate::approval`): none is `approval_required`, a bad one
//!    `refused_ticket`.
//!
//! Policy and tickets come *after* step 3 on purpose: the self-target
//! guard is not a policy dimension, so nothing a policy or a ticket says
//! can reach the code that would skip it. A ticket only satisfies an
//! approval a rule demands; it never grants anything policy doesn't.
//!
//! Root-capable calls ([`is_root_capable`]) are a separate policy grant
//! from ordinary ones: a rule must say `sudo = true` to grant them. That
//! covers prompto's own root paths only — an exec grant
//! ([`ARBITRARY_EXEC_TOOLS`]) is a shell as `ssh_user`, which is root
//! wherever that user is root or has passwordless sudo.
//!
//! Steps 1–3 answer before policy does, so an agent with no grant at all
//! can still tell `unknown_host` from `refused_capability` from
//! `refused_self_target` — i.e. probe which names exist and what they
//! carry, though `inventory_list` hides hosts it has no grant on. That is
//! a known, accepted property: the self-target guard must stay
//! unconditional, which means it cannot wait for policy.
//!
//! The only way to resolve a host without the guard is [`lookup`], for
//! tools that read the inventory and never contact the host
//! (`inventory_get_host`). There is no tool-name table: a new tool that
//! contacts a host calls [`authorize`] like every other one, and is
//! guarded without anyone having to remember it.

use crate::ctx::CallCtx;
use crate::error_class::{ClassifiedError, ErrorClass};
use crate::inventory::{Capability, HostConfig, Inventory};
use crate::policy::Enforcer;

/// Tools that target no host. Policy matches them on agent and tool only.
pub const HOSTLESS_TOOLS: &[&str] = &["inventory_list", "prompto_gain", "mcp_reconnect_hint"];

/// Tools that are root-capable whatever their arguments, besides those
/// gated on `sudo_exec` (which run as root by definition). `vm_stop` can
/// destroy a domain, so it is held to the same separate grant.
pub const ROOT_TOOLS: &[&str] = &[
    "ssh_sudo_exec",
    "host_sleep",
    "service_control",
    "service_logs",
    "mcp_logs",
    "vm_stop",
];

/// Tools that are root-capable only with an argument (`sudo = true`).
pub const SUDO_FLAG_TOOLS: &[&str] = &["file_write"];

/// Tools that run whatever the caller sends on the host, with the
/// capability each needs there. They are ordinary calls (a `sudo = false`
/// rule grants them), but the code runs as the host's `ssh_user` — so on
/// a host where that user is root, or can `sudo` without a password, an
/// exec grant is a root grant in all but name. `sudo = true` gates only
/// prompto's own root paths; `policy::lint` warns about the rest.
pub const ARBITRARY_EXEC_TOOLS: &[(&str, Capability)] = &[
    ("ssh_exec", Capability::Exec),
    ("ssh_batch", Capability::Exec),
    ("bash_exec", Capability::Exec),
    ("python_exec", Capability::Exec),
    ("node_exec", Capability::Exec),
    ("ruby_exec", Capability::Exec),
    ("perl_exec", Capability::Exec),
    ("deno_exec", Capability::Exec),
    ("claude_exec", Capability::ClaudeExec),
    // A stdio server's command runs on the client whenever claude starts.
    ("mcp_add", Capability::ClaudeAdmin),
    // Writing a file the user's shell reads (~/.bashrc, ~/.ssh/rc, a
    // crontab, a systemd user unit) is code execution as ssh_user. Its
    // `sudo = true` variant is root-capable (`SUDO_FLAG_TOOLS`); this is
    // the other one.
    ("file_write", Capability::Exec),
    // The same, on the dest host: files land there as its ssh_user.
    ("rsync_sync", Capability::Exec),
];

/// Every other tool: neither root-capable nor arbitrary exec. Each tool
/// is in exactly one of [`ROOT_TOOLS`] ∪ [`SUDO_FLAG_TOOLS`],
/// [`ARBITRARY_EXEC_TOOLS`] and this list — except that a
/// [`SUDO_FLAG_TOOLS`] tool is also arbitrary exec without the flag
/// (`file_write`). A test fails on a tool that isn't, so a new tool can't
/// fall under `tools = ["*"]` unclassified.
pub const ORDINARY_TOOLS: &[&str] = &[
    "host_wake",
    "host_status",
    "host_diagnose",
    "vm_list",
    "vm_state",
    "vm_start",
    "vm_ensure_up",
    "file_read",
    "file_list",
    "file_stat",
    "port_scan",
    "inventory_list",
    "inventory_get_host",
    "mcp_list",
    "mcp_get",
    "mcp_remove",
    "mcp_restart_claudecli",
    "mcp_status",
    "mcp_reconnect_hint",
    "prompto_gain",
];

/// Whether `tool` runs arbitrary caller-supplied code
/// ([`ARBITRARY_EXEC_TOOLS`]).
pub fn is_arbitrary_exec(tool: &str) -> bool {
    ARBITRARY_EXEC_TOOLS.iter().any(|(t, _)| *t == tool)
}

/// Whether a call is root-capable, i.e. needs a `sudo = true` policy
/// rule. Everything gated on the `sudo_exec` capability runs something
/// as root on the host, so `need` alone covers `ssh_sudo_exec`,
/// `file_write` with `sudo = true`, `service_control`, `host_sleep` and
/// the journal readers; [`ROOT_TOOLS`] adds the ones that aren't gated
/// on it (`vm_stop`).
pub fn is_root_capable(tool: &str, need: Need) -> bool {
    need == Need::Cap(Capability::SudoExec) || ROOT_TOOLS.contains(&tool)
}

/// The root-capability values a call to `tool` can have — for
/// enumerating calls (`policy::lint`, `prompto policy check`).
pub fn root_variants(tool: &str) -> &'static [bool] {
    if ROOT_TOOLS.contains(&tool) {
        &[true]
    } else if SUDO_FLAG_TOOLS.contains(&tool) {
        &[false, true]
    } else {
        &[false]
    }
}

/// The authorizations a call makes, read off its tool and arguments:
/// what `POST /v1/precheck` evaluates without running anything, and
/// which hosts a ticket binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Requirements {
    /// Targets no host ([`HOSTLESS_TOOLS`]): [`authorize_tool`].
    Hostless,
    /// Reads the inventory entry named by this argument: [`lookup`].
    Lookup(&'static str),
    /// [`authorize`] against the host named by each argument, in order.
    /// The first is the call's host, the second (`rsync_sync`) its
    /// `dest_host`.
    Hosts(Vec<(&'static str, Need)>),
}

/// The authorizations `tool` makes with `args`, exactly as its handler in
/// `crate::mcp` makes them (a test drives every tool through both and
/// fails on any difference). `None` for an unknown tool.
///
/// `vm_ensure_up` also needs `wake`, but only if the host turns out to be
/// down, and its handler enforces that only then; precheck can't know, so
/// it is not listed (policy for it is the same tool and host anyway).
pub fn requirements(tool: &str, args: &serde_json::Value) -> Option<Requirements> {
    use Capability::*;
    let host = |need| Some(Requirements::Hosts(vec![("host", need)]));
    match tool {
        "inventory_list" | "prompto_gain" | "mcp_reconnect_hint" => Some(Requirements::Hostless),
        "inventory_get_host" => Some(Requirements::Lookup("name")),
        "host_status" | "port_scan" => host(Need::Exists),
        "host_wake" => host(Need::Cap(Wake)),
        "host_sleep" | "ssh_sudo_exec" | "service_control" | "service_logs" | "mcp_logs" => {
            host(Need::Cap(SudoExec))
        }
        "vm_list" | "vm_state" | "vm_start" | "vm_stop" | "vm_ensure_up" => host(Need::Cap(Virt)),
        "ssh_exec" | "ssh_batch" | "python_exec" | "node_exec" | "ruby_exec" | "perl_exec"
        | "deno_exec" | "bash_exec" | "file_list" | "file_stat" | "file_read" | "host_diagnose" => {
            host(Need::Cap(Exec))
        }
        "file_write" => {
            let sudo = args.get("sudo").and_then(|v| v.as_bool()).unwrap_or(false);
            host(Need::Cap(if sudo { SudoExec } else { Exec }))
        }
        "claude_exec" => host(Need::Cap(ClaudeExec)),
        "mcp_list"
        | "mcp_get"
        | "mcp_add"
        | "mcp_remove"
        | "mcp_restart_claudecli"
        | "mcp_status" => Some(Requirements::Hosts(vec![(
            "client",
            Need::Cap(ClaudeAdmin),
        )])),
        "rsync_sync" => Some(Requirements::Hosts(vec![
            ("source_host", Need::Cap(Exec)),
            ("dest_host", Need::Cap(Exec)),
        ])),
        _ => None,
    }
}

/// The hosts a ticket for this call binds: `(host, dest_host)`, each the
/// canonical inventory name of what the call names (or the name as typed
/// when it is no inventory host; such a call is refused before tickets
/// matter).
pub fn bound_hosts(
    tool: &str,
    args: &serde_json::Value,
    inv: Option<&Inventory>,
) -> (Option<String>, Option<String>) {
    let canon = |field: &str| {
        let name = args.get(field)?.as_str()?;
        Some(
            inv.and_then(|i| i.canonical(name))
                .unwrap_or(name)
                .to_string(),
        )
    };
    match requirements(tool, args) {
        Some(Requirements::Lookup(f)) => (canon(f), None),
        Some(Requirements::Hosts(v)) => (
            v.first().and_then(|(f, _)| canon(f)),
            v.get(1).and_then(|(f, _)| canon(f)),
        ),
        Some(Requirements::Hostless) | None => (None, None),
    }
}

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
    /// The policy rule that allowed the call; `None` when policy is off.
    pub rule: Option<String>,
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
        rule: None,
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
///
/// `policy` is `None` with `PROMPTO_AUTH=off`, which skips step 4.
pub fn authorize(
    inv: &Inventory,
    policy: Option<&Enforcer>,
    ctx: &CallCtx,
    tool: &str,
    host_name: &str,
    need: Need,
) -> Result<Authorized, ClassifiedError> {
    let mut target = resolve(inv, host_name, need)?;

    // `caller_ip` is None only on transports without addresses (stdio,
    // tests); that is the one way to skip the comparison. `ip` is an
    // `IpAddr`, so inventory content can never make it incomparable.
    // Both sides are canonicalized: an IPv4 client seen through a
    // dual-stack socket (or a proxy) as `::ffff:a.b.c.d` is the same
    // machine as `a.b.c.d`, and a plain `==` says it is not.
    // `extra_ips` (the machine's other NICs, VPN, IPv6) count too.
    if let Some(caller) = ctx.caller_ip
        && target.host.is_own_address(caller)
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

    // Policy can only narrow: it runs after the self-target guard and
    // has no way to undo it. Then the ticket, where the rule wants one.
    if let Some(p) = policy {
        let root = is_root_capable(tool, need);
        let grant = p.check(ctx, tool, Some((&target.canonical, &target.host)), root)?;
        approve(
            p,
            Some(inv),
            ctx,
            tool,
            &grant,
            Some(&target.canonical),
            root,
        )?;
        target.rule = Some(grant.rule);
    }

    Ok(target)
}

/// Resolve a host for a tool that only reads its inventory entry and
/// never contacts it (`inventory_get_host`). No self-target guard,
/// because nothing reaches the machine. Do not use this for anything
/// that opens a connection to the host — use [`authorize`].
/// Policy still applies, against the looked-up host.
pub fn lookup(
    inv: &Inventory,
    policy: Option<&Enforcer>,
    ctx: &CallCtx,
    tool: &str,
    host_name: &str,
) -> Result<Authorized, ClassifiedError> {
    let mut target = resolve(inv, host_name, Need::Exists)?;
    if let Some(p) = policy {
        let grant = p.check(ctx, tool, Some((&target.canonical, &target.host)), false)?;
        approve(
            p,
            Some(inv),
            ctx,
            tool,
            &grant,
            Some(&target.canonical),
            false,
        )?;
        target.rule = Some(grant.rule);
    }
    Ok(target)
}

/// Authorize a tool that targets no host (`inventory_list`,
/// `prompto_gain`, `mcp_reconnect_hint`): policy on agent × tool. Returns
/// the allowing rule (`None` with policy off).
pub fn authorize_tool(
    policy: Option<&Enforcer>,
    ctx: &CallCtx,
    tool: &str,
) -> Result<Option<String>, ClassifiedError> {
    let Some(p) = policy else { return Ok(None) };
    let grant = p.check(ctx, tool, None, false)?;
    approve(p, None, ctx, tool, &grant, None, false)?;
    Ok(Some(grant.rule))
}

/// Step 5: the ticket, when the granting rule demands an approval.
/// `root`: the call is root-capable (a scoped ticket is bound to it).
fn approve(
    p: &Enforcer,
    inv: Option<&Inventory>,
    ctx: &CallCtx,
    tool: &str,
    grant: &crate::policy::Grant,
    on: Option<&str>,
    root: bool,
) -> Result<(), ClassifiedError> {
    if grant.approval == crate::policy::Approval::None {
        return Ok(());
    }
    let demand = crate::approval::Demand {
        rule: grant.rule.clone(),
        root,
    };
    ctx.note(|n| n.demands.push(demand.clone()));
    p.approvals
        .require(inv, ctx, tool, &demand, on, grant.approval)
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
            None,
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
        let r = authorize(&inv(), None, &ctx(None), "ssh_exec", "nope", Need::Exists);
        assert_eq!(class(r), ErrorClass::UnknownHost);
    }

    #[test]
    fn missing_capability_is_classified() {
        let r = authorize(
            &inv(),
            None,
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
            None,
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
                None,
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
            None,
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
            None,
            &ctx(Some("192.0.2.12")),
            "ssh_exec",
            "mapped",
            Need::Cap(Capability::Exec),
        );
        assert_eq!(class(r), ErrorClass::RefusedSelfTarget);
    }

    /// A machine calling from its Wi-Fi, VPN or IPv6 address is still
    /// itself: every `extra_ips` entry is compared, mapped or not.
    #[test]
    fn extra_ips_are_the_same_machine() {
        let inv = Inventory::from_toml_str(
            r#"
[host.laptop]
ip = "192.0.2.12"
extra_ips = ["198.51.100.4", "2001:db8::4", "::ffff:203.0.113.4"]
ssh_user = "u"
ssh_key = "/dev/null"
capabilities = ["exec"]
"#,
        )
        .unwrap();
        for caller in [
            "198.51.100.4",
            "::ffff:198.51.100.4",
            "2001:db8::4",
            "203.0.113.4",
        ] {
            let e = authorize(
                &inv,
                None,
                &ctx(Some(caller)),
                "ssh_exec",
                "laptop",
                Need::Cap(Capability::Exec),
            )
            .expect_err(caller);
            assert_eq!(e.class, ErrorClass::RefusedSelfTarget, "{caller}");
        }
        authorize(
            &inv,
            None,
            &ctx(Some("198.51.100.5")),
            "ssh_exec",
            "laptop",
            Need::Cap(Capability::Exec),
        )
        .unwrap();
    }

    #[test]
    fn a_different_caller_is_not_self_targeting() {
        for caller in ["192.0.2.13", "::ffff:192.0.2.13", "2001:db8::12"] {
            authorize(
                &inv(),
                None,
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
        let a = lookup(
            &inv(),
            None,
            &ctx(Some("192.0.2.12")),
            "inventory_get_host",
            "a",
        )
        .unwrap();
        assert_eq!(a.canonical, "alpha");
        let r = lookup(&inv(), None, &ctx(None), "inventory_get_host", "nope");
        assert_eq!(class(r), ErrorClass::UnknownHost);
    }

    #[test]
    fn capability_is_checked_before_self_target() {
        let r = authorize(
            &inv(),
            None,
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
            None,
            &ctx(None),
            "ssh_exec",
            "alpha",
            Need::Cap(Capability::Exec),
        )
        .unwrap();
    }

    // ----- policy (E3) -----

    use crate::policy::{Enforcer, Policy, PolicyStore};

    const ALLOW_ALL: &str = "[[rule]]\nagents = [\"anonymous\"]\nhosts = [\"*\"]\ntools = [\"*\"]\n\
                             [[rule]]\nagents = [\"anonymous\"]\nhosts = [\"*\"]\ntools = [\"*\"]\nsudo = true\n";
    const NO_ROOT: &str = "[[rule]]\nagents = [\"anonymous\"]\nhosts = [\"*\"]\ntools = [\"*\"]\n";

    fn enforcer(policy: &str) -> Enforcer {
        Enforcer {
            policy: PolicyStore::new(Policy::from_toml_str(policy, "policy.toml").unwrap(), None),
            agents: Default::default(),
            approvals: Default::default(),
        }
    }

    fn anon(ip: Option<&str>) -> CallCtx {
        ctx(ip).with_identity(crate::agent::Identity::anonymous(None))
    }

    fn sudo_inv() -> Inventory {
        Inventory::from_toml_str(
            "[host.alpha]\nip = \"192.0.2.12\"\nssh_user = \"u\"\nssh_key = \"/k\"\n\
             capabilities = [\"exec\", \"sudo_exec\", \"virt\"]\n",
        )
        .unwrap()
    }

    /// S3.3b: no rule can grant the caller's own machine. The guard runs
    /// before policy, so even allow-everything refuses it.
    #[test]
    fn policy_cannot_grant_self_target() {
        let p = enforcer(ALLOW_ALL);
        let r = authorize(
            &sudo_inv(),
            Some(&p),
            &anon(Some("192.0.2.12")),
            "ssh_sudo_exec",
            "alpha",
            Need::Cap(Capability::SudoExec),
        );
        assert_eq!(class(r), ErrorClass::RefusedSelfTarget);
    }

    /// Effective permission = policy ∩ capability: allow-everything does
    /// not lend a host a capability it lacks.
    #[test]
    fn policy_cannot_grant_a_missing_capability() {
        let r = authorize(
            &inv(),
            Some(&enforcer(ALLOW_ALL)),
            &anon(None),
            "ssh_exec",
            "bravo",
            Need::Cap(Capability::Exec),
        );
        assert_eq!(class(r), ErrorClass::RefusedCapability);
    }

    #[test]
    fn policy_decides_after_the_other_checks_and_names_its_rule() {
        let a = authorize(
            &inv(),
            Some(&enforcer(ALLOW_ALL)),
            &anon(Some("10.0.0.1")),
            "ssh_exec",
            "a",
            Need::Cap(Capability::Exec),
        )
        .unwrap();
        assert_eq!(a.rule.as_deref(), Some("policy.toml:1"));
        let e = authorize(
            &inv(),
            Some(&enforcer("")),
            &anon(Some("10.0.0.1")),
            "ssh_exec",
            "a",
            Need::Cap(Capability::Exec),
        )
        .unwrap_err();
        assert_eq!(e.class, ErrorClass::RefusedPolicy);
        assert_eq!(e.rule.as_deref(), Some(crate::policy::DEFAULT_DENY));
        assert!(
            e.message
                .contains("agent anonymous has no grant for ssh_exec on alpha"),
            "{}",
            e.message
        );
        // Policy off: no rule, no refusal.
        let a = authorize(
            &inv(),
            None,
            &anon(None),
            "ssh_exec",
            "a",
            Need::Cap(Capability::Exec),
        )
        .unwrap();
        assert_eq!(a.rule, None);
    }

    #[test]
    fn root_capable_calls_are_derived_from_need_and_tool() {
        assert!(is_root_capable(
            "file_write",
            Need::Cap(Capability::SudoExec)
        ));
        assert!(!is_root_capable("file_write", Need::Cap(Capability::Exec)));
        assert!(is_root_capable("vm_stop", Need::Cap(Capability::Virt)));
        assert!(is_root_capable(
            "some_future_tool",
            Need::Cap(Capability::SudoExec)
        ));
        assert!(!is_root_capable("ssh_exec", Need::Cap(Capability::Exec)));
        assert!(!is_root_capable("host_status", Need::Exists));
    }

    /// The separate sudo grant, through `authorize`: a rule granting
    /// every tool without `sudo = true` grants no root-capable call.
    #[test]
    fn a_grant_without_sudo_grants_no_root_capable_call() {
        let p = enforcer(NO_ROOT);
        let (inv, ctx) = (sudo_inv(), anon(None));
        let go = |tool: &str, need| authorize(&inv, Some(&p), &ctx, tool, "alpha", need);
        go("ssh_exec", Need::Cap(Capability::Exec)).unwrap();
        go("file_write", Need::Cap(Capability::Exec)).unwrap();
        go("vm_list", Need::Cap(Capability::Virt)).unwrap();
        for (tool, need) in [
            ("ssh_sudo_exec", Need::Cap(Capability::SudoExec)),
            ("file_write", Need::Cap(Capability::SudoExec)),
            ("service_control", Need::Cap(Capability::SudoExec)),
            ("host_sleep", Need::Cap(Capability::SudoExec)),
            ("vm_stop", Need::Cap(Capability::Virt)),
        ] {
            let e = go(tool, need).unwrap_err();
            assert_eq!(e.class, ErrorClass::RefusedPolicy, "{tool}");
            assert!(e.message.contains("root-capable"), "{tool}: {}", e.message);
        }
    }

    #[test]
    fn hostless_and_lookup_tools_pass_policy() {
        let deny = enforcer("");
        let e = authorize_tool(Some(&deny), &anon(None), "prompto_gain").unwrap_err();
        assert_eq!(e.class, ErrorClass::RefusedPolicy);
        let e = lookup(&inv(), Some(&deny), &anon(None), "inventory_get_host", "a").unwrap_err();
        assert_eq!(e.class, ErrorClass::RefusedPolicy);
        let allow = enforcer(NO_ROOT);
        assert_eq!(
            authorize_tool(Some(&allow), &anon(None), "prompto_gain").unwrap(),
            Some("policy.toml:1".into())
        );
        assert_eq!(
            authorize_tool(None, &anon(None), "prompto_gain").unwrap(),
            None
        );
        lookup(&inv(), Some(&allow), &anon(None), "inventory_get_host", "a").unwrap();
    }
}
