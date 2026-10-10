//! `inv_check <inventory> [<policy.toml> <agents.toml>]`: check an
//! inventory, and with the two extra paths also lint the policy against
//! it (same checks as `prompto policy lint`). Exits 1 on any error.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let s = std::fs::read_to_string(&args[1]).unwrap();
    match prompto::inventory::Inventory::from_toml_str(&s) {
        Ok(inv) => {
            println!("LOADS OK — {} hosts", inv.hosts.len());
            let mut v: Vec<_> = inv.hosts.iter().collect();
            v.sort_by_key(|(n, _)| n.to_string());
            for (n, h) in v {
                let hv = h.hypervisor.clone().unwrap_or_default();
                let al = if h.aliases.is_empty() {
                    String::new()
                } else {
                    format!(" aka {:?}", h.aliases)
                };
                let groups = if h.groups.is_empty() {
                    String::new()
                } else {
                    format!(" groups {:?}", h.groups)
                };
                println!(
                    "  {:11} {:14} {:8} {:9} {:10} {}{}{}",
                    n,
                    h.ip.to_string(),
                    h.platform.as_str(),
                    h.chassis.as_str(),
                    hv,
                    h.capabilities
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                    al,
                    groups
                );
            }
            if let (Some(policy), Some(agents)) = (args.get(2), args.get(3)) {
                lint_policy(&inv, policy.as_ref(), agents.as_ref());
            }
        }
        Err(e) => {
            println!("REJECTED: {e:#}");
            std::process::exit(1);
        }
    }
}

fn lint_policy(inv: &prompto::Inventory, policy: &std::path::Path, agents: &std::path::Path) {
    let fail = |what: &str, e: anyhow::Error| -> ! {
        println!("{what} REJECTED: {e:#}");
        std::process::exit(1);
    };
    let p = prompto::policy::Policy::from_path(policy).unwrap_or_else(|e| fail("POLICY", e));
    let a = prompto::agent::Agents::from_path(agents).unwrap_or_else(|e| fail("AGENTS", e));
    let tools = prompto::mcp::Prompto::tool_names();
    let tools: Vec<&str> = tools.iter().map(String::as_str).collect();
    let findings = prompto::policy::lint(
        &p,
        inv,
        &a,
        &tools,
        &prompto::policy::service_user_from_env(),
    );
    if p.missing.is_some() {
        println!("POLICY MISSING — every call would be denied");
    }
    for f in &findings {
        println!("  {f}");
    }
    let errors = findings
        .iter()
        .filter(|f| f.level == prompto::policy::Level::Error)
        .count();
    println!(
        "POLICY {} rules, {errors} errors, {} warnings",
        p.rules.len(),
        findings.len() - errors
    );
    if errors > 0 {
        std::process::exit(1);
    }
}
