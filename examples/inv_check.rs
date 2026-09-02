fn main() {
    let s = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    match prompto::inventory::Inventory::from_toml_str(&s) {
        Ok(inv) => {
            println!("LOADS OK — {} hosts", inv.hosts.len());
            let mut v: Vec<_> = inv.hosts.iter().collect();
            v.sort_by_key(|(n, _)| n.to_string());
            for (n, h) in v {
                let hv = h.hypervisor.clone().unwrap_or_default();
                let al = if h.aliases.is_empty() { String::new() } else { format!(" aka {:?}", h.aliases) };
                println!("  {:11} {:14} {:8} {:9} {:10} {}{}", n, h.ip.to_string(),
                    h.platform.as_str(), h.chassis.as_str(), hv,
                    h.capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(","), al);
            }
            println!("  alias check: polnareff -> {:?}", inv.canonical("polnareff"));
        }
        Err(e) => { println!("REJECTED: {e:#}"); std::process::exit(1); }
    }
}
