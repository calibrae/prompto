//! Policy engine (roadmap E3): which agent may use which tool on which
//! host.
//!
//! `/etc/prompto/policy.toml` (`PROMPTO_POLICY`) is an ordered list of
//! grants:
//!
//! ```toml
//! [[rule]]
//! id = "dev-exec"                       # optional, names the rule in logs
//! agents = ["sbx-dev-agent", "group:ops"]
//! hosts = ["sbx-t1", "web-*", "group:build"]
//! tools = ["ssh_exec", "file_*"]
//!
//! [[rule]]
//! agents = ["sbx-dev-agent"]
//! hosts = ["sbx-t1"]
//! tools = ["ssh_sudo_exec", "file_write"]
//! sudo = true                           # root-capable calls only
//! approval = "none"                     # "none" | "ticket" | "human"
//! ```
//!
//! # Matching
//!
//! Rules are read top to bottom and **the first rule that matches the
//! call decides**. No match is a deny. There are no deny rules: policy
//! only grants, so the order matters only for which rule's `approval`
//! applies (put the narrow, stricter rule first).
//!
//! A rule matches a call when all four hold:
//!
//! - **agent**: one of `agents` is the agent's name, or `group:<g>` with
//!   `<g>` among the agent's groups (read from the live `agents.toml` at
//!   decision time, so a SIGHUP group change applies to open sessions).
//!   `anonymous` and `local` are matched only by name. No globs: a rule
//!   never grants an agent nobody named.
//! - **host**: one of `hosts` matches the host's inventory name or any of
//!   its aliases (`*` and `?` are wildcards), or is `group:<g>` with `<g>`
//!   in the host's inventory `groups`. Tools that target no host
//!   (`inventory_list`, `prompto_gain`, `mcp_reconnect_hint`) skip this
//!   dimension: a rule grants them when it names the agent and the tool,
//!   whatever its `hosts` say.
//! - **tool**: one of `tools` matches the tool name (`*`, `?` wildcards).
//! - **sudo**: the rule's `sudo` equals whether the call is root-capable
//!   (see `authz::is_root_capable`). A `sudo = false` rule (the default)
//!   never grants a root-capable call, whatever its `tools` say —
//!   `tools = ["*"]` grants every *ordinary* tool, not `ssh_sudo_exec`.
//!   A `sudo = true` rule grants only root-capable calls, so root access
//!   *through prompto's own root paths* is always a separate, explicit
//!   grant. It is not "no root" on the host: an exec tool
//!   (`authz::ARBITRARY_EXEC_TOOLS`) is a shell as `ssh_user`, which is
//!   root wherever that user is root or has passwordless sudo. `lint`
//!   warns about those grants (inventory `nopasswd_sudo`).
//!
//! A matching rule with `approval` other than `none` grants the call only
//! with a valid ticket (E6, `crate::approval`): `ticket` takes one from
//! `POST /v1/precheck`, `human` one from `POST /v1/approve` (an
//! approver's TOTP code). Without one the call is refused
//! (`approval_required`, saying how to get one); with a bad one,
//! `refused_ticket`.
//!
//! # Reload
//!
//! The file is re-read when it changes ([`PolicyStore::refresh`], one
//! `stat` per call: an edit applies to the next call), and on SIGHUP.
//! A missing file is deny-all. A malformed one
//! is fatal at startup; on reload it **fails closed** — the live policy
//! becomes deny-all and every refusal says `policy file invalid since
//! <time>` until a valid file is loaded (the parser's error and the path
//! go to the journal only). The previous policy is not kept, because it
//! may be broader than the one being written.
//!
//! # Inventory visibility
//!
//! `inventory_list` shows an agent only the hosts some rule grants it a
//! tool on, and `sudo_password_vault_path` only where it has a
//! `sudo = true` grant (see [`Visibility`]); `inventory_get_host` hides
//! the vault path the same way.
//!
//! # What policy cannot do
//!
//! Policy only narrows. It runs in `authz::authorize` after the
//! existence, capability and self-target checks, and nothing here can
//! reach them: effective permission = policy ∩ host capability, minus the
//! caller's own machine.

use crate::agent::{ANONYMOUS, AgentStore, Agents, LOCAL, validate_name};
use crate::authz;
use crate::ctx::CallCtx;
use crate::error_class::{ClassifiedError, ErrorClass};
use crate::inventory::{HostConfig, Inventory};
use crate::stamp::{Seen, Stamp, read_settled};
use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Rule name of a deny that no rule produced.
pub const DEFAULT_DENY: &str = "default-deny";
/// Prefix of group references in `agents` and `hosts`.
pub const GROUP_PREFIX: &str = "group:";

/// What a matching rule demands beyond the match itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    /// The match is enough.
    #[default]
    None,
    /// A valid ticket must accompany the call: one from
    /// `POST /v1/precheck` (or a human one) — E6.
    Ticket,
    /// A human must approve the call: a ticket from `POST /v1/approve`,
    /// which takes an approver's TOTP code — E6.
    Human,
}

impl Approval {
    pub fn as_str(self) -> &'static str {
        match self {
            Approval::None => "none",
            Approval::Ticket => "ticket",
            Approval::Human => "human",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    #[serde(default)]
    id: Option<String>,
    agents: Vec<String>,
    hosts: Vec<String>,
    tools: Vec<String>,
    #[serde(default)]
    sudo: bool,
    #[serde(default)]
    approval: Approval,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    #[serde(default)]
    rule: Vec<toml::Spanned<RawRule>>,
}

/// A name pattern: `*` matches any run of characters, `?` exactly one.
/// Without either it is a literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Glob(String);

impl Glob {
    pub fn new(p: &str) -> Self {
        Glob(p.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_literal(&self) -> bool {
        !self.0.contains(['*', '?'])
    }

    pub fn matches(&self, s: &str) -> bool {
        let (p, s): (Vec<char>, Vec<char>) = (self.0.chars().collect(), s.chars().collect());
        // Classic two-pointer wildcard match: remember the last `*` and
        // retry from one character further on a mismatch.
        let (mut pi, mut si) = (0, 0);
        let mut star: Option<(usize, usize)> = None;
        while si < s.len() {
            if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
                pi += 1;
                si += 1;
            } else if pi < p.len() && p[pi] == '*' {
                star = Some((pi, si));
                pi += 1;
            } else if let Some((sp, ss)) = star {
                pi = sp + 1;
                si = ss + 1;
                star = Some((sp, ss + 1));
            } else {
                return false;
            }
        }
        p[pi..].iter().all(|&c| c == '*')
    }
}

/// An entry of a rule's `agents`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentPat {
    Name(String),
    Group(String),
}

/// An entry of a rule's `hosts`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostPat {
    /// Matched against the inventory name and every alias.
    Name(Glob),
    /// `group:<g>`: the host's inventory `groups` contain `<g>`.
    Group(String),
}

/// One validated `[[rule]]`.
#[derive(Clone, Debug)]
pub struct Rule {
    /// 1-based line of the rule's `[[rule]]` header.
    pub line: usize,
    pub id: Option<String>,
    pub agents: Vec<AgentPat>,
    pub hosts: Vec<HostPat>,
    pub tools: Vec<Glob>,
    pub sudo: bool,
    pub approval: Approval,
    /// `policy.toml:<line>`, plus ` (<id>)` when the rule has an id.
    name: String,
}

/// The calling agent, with its groups as of now.
#[derive(Clone, Copy, Debug)]
pub struct Subject<'a> {
    pub name: &'a str,
    pub groups: &'a [String],
}

/// The target host, as the inventory describes it.
#[derive(Clone, Copy, Debug)]
pub struct Target<'a> {
    /// Canonical inventory name.
    pub name: &'a str,
    pub aliases: &'a [String],
    pub groups: &'a [String],
}

impl<'a> Target<'a> {
    pub fn of(name: &'a str, host: &'a HostConfig) -> Self {
        Target {
            name,
            aliases: &host.aliases,
            groups: &host.groups,
        }
    }
}

/// One call, as policy sees it.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub agent: Subject<'a>,
    /// `None` for tools that target no host.
    pub host: Option<Target<'a>>,
    pub tool: &'a str,
    /// Whether the call is root-capable (`authz::is_root_capable`).
    pub root: bool,
}

impl Rule {
    pub fn name(&self) -> &str {
        &self.name
    }

    fn matches_agent(&self, a: &Subject) -> bool {
        self.agents.iter().any(|p| match p {
            AgentPat::Name(n) => n == a.name,
            AgentPat::Group(g) => a.groups.iter().any(|x| x == g),
        })
    }

    fn matches_host(&self, t: &Target) -> bool {
        self.hosts.iter().any(|p| match p {
            HostPat::Name(g) => g.matches(t.name) || t.aliases.iter().any(|a| g.matches(a)),
            HostPat::Group(g) => t.groups.iter().any(|x| x == g),
        })
    }

    fn matches_tool(&self, tool: &str) -> bool {
        self.tools.iter().any(|g| g.matches(tool))
    }

    /// Everything but the `sudo` dimension.
    fn matches_ignoring_sudo(&self, r: &Request) -> bool {
        self.matches_agent(&r.agent)
            && self.matches_tool(r.tool)
            && r.host.as_ref().is_none_or(|t| self.matches_host(t))
    }

    pub fn matches(&self, r: &Request) -> bool {
        self.sudo == r.root && self.matches_ignoring_sudo(r)
    }
}

/// The parsed, validated `policy.toml`.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub rules: Vec<Rule>,
    /// Set when the file did not exist: no rules, and deny messages say
    /// why.
    pub missing: Option<PathBuf>,
    /// Set when a reload found the file malformed: no rules (the
    /// previous policy is dropped, not kept), and deny messages say why.
    pub invalid: Option<Invalid>,
}

/// Why the live policy is deny-all after a failed reload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invalid {
    /// RFC 3339 time of the failed reload.
    pub since: String,
    /// The load error, on one line and without the TOML source excerpt.
    pub error: String,
}

impl Invalid {
    pub fn new(e: &anyhow::Error) -> Self {
        Invalid {
            since: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            error: one_line_error(e),
        }
    }
}

/// `e`'s cause chain on one line. The `toml` crate's message quotes the
/// offending source line (`2 | agents = 1`, a caret under it); that is
/// dropped — the line and column numbers stay — so a deny message doesn't
/// hand whole lines of the policy to every agent. (The parser's own
/// message may still quote the one bad value.)
fn one_line_error(e: &anyhow::Error) -> String {
    let excerpt = |l: &str| {
        let t = l.trim();
        t.is_empty()
            || t.starts_with('|')
            || t.split_once('|')
                .is_some_and(|(n, _)| n.trim().chars().all(|c| c.is_ascii_digit()))
    };
    format!("{e:#}")
        .lines()
        .filter(|l| !excerpt(l))
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(": ")
}

/// What policy says about one call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    /// A rule matched but demands an approval: the call needs a ticket.
    ApprovalRequired(Approval),
    Deny,
}

/// What the inventory tools (`inventory_list`, `inventory_get_host`) may
/// show an agent of one host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Visibility {
    /// Some rule grants the agent a host-targeting tool on the host — any
    /// tool, with or without sudo, approval or not. Hosts without one are
    /// left out of `inventory_list`.
    pub listed: bool,
    /// Some `sudo = true` rule grants it a root-capable call there. Only
    /// then is the host's `sudo_password_vault_path` shown.
    pub sudo: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub outcome: Outcome,
    /// The deciding rule's name, or [`DEFAULT_DENY`].
    pub rule: String,
    /// Human- and agent-readable explanation (for refusals: what to ask
    /// the operator for).
    pub message: String,
}

fn validate_pattern(kind: &str, p: &str, extra: &[char]) -> Result<()> {
    let ok = !p.is_empty()
        && p.len() <= 128
        && p.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '-' | '_' | '.' | '*' | '?')
                || extra.contains(&c)
        });
    if !ok {
        bail!("{kind} pattern {p:?}: use letters, digits, - _ . and the wildcards * ?");
    }
    Ok(())
}

fn group_ref<'a>(kind: &str, p: &'a str) -> Result<Option<&'a str>> {
    match p.strip_prefix(GROUP_PREFIX) {
        None => Ok(None),
        Some(g) => {
            validate_name(&format!("{kind} group"), g)?;
            Ok(Some(g))
        }
    }
}

impl Policy {
    /// Parse `s`; `source` is the file name used in rule names
    /// (`policy.toml:12`).
    pub fn from_toml_str(s: &str, source: &str) -> Result<Self> {
        let raw: RawPolicy = toml::from_str(s).context("parse policy TOML")?;
        let mut rules = Vec::with_capacity(raw.rule.len());
        let mut ids = std::collections::HashSet::new();
        for spanned in raw.rule {
            let line = s[..spanned.span().start].matches('\n').count() + 1;
            let r = spanned.into_inner();
            let at = format!("{source}:{line}");
            let rule =
                Self::validate_rule(r, line, &at).with_context(|| format!("rule at {at}"))?;
            if let Some(id) = &rule.id
                && !ids.insert(id.clone())
            {
                bail!("rule at {at}: id {id:?} is used by another rule");
            }
            rules.push(rule);
        }
        Ok(Policy {
            rules,
            ..Default::default()
        })
    }

    fn validate_rule(r: RawRule, line: usize, at: &str) -> Result<Rule> {
        if let Some(id) = &r.id {
            validate_name("rule id", id)?;
        }
        for (k, v) in [
            ("agents", &r.agents),
            ("hosts", &r.hosts),
            ("tools", &r.tools),
        ] {
            if v.is_empty() {
                bail!("`{k}` is empty — the rule would match nothing");
            }
        }
        let mut agents = Vec::new();
        for a in &r.agents {
            agents.push(match group_ref("agent", a)? {
                Some(g) => AgentPat::Group(g.into()),
                None => {
                    validate_name("agent", a).context(
                        "agents are names or group:<g> — no wildcards, so a rule never \
                         grants an agent nobody named",
                    )?;
                    AgentPat::Name(a.clone())
                }
            });
        }
        let mut hosts = Vec::new();
        for h in &r.hosts {
            hosts.push(match group_ref("host", h)? {
                Some(g) => HostPat::Group(g.into()),
                None => {
                    validate_pattern("host", h, &[])?;
                    HostPat::Name(Glob::new(h))
                }
            });
        }
        let mut tools = Vec::new();
        for t in &r.tools {
            validate_pattern("tool", t, &[])?;
            tools.push(Glob::new(t));
        }
        let name = match &r.id {
            Some(id) => format!("{at} ({id})"),
            None => at.to_string(),
        };
        Ok(Rule {
            line,
            id: r.id,
            agents,
            hosts,
            tools,
            sudo: r.sudo,
            approval: r.approval,
            name,
        })
    }

    /// Read `path`. A missing file is an empty policy (deny everything)
    /// that remembers it was missing; anything else unreadable or
    /// malformed is an error.
    pub fn from_path(path: &Path) -> Result<Self> {
        let source = path
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        match std::fs::read_to_string(path) {
            Ok(raw) => {
                Self::from_toml_str(&raw, &source).with_context(|| format!("{}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Policy {
                missing: Some(path.to_path_buf()),
                ..Default::default()
            }),
            Err(e) => Err(e).with_context(|| format!("read policy file {}", path.display())),
        }
    }

    /// The first rule matching `r`.
    pub fn first_match(&self, r: &Request) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.matches(r))
    }

    /// Which of `host` the inventory tools may show `agent`: every
    /// host-targeting tool of `tools`, in each of its root variants, is
    /// tried against the rules.
    pub fn visibility(&self, agent: Subject, host: Target, tools: &[&str]) -> Visibility {
        let mut v = Visibility::default();
        for &tool in tools.iter().filter(|t| !authz::HOSTLESS_TOOLS.contains(t)) {
            for &root in authz::root_variants(tool) {
                let req = Request {
                    agent,
                    host: Some(host),
                    tool,
                    root,
                };
                if self.first_match(&req).is_some() {
                    v.listed = true;
                    v.sudo |= root;
                }
            }
        }
        v
    }

    /// Decide `r`. See the module docs for the semantics.
    pub fn decide(&self, r: &Request) -> Decision {
        let on = match &r.host {
            Some(t) => format!(" on {}", t.name),
            None => String::new(),
        };
        let what = if r.root {
            format!("{} (root-capable)", r.tool)
        } else {
            r.tool.to_string()
        };
        if let Some(rule) = self.first_match(r) {
            return match rule.approval {
                Approval::None => Decision {
                    outcome: Outcome::Allow,
                    rule: rule.name().into(),
                    message: format!(
                        "agent {} may use {what}{on} (rule {})",
                        r.agent.name,
                        rule.name()
                    ),
                },
                a => Decision {
                    outcome: Outcome::ApprovalRequired(a),
                    rule: rule.name().into(),
                    message: format!(
                        "agent {} may use {what}{on} with approval = \"{}\" (rule {})",
                        r.agent.name,
                        a.as_str(),
                        rule.name()
                    ),
                },
            };
        }
        let mut why = String::from("no rule matched");
        if let Some(bad) = &self.invalid {
            // The parser's detail and the file's path stay in the
            // journal (`POLICY FILE INVALID`); agents get the time only.
            why = format!("policy file invalid since {}", bad.since);
        } else if let Some(path) = &self.missing {
            why = format!(
                "no policy loaded: {} does not exist, so every call is denied",
                path.display()
            );
        } else if r.root {
            why.push_str("; root-capable calls need a rule with sudo = true");
            if let Some(near) = self.rules.iter().find(|x| x.matches_ignoring_sudo(r)) {
                why.push_str(&format!(
                    " — {} grants {}{on} but without sudo",
                    near.name(),
                    r.tool
                ));
            }
        }
        Decision {
            outcome: Outcome::Deny,
            rule: DEFAULT_DENY.into(),
            message: format!(
                "refused_policy: agent {} has no grant for {what}{on} ({why}). Ask the \
                 operator for a policy.toml rule if you need it.",
                r.agent.name
            ),
        }
    }
}

/// `policy.toml`, hot-swappable. Re-read on SIGHUP like the inventory
/// and agents, and by itself when the file changes: [`Self::refresh`]
/// runs on every policy decision (one `stat`), so an edit applies to the
/// next call. Either way a bad file fails closed (see [`Self::reload`]).
#[derive(Clone)]
pub struct PolicyStore {
    inner: Arc<ArcSwap<Policy>>,
    path: Option<PathBuf>,
    /// The file's metadata when it was last read.
    seen: Arc<std::sync::Mutex<Seen>>,
}

impl Default for PolicyStore {
    /// No rules: deny everything.
    fn default() -> Self {
        Self::new(Policy::default(), None)
    }
}

impl PolicyStore {
    pub fn new(policy: Policy, path: Option<PathBuf>) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(policy)),
            path,
            seen: Default::default(),
        }
    }

    pub fn load_from(path: PathBuf) -> Result<Self> {
        // Stamped before reading: a change during the read is seen next.
        let (stamp, p) = read_settled(&path, Policy::from_path);
        let p = p?;
        let store = Self::new(p, Some(path));
        store
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record(stamp);
        Ok(store)
    }

    pub fn snapshot(&self) -> Arc<Policy> {
        self.inner.load_full()
    }

    /// Re-read the file. Returns the rule count. Fails closed: a file
    /// that is malformed (or unreadable) replaces the live policy with
    /// deny-all, marked [`Policy::invalid`], and the error is returned;
    /// a file that has disappeared becomes deny-all too. The previous
    /// policy is never kept — it may be broader than what the operator
    /// was trying to write.
    pub fn reload(&self) -> Result<usize> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("no policy path configured — cannot reload"))?;
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        self.read_locked(path, &mut seen)
    }

    /// Re-read the file if it changed since it was last read, with the
    /// same fail-closed semantics as [`Self::reload`]. Cheap (one
    /// `stat`); called on every policy decision.
    pub fn refresh(&self) {
        let Some(path) = &self.path else { return };
        let now = Stamp::of(path);
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let Some(changed) = seen.check(now) else {
            return;
        };
        match self.read_locked(path, &mut seen) {
            Ok(_) if !changed => {}
            Ok(n) => {
                let live = self.snapshot();
                if live.missing.is_some() {
                    tracing::warn!(
                        path = %path.display(),
                        "POLICY FILE MISSING — every tool call is DENIED (refused_policy) until \
                         it exists"
                    );
                } else {
                    tracing::info!(
                        rule_count = n,
                        path = %path.display(),
                        "policy file changed — reloaded (`prompto policy lint` checks it)"
                    );
                }
            }
            Err(e) => tracing::error!(
                error = %format!("{e:#}"),
                path = %path.display(),
                "POLICY FILE INVALID — every tool call is DENIED (refused_policy) until a valid \
                 file is written"
            ),
        }
    }

    fn read_locked(&self, path: &Path, seen: &mut Seen) -> Result<usize> {
        let (stamp, read) = read_settled(path, Policy::from_path);
        seen.record(stamp);
        match read {
            Ok(new) => {
                let n = new.rules.len();
                self.inner.store(Arc::new(new));
                Ok(n)
            }
            Err(e) => {
                self.inner.store(Arc::new(Policy {
                    invalid: Some(Invalid::new(&e)),
                    ..Default::default()
                }));
                Err(e)
            }
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

/// Policy as applied to live calls: the rules plus the live agent store,
/// which supplies each agent's *current* groups. Present only when
/// `PROMPTO_AUTH` is `optional` or `required`.
#[derive(Clone)]
pub struct Enforcer {
    pub policy: PolicyStore,
    pub agents: AgentStore,
    /// Tickets and approvers (E6), for rules with an `approval`.
    pub approvals: crate::approval::Approvals,
}

/// A call policy grants, and what the granting rule demands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The deciding rule's name.
    pub rule: String,
    /// `none`, or the approval the call's ticket must carry.
    pub approval: Approval,
}

impl Enforcer {
    /// Check one call. `host` is the resolved target (canonical name and
    /// inventory entry), `None` for hostless tools. Returns the granting
    /// rule and the approval it demands — which the caller (`authz`) must
    /// then check the call's ticket against — or a `refused_policy`
    /// refusal naming the rule that decided.
    pub fn check(
        &self,
        ctx: &CallCtx,
        tool: &str,
        host: Option<(&str, &HostConfig)>,
        root: bool,
    ) -> Result<Grant, ClassifiedError> {
        // An edit to policy.toml applies to this call, no SIGHUP needed.
        self.policy.refresh();
        let (name, groups) = self.subject(ctx, tool).map_err(|msg| {
            ClassifiedError::refused(ErrorClass::RefusedPolicy, msg).with_rule(DEFAULT_DENY)
        })?;
        let req = Request {
            agent: Subject {
                name,
                groups: &groups,
            },
            host: host.map(|(n, h)| Target::of(n, h)),
            tool,
            root,
        };
        let d = self.policy.snapshot().decide(&req);
        // For the audit record: the deciding rule's approval mode.
        let approval = match &d.outcome {
            Outcome::Allow => Some(Approval::None.as_str()),
            Outcome::ApprovalRequired(a) => Some(a.as_str()),
            Outcome::Deny => None,
        };
        ctx.note(|n| n.approval = approval);
        let approval = match d.outcome {
            Outcome::Allow => Approval::None,
            Outcome::ApprovalRequired(a) => a,
            Outcome::Deny => {
                return Err(
                    ClassifiedError::refused(ErrorClass::RefusedPolicy, d.message)
                        .with_rule(d.rule),
                );
            }
        };
        tracing::info!(
            request_id = %ctx.request_id,
            agent = %name,
            tool,
            host = host.map(|h| h.0),
            root,
            rule = %d.rule,
            approval = approval.as_str(),
            "policy allow"
        );
        Ok(Grant {
            rule: d.rule,
            approval,
        })
    }

    /// The caller's name and current groups, or why policy grants it
    /// nothing. Groups come from the live store, by name, so a SIGHUP
    /// that changes them (or revokes the agent) applies to a session that
    /// authenticated before it.
    fn subject<'c>(&self, ctx: &'c CallCtx, tool: &str) -> Result<(&'c str, Vec<String>), String> {
        let Some(agent) = &ctx.agent else {
            return Err(format!(
                "refused_policy: no agent identity for {tool}, and policy grants only to agents"
            ));
        };
        let groups = agent_groups(&self.agents.snapshot(), &agent.name)?;
        Ok((&agent.name, groups))
    }

    /// What the inventory tools may show the caller of `host`; nothing
    /// for a caller policy grants nothing. `tools` is the server's tool
    /// list.
    pub fn visibility(
        &self,
        ctx: &CallCtx,
        host: (&str, &HostConfig),
        tools: &[&str],
    ) -> Visibility {
        let Ok((name, groups)) = self.subject(ctx, "inventory") else {
            return Visibility::default();
        };
        let agent = Subject {
            name,
            groups: &groups,
        };
        self.policy
            .snapshot()
            .visibility(agent, Target::of(host.0, host.1), tools)
    }
}

/// An agent's current groups from `agents`: none for the pseudo-agents
/// `anonymous` and `local`; for a role, its entry's groups. A role that
/// has been revoked or removed since it authenticated gets a
/// `refused_policy` message instead — policy grants nothing to it.
pub fn agent_groups(agents: &Agents, name: &str) -> Result<Vec<String>, String> {
    match name {
        ANONYMOUS | LOCAL => Ok(vec![]),
        _ => match agents.agents.get(name) {
            Some(e) if !e.disabled => Ok(e.groups.clone()),
            Some(_) => Err(format!(
                "refused_policy: agent {name} has been revoked in agents.toml"
            )),
            None => Err(format!(
                "refused_policy: agent {name} is not in agents.toml"
            )),
        },
    }
}

// ---------------------------------------------------------------------------
// Lint
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error,
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    /// The rule concerned, by name.
    pub rule: String,
    pub message: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let level = match self.level {
            Level::Error => "error",
            Level::Warning => "warning",
        };
        write!(f, "{level}: {}: {}", self.rule, self.message)
    }
}

/// Check `policy` against the inventory, the agents and the tool list.
///
/// Errors: references to agents, hosts, host groups or tools that don't
/// exist (a typo there silently grants nothing). Warnings: agent groups
/// nobody is in yet, globs that match nothing, disabled agents, exec grants without `sudo = true` on hosts
/// where the shell is root anyway ([`authz::ARBITRARY_EXEC_TOOLS`]), and
/// rules that can never decide a call —
/// because an earlier rule always wins (shadowed) or because nothing
/// matches them at all. Reachability is exact, not heuristic: every
/// (agent, host, tool, root) combination the files allow is enumerated.
pub fn lint(policy: &Policy, inv: &Inventory, agents: &Agents, tools: &[&str]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut push = |level, rule: &Rule, message: String| {
        out.push(Finding {
            level,
            rule: rule.name().into(),
            message,
        })
    };
    for rule in &policy.rules {
        for a in &rule.agents {
            match a {
                AgentPat::Name(n) if n == ANONYMOUS || n == LOCAL => {}
                AgentPat::Name(n) => match agents.agents.get(n) {
                    None => push(Level::Error, rule, format!("unknown agent {n:?}")),
                    Some(e) if e.disabled => {
                        push(Level::Warning, rule, format!("agent {n:?} is revoked"))
                    }
                    Some(_) => {}
                },
                AgentPat::Group(g) => {
                    // A warning, not an error: a group may be prepared
                    // before its first agent is added.
                    if !agents.agents.values().any(|e| e.groups.contains(g)) {
                        push(
                            Level::Warning,
                            rule,
                            format!("no agent in agents.toml is in group {g:?}"),
                        )
                    }
                }
            }
        }
        for h in &rule.hosts {
            match h {
                HostPat::Group(g) => {
                    if !inv.hosts.values().any(|x| x.groups.contains(g)) {
                        push(
                            Level::Error,
                            rule,
                            format!("no inventory host is in group {g:?}"),
                        )
                    }
                }
                HostPat::Name(g) if g.is_literal() => {
                    if inv.get(g.as_str()).is_err() {
                        push(Level::Error, rule, format!("unknown host {:?}", g.as_str()))
                    }
                }
                HostPat::Name(g) => {
                    let hit = inv
                        .hosts
                        .iter()
                        .any(|(n, x)| g.matches(n) || x.aliases.iter().any(|a| g.matches(a)));
                    if !hit {
                        push(
                            Level::Warning,
                            rule,
                            format!("host pattern {:?} matches no inventory host", g.as_str()),
                        )
                    }
                }
            }
        }
        for t in &rule.tools {
            let hit = tools.iter().any(|x| t.matches(x));
            match (hit, t.is_literal()) {
                (true, _) => {}
                (false, true) => push(Level::Error, rule, format!("unknown tool {:?}", t.as_str())),
                (false, false) => push(
                    Level::Warning,
                    rule,
                    format!("tool pattern {:?} matches no tool", t.as_str()),
                ),
            }
        }
        if let Some(msg) = exec_as_root(rule, inv, tools) {
            push(Level::Warning, rule, msg)
        }
    }
    reachability(policy, inv, agents, tools, &mut out);
    out.sort_by_key(|f| f.level);
    out
}

/// The `sudo = false` rule's arbitrary-exec grants on hosts where that
/// shell can become root anyway — `ssh_user` is root, or the inventory
/// says `nopasswd_sudo = true` or doesn't say. One message per rule,
/// naming the tools and each host with its reason; `None` when there are
/// none. A host counts only if it carries the capability one of those
/// tools needs, so a rule with `hosts = ["*"]` doesn't list every box.
fn exec_as_root(rule: &Rule, inv: &Inventory, tools: &[&str]) -> Option<String> {
    if rule.sudo {
        return None;
    }
    let exec: Vec<_> = authz::ARBITRARY_EXEC_TOOLS
        .iter()
        .filter(|(t, _)| tools.contains(t) && rule.matches_tool(t))
        .collect();
    if exec.is_empty() {
        return None;
    }
    let mut hosts: Vec<String> = inv
        .hosts
        .iter()
        .filter(|(n, h)| {
            rule.matches_host(&Target::of(n, h)) && exec.iter().any(|(_, cap)| h.has(*cap))
        })
        .filter_map(|(n, h)| {
            let why = if h.ssh_user == "root" {
                "ssh_user is root"
            } else {
                match h.nopasswd_sudo {
                    Some(true) => "nopasswd_sudo = true",
                    None => "nopasswd_sudo unset",
                    Some(false) => return None,
                }
            };
            Some(format!("{n} ({why})"))
        })
        .collect();
    if hosts.is_empty() {
        return None;
    }
    hosts.sort();
    let names: Vec<&str> = exec.iter().map(|(t, _)| *t).collect();
    Some(format!(
        "grants arbitrary-exec tools ({}) without sudo = true on hosts where that shell can \
         become root: {}. sudo = true gates only prompto's own root paths; an exec grant runs \
         as ssh_user. Narrow the rule, or set nopasswd_sudo = false on hosts whose sudo needs \
         a password",
        names.join(", "),
        hosts.join(", ")
    ))
}

/// Flag rules that never decide any call.
fn reachability(
    policy: &Policy,
    inv: &Inventory,
    agents: &Agents,
    tools: &[&str],
    out: &mut Vec<Finding>,
) {
    let n = policy.rules.len();
    // decided[i]: rule i is first for some call. hit[i]: rule i matches
    // some call. by[i]: earlier rules that won calls rule i matches.
    let mut decided = vec![false; n];
    let mut hit = vec![false; n];
    let mut by: Vec<std::collections::BTreeSet<usize>> = vec![Default::default(); n];

    let none: Vec<String> = vec![];
    let mut subjects: Vec<(&str, &[String])> = vec![(ANONYMOUS, &none), (LOCAL, &none)];
    subjects.extend(
        agents
            .agents
            .iter()
            .filter(|(_, e)| !e.disabled)
            .map(|(n, e)| (n.as_str(), e.groups.as_slice())),
    );
    let hosts: Vec<Target> = inv.hosts.iter().map(|(n, h)| Target::of(n, h)).collect();
    for &(name, groups) in &subjects {
        for &tool in tools {
            let targets: Vec<Option<Target>> = if authz::HOSTLESS_TOOLS.contains(&tool) {
                vec![None]
            } else {
                hosts.iter().copied().map(Some).collect()
            };
            for host in targets {
                for &root in authz::root_variants(tool) {
                    let req = Request {
                        agent: Subject { name, groups },
                        host,
                        tool,
                        root,
                    };
                    let mut first = None;
                    for (i, rule) in policy.rules.iter().enumerate() {
                        if rule.matches(&req) {
                            hit[i] = true;
                            match first {
                                None => {
                                    first = Some(i);
                                    decided[i] = true;
                                }
                                Some(f) => {
                                    by[i].insert(f);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    for (i, rule) in policy.rules.iter().enumerate() {
        if decided[i] {
            continue;
        }
        let message = if hit[i] {
            let names: Vec<&str> = by[i].iter().map(|&j| policy.rules[j].name()).collect();
            format!(
                "shadowed: every call it matches is decided first by {}",
                names.join(", ")
            )
        } else {
            let root_tools = tools
                .iter()
                .filter(|t| rule.matches_tool(t))
                .map(|t| authz::root_variants(t));
            let mut why = "matches no call with the current inventory and agents";
            let (mut any, mut can_root, mut can_plain) = (false, false, false);
            for v in root_tools {
                any = true;
                can_root |= v.contains(&true);
                can_plain |= v.contains(&false);
            }
            if any && rule.sudo && !can_root {
                why = "matches no call: sudo = true, but none of its tools is ever \
                       root-capable — drop sudo = true";
            } else if any && !rule.sudo && !can_plain {
                why = "matches no call: its tools are always root-capable, which only a \
                       rule with sudo = true can grant";
            }
            why.to_string()
        };
        out.push(Finding {
            level: Level::Warning,
            rule: rule.name().into(),
            message,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INV: &str = r#"
[host.alpha]
ip = "192.0.2.1"
ssh_user = "u"
ssh_key = "/k"
aliases = ["a1"]
groups = ["build"]
nopasswd_sudo = false
capabilities = ["exec", "sudo_exec"]

[host.bravo]
ip = "192.0.2.2"
ssh_user = "u"
ssh_key = "/k"
groups = ["build", "web"]
nopasswd_sudo = false
capabilities = ["exec", "sudo_exec"]

[host.web-1]
ip = "192.0.2.3"
ssh_user = "u"
ssh_key = "/k"
nopasswd_sudo = false
capabilities = ["exec"]
"#;

    fn inv() -> Inventory {
        Inventory::from_toml_str(INV).unwrap()
    }

    // Line numbers matter: rule names are `policy.toml:<line>`.
    const POLICY: &str = r#"# line 1
[[rule]]
id = "web-sudo-human"
agents = ["dev"]
hosts = ["group:web"]
tools = ["ssh_sudo_exec"]
sudo = true
approval = "human"

[[rule]]
agents = ["dev", "group:ops"]
hosts = ["alpha", "web-*", "group:build"]
tools = ["ssh_*", "file_*", "inventory_*"]

[[rule]]
agents = ["dev"]
hosts = ["a1"]
tools = ["ssh_sudo_exec", "file_write"]
sudo = true

[[rule]]
agents = ["anonymous"]
hosts = ["*"]
tools = ["inventory_list", "host_status"]

[[rule]]
agents = ["group:ops"]
hosts = ["bravo"]
tools = ["ssh_exec"]
approval = "ticket"
"#;

    fn policy() -> Policy {
        Policy::from_toml_str(POLICY, "policy.toml").unwrap()
    }

    fn decide(
        p: &Policy,
        agent: &str,
        groups: &[&str],
        host: Option<&str>,
        tool: &str,
        root: bool,
    ) -> Decision {
        let inv = inv();
        let groups: Vec<String> = groups.iter().map(|g| g.to_string()).collect();
        let target = host.map(|h| {
            let canon = inv.canonical(h).unwrap();
            Target::of(canon, inv.get(canon).unwrap())
        });
        p.decide(&Request {
            agent: Subject {
                name: agent,
                groups: &groups,
            },
            host: target,
            tool,
            root,
        })
    }

    #[test]
    fn rules_are_named_by_line_and_id() {
        let p = policy();
        let names: Vec<&str> = p.rules.iter().map(Rule::name).collect();
        assert_eq!(
            names,
            [
                "policy.toml:2 (web-sudo-human)",
                "policy.toml:10",
                "policy.toml:15",
                "policy.toml:21",
                "policy.toml:26"
            ]
        );
    }

    /// agent, groups, host, tool, root → outcome, rule.
    type Row<'a> = (
        &'a str,
        &'a [&'a str],
        Option<&'a str>,
        &'a str,
        bool,
        Outcome,
        &'a str,
    );

    /// The matching semantics, one row per case: agent, its groups,
    /// host (as typed: aliases resolve), tool, root-capable → outcome and
    /// deciding rule.
    #[test]
    fn matching_table() {
        use Outcome::*;
        let p = policy();
        let human = ApprovalRequired(Approval::Human);
        let ticket = ApprovalRequired(Approval::Ticket);
        #[rustfmt::skip]
        let table: &[Row] = &[
            // literal host, tool glob
            ("dev", &[], Some("alpha"), "ssh_exec", false, Allow, "policy.toml:10"),
            // alias typed by the caller resolves to the canonical name
            ("dev", &[], Some("a1"), "file_read", false, Allow, "policy.toml:10"),
            // host glob
            ("dev", &[], Some("web-1"), "ssh_batch", false, Allow, "policy.toml:10"),
            // host group (bravo is in build)
            ("dev", &[], Some("bravo"), "ssh_exec", false, Allow, "policy.toml:10"),
            // tool outside every glob → default deny
            ("dev", &[], Some("alpha"), "service_control", true, Deny, DEFAULT_DENY),
            ("dev", &[], Some("alpha"), "vm_list", false, Deny, DEFAULT_DENY),
            // agent group; nobody else
            ("eve", &["ops"], Some("alpha"), "ssh_exec", false, Allow, "policy.toml:10"),
            ("eve", &["web"], Some("alpha"), "ssh_exec", false, Deny, DEFAULT_DENY),
            ("eve", &[], Some("alpha"), "ssh_exec", false, Deny, DEFAULT_DENY),
            // sudo is a separate grant: `ssh_*` without sudo never covers it
            ("dev", &[], Some("web-1"), "ssh_sudo_exec", true, Deny, DEFAULT_DENY),
            ("dev", &[], Some("alpha"), "ssh_sudo_exec", true, Allow, "policy.toml:15"),
            // the rule names an alias: matches the host through it
            ("dev", &[], Some("alpha"), "file_write", true, Allow, "policy.toml:15"),
            ("dev", &[], Some("alpha"), "file_write", false, Allow, "policy.toml:10"),
            ("eve", &["ops"], Some("alpha"), "file_write", true, Deny, DEFAULT_DENY),
            // a sudo = true rule grants only root-capable calls
            ("dev", &[], Some("alpha"), "ssh_sudo_exec", false, Allow, "policy.toml:10"),
            // first match decides: the approval rule sits above the grant
            ("dev", &[], Some("bravo"), "ssh_sudo_exec", true, human.clone(), "policy.toml:2 (web-sudo-human)"),
            ("eve", &["ops"], Some("bravo"), "ssh_exec", false, Allow, "policy.toml:10"),
            // anonymous only by name, and only what it is named for
            ("anonymous", &[], Some("web-1"), "host_status", false, Allow, "policy.toml:21"),
            ("anonymous", &[], Some("web-1"), "ssh_exec", false, Deny, DEFAULT_DENY),
            ("anonymous", &[], None, "inventory_list", false, Allow, "policy.toml:21"),
            ("anonymous", &[], None, "prompto_gain", false, Deny, DEFAULT_DENY),
            // hostless tools match on agent and tool only
            ("dev", &[], None, "inventory_list", false, Allow, "policy.toml:10"),
            ("dev", &[], None, "prompto_gain", false, Deny, DEFAULT_DENY),
            // `local` (stdio) gets nothing unless named
            ("local", &[], Some("alpha"), "ssh_exec", false, Deny, DEFAULT_DENY),
            // a name is not a group and a group is not a name
            ("ops", &[], Some("alpha"), "ssh_exec", false, Deny, DEFAULT_DENY),
        ];
        for (agent, groups, host, tool, root, want, rule) in table {
            let d = decide(&p, agent, groups, *host, tool, *root);
            assert_eq!(
                (&d.outcome, d.rule.as_str()),
                (want, *rule),
                "{agent} {groups:?} {host:?} {tool} root={root}: {}",
                d.message
            );
        }
        // Ticket approval on a rule below a broader grant is shadowed for
        // ops agents on bravo — rule 10 decides first.
        let d = decide(&p, "eve", &["ops"], Some("bravo"), "ssh_exec", false);
        assert_ne!(d.outcome, ticket);
    }

    #[test]
    fn default_deny_with_no_rules() {
        let p = Policy::from_toml_str("", "policy.toml").unwrap();
        let d = decide(&p, "dev", &[], Some("alpha"), "ssh_exec", false);
        assert_eq!(d.outcome, Outcome::Deny);
        assert_eq!(d.rule, DEFAULT_DENY);
        assert_eq!(
            d.message,
            "refused_policy: agent dev has no grant for ssh_exec on alpha (no rule matched). \
             Ask the operator for a policy.toml rule if you need it."
        );
    }

    #[test]
    fn missing_file_denies_and_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let p = Policy::from_path(&path).unwrap();
        assert_eq!(p.missing.as_deref(), Some(path.as_path()));
        let d = decide(&p, "dev", &[], None, "inventory_list", false);
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(
            d.message
                .contains("does not exist, so every call is denied"),
            "{}",
            d.message
        );
    }

    #[test]
    fn root_deny_points_at_the_near_miss() {
        let d = decide(&policy(), "dev", &[], Some("bravo"), "file_write", true);
        assert_eq!(
            d.message,
            "refused_policy: agent dev has no grant for file_write (root-capable) on bravo (no \
             rule matched; root-capable calls need a rule with sudo = true — policy.toml:10 \
             grants file_write on bravo but without sudo). Ask the operator for a policy.toml \
             rule if you need it."
        );
    }

    #[test]
    fn approval_rules_name_the_rule_and_the_approval() {
        for (approval, host, groups) in
            [("human", "bravo", vec![]), ("ticket", "bravo", vec!["ops"])]
        {
            let p = Policy::from_toml_str(
                &format!(
                    "[[rule]]\nagents = [\"dev\", \"group:ops\"]\nhosts = [\"*\"]\ntools = [\"ssh_exec\"]\napproval = \"{approval}\"\n"
                ),
                "policy.toml",
            )
            .unwrap();
            let d = decide(&p, "dev", &groups, Some(host), "ssh_exec", false);
            assert!(
                matches!(d.outcome, Outcome::ApprovalRequired(_)),
                "{approval}"
            );
            assert_eq!(d.rule, "policy.toml:1");
            assert!(
                d.message
                    .contains(&format!("with approval = \"{approval}\"")),
                "{}",
                d.message
            );
        }
    }

    #[test]
    fn rejects_malformed_rules() {
        let rule =
            |body: &str| Policy::from_toml_str(&format!("[[rule]]\n{body}\n"), "policy.toml");
        let ok = "agents = [\"dev\"]\nhosts = [\"*\"]\ntools = [\"*\"]";
        rule(ok).unwrap();
        for (bad, why) in [
            (
                "agents = []\nhosts = [\"*\"]\ntools = [\"*\"]",
                "`agents` is empty",
            ),
            (
                "agents = [\"dev\"]\nhosts = []\ntools = [\"*\"]",
                "`hosts` is empty",
            ),
            (
                "agents = [\"dev\"]\nhosts = [\"*\"]\ntools = []",
                "`tools` is empty",
            ),
            (
                "agents = [\"*\"]\nhosts = [\"*\"]\ntools = [\"*\"]",
                "no wildcards",
            ),
            (
                "agents = [\"group:Ops\"]\nhosts = [\"*\"]\ntools = [\"*\"]",
                "agent group",
            ),
            (
                "agents = [\"dev\"]\nhosts = [\"group:\"]\ntools = [\"*\"]",
                "host group",
            ),
            (
                "agents = [\"dev\"]\nhosts = [\"a b\"]\ntools = [\"*\"]",
                "host pattern",
            ),
            (
                "agents = [\"dev\"]\nhosts = [\"*\"]\ntools = [\"ssh exec\"]",
                "tool pattern",
            ),
            (&format!("{ok}\napproval = \"maybe\""), "unknown variant"),
            (&format!("{ok}\nsudo = \"yes\""), "invalid type"),
            (&format!("{ok}\nhost = [\"x\"]"), "unknown field"),
            (&format!("{ok}\nid = \"Bad Id\""), "rule id"),
            ("hosts = [\"*\"]\ntools = [\"*\"]", "missing field `agents`"),
        ] {
            let e = format!("{:#}", rule(bad).expect_err(bad));
            assert!(e.contains(why), "{bad}: {e}");
        }
        let dup = format!("[[rule]]\nid = \"x\"\n{ok}\n[[rule]]\nid = \"x\"\n{ok}\n");
        let e = format!(
            "{:#}",
            Policy::from_toml_str(&dup, "policy.toml").unwrap_err()
        );
        assert!(
            e.contains("used by another rule") && e.contains("policy.toml:6"),
            "{e}"
        );
        let e = format!(
            "{:#}",
            Policy::from_toml_str("[agent.x]\nhosts = []\n", "p").unwrap_err()
        );
        assert!(e.contains("unknown field `agent`"), "{e}");
    }

    fn agents() -> Agents {
        let h = "0".repeat(64);
        let h2 = "1".repeat(64);
        let h3 = "2".repeat(64);
        Agents::from_toml_str(&format!(
            "[agent.dev]\ntoken_sha256 = \"{h}\"\n\
             [agent.eve]\ngroups = [\"ops\"]\ntoken_sha256 = \"{h2}\"\n\
             [agent.old]\ntoken_sha256 = \"{h3}\"\ndisabled = true\n"
        ))
        .unwrap()
    }

    fn tools() -> Vec<&'static str> {
        vec![
            "ssh_exec",
            "ssh_batch",
            "ssh_sudo_exec",
            "file_read",
            "file_write",
            "file_list",
            "inventory_list",
            "inventory_get_host",
            "host_status",
            "service_control",
            "vm_list",
            "prompto_gain",
        ]
    }

    fn lint_of(policy: &str) -> Vec<String> {
        let p = Policy::from_toml_str(policy, "policy.toml").unwrap();
        lint(&p, &inv(), &agents(), &tools())
            .iter()
            .map(|f| f.to_string())
            .collect()
    }

    #[test]
    fn lint_flags_unknown_references_as_errors() {
        let f = lint_of(
            "[[rule]]\nagents = [\"dev\", \"ghost\", \"group:nobody\", \"old\"]\n\
             hosts = [\"alpha\", \"a1\", \"nohost\", \"group:nogroup\", \"zz-*\"]\n\
             tools = [\"ssh_exec\", \"ssh_exce\", \"zz_*\"]\n",
        );
        for want in [
            "error: policy.toml:1: unknown agent \"ghost\"",
            "warning: policy.toml:1: no agent in agents.toml is in group \"nobody\"",
            "error: policy.toml:1: unknown host \"nohost\"",
            "error: policy.toml:1: no inventory host is in group \"nogroup\"",
            "error: policy.toml:1: unknown tool \"ssh_exce\"",
            "warning: policy.toml:1: agent \"old\" is revoked",
            "warning: policy.toml:1: host pattern \"zz-*\" matches no inventory host",
            "warning: policy.toml:1: tool pattern \"zz_*\" matches no tool",
        ] {
            assert!(f.contains(&want.to_string()), "missing {want:?} in {f:#?}");
        }
        assert_eq!(f.len(), 8, "{f:#?}");
        // Errors sort first.
        assert!(f[0].starts_with("error") && f[7].starts_with("warning"));
    }

    /// An exec grant without `sudo = true` is a root shell wherever
    /// `ssh_user` is root or can sudo without a password: one warning per
    /// rule, naming the tools and each such host with its reason.
    #[test]
    fn lint_warns_on_exec_grants_where_the_shell_is_root() {
        let inv = Inventory::from_toml_str(
            r#"
[host.pw]
ip = "192.0.2.1"
ssh_user = "u"
ssh_key = "/k"
nopasswd_sudo = false
capabilities = ["exec"]

[host.nopw]
ip = "192.0.2.2"
ssh_user = "u"
ssh_key = "/k"
nopasswd_sudo = true
capabilities = ["exec"]

[host.unknown]
ip = "192.0.2.3"
ssh_user = "u"
ssh_key = "/k"
capabilities = ["exec"]

[host.rootuser]
ip = "192.0.2.4"
ssh_user = "root"
ssh_key = "/k"
nopasswd_sudo = false
capabilities = ["exec"]

[host.noexec]
ip = "192.0.2.5"
ssh_user = "root"
ssh_key = "/k"
capabilities = ["virt"]
"#,
        )
        .unwrap();
        let tools = [
            "ssh_exec",
            "bash_exec",
            "file_read",
            "ssh_sudo_exec",
            "host_status",
        ];
        let lint_of = |policy: &str| -> Vec<String> {
            let p = Policy::from_toml_str(policy, "policy.toml").unwrap();
            lint(&p, &inv, &agents(), &tools)
                .iter()
                .map(|f| f.to_string())
                .collect()
        };
        let f = lint_of(
            "[[rule]]\nagents = [\"dev\"]\nhosts = [\"*\"]\ntools = [\"*\"]\n\
             [[rule]]\nagents = [\"dev\"]\nhosts = [\"*\"]\ntools = [\"ssh_sudo_exec\"]\nsudo = true\n",
        );
        assert_eq!(
            f,
            [
                "warning: policy.toml:1: grants arbitrary-exec tools (ssh_exec, bash_exec) \
                 without sudo = true on hosts where that shell can become root: nopw \
                 (nopasswd_sudo = true), rootuser (ssh_user is root), unknown (nopasswd_sudo \
                 unset). sudo = true gates only prompto's own root paths; an exec grant runs as \
                 ssh_user. Narrow the rule, or set nopasswd_sudo = false on hosts whose sudo \
                 needs a password"
            ],
            "pw has a sudo password; noexec can't exec; the sudo rule is explicit"
        );
        // Only hosts the rule names; nothing for non-exec tools.
        assert!(
            lint_of("[[rule]]\nagents = [\"dev\"]\nhosts = [\"pw\"]\ntools = [\"*\"]\n").is_empty()
        );
        assert!(
            lint_of("[[rule]]\nagents = [\"dev\"]\nhosts = [\"*\"]\ntools = [\"file_read\", \"host_status\"]\n")
                .is_empty()
        );
        let f = lint_of(
            "[[rule]]\nagents = [\"dev\"]\nhosts = [\"unknown\"]\ntools = [\"ssh_exec\"]\n",
        );
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(f[0].contains("(ssh_exec)") && f[0].contains("unknown (nopasswd_sudo unset)"));
    }

    /// Writing ~/.bashrc is code execution: a plain `file_write` grant and
    /// an `rsync_sync` grant warn like an exec grant does. `file_write`
    /// with `sudo = true` is a root grant and doesn't.
    #[test]
    fn lint_counts_file_write_and_rsync_as_exec() {
        let inv = Inventory::from_toml_str(
            "[host.h]\nip = \"192.0.2.1\"\nssh_user = \"u\"\nssh_key = \"/k\"\ncapabilities = [\"exec\", \"sudo_exec\"]\n",
        )
        .unwrap();
        let tools = ["file_write", "rsync_sync", "file_read"];
        let lint_of = |policy: &str| -> Vec<String> {
            let p = Policy::from_toml_str(policy, "policy.toml").unwrap();
            lint(&p, &inv, &agents(), &tools)
                .iter()
                .map(|f| f.to_string())
                .collect()
        };
        let f = lint_of(
            "[[rule]]\nagents = [\"dev\"]\nhosts = [\"h\"]\ntools = [\"file_write\", \"rsync_sync\"]\n",
        );
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(
            f[0].contains("arbitrary-exec tools (file_write, rsync_sync)"),
            "{f:#?}"
        );
        let f = lint_of(
            "[[rule]]\nagents = [\"dev\"]\nhosts = [\"h\"]\ntools = [\"file_write\"]\nsudo = true\n",
        );
        assert!(f.iter().all(|l| !l.contains("arbitrary-exec")), "{f:#?}");
    }

    #[test]
    fn lint_is_clean_on_a_good_policy() {
        let f = lint_of(
            "[[rule]]\nagents = [\"dev\", \"group:ops\", \"anonymous\"]\n\
             hosts = [\"group:build\", \"web-*\"]\ntools = [\"ssh_exec\", \"inventory_*\"]\n\
             [[rule]]\nagents = [\"dev\"]\nhosts = [\"a1\"]\ntools = [\"ssh_sudo_exec\"]\nsudo = true\n",
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn lint_warns_on_unreachable_rules() {
        let f = lint_of(
            "[[rule]]\nagents = [\"dev\"]\nhosts = [\"*\"]\ntools = [\"ssh_*\"]\n\
             [[rule]]\nagents = [\"dev\"]\nhosts = [\"alpha\"]\ntools = [\"ssh_exec\"]\n\
             [[rule]]\nagents = [\"dev\"]\nhosts = [\"alpha\"]\ntools = [\"ssh_exec\"]\nsudo = true\n\
             [[rule]]\nagents = [\"dev\"]\nhosts = [\"alpha\"]\ntools = [\"service_control\"]\n\
             [[rule]]\nagents = [\"dev\"]\nhosts = [\"web-1\"]\ntools = [\"ssh_sudo_exec\"]\nsudo = true\napproval = \"human\"\n",
        );
        assert_eq!(
            f,
            [
                "warning: policy.toml:5: shadowed: every call it matches is decided first by \
                 policy.toml:1",
                "warning: policy.toml:9: matches no call: sudo = true, but none of its tools is \
                 ever root-capable — drop sudo = true",
                "warning: policy.toml:14: matches no call: its tools are always root-capable, \
                 which only a rule with sudo = true can grant",
            ]
        );
    }

    fn store_with(agents_toml: &str, dir: &Path) -> AgentStore {
        let path = dir.join("agents.toml");
        std::fs::write(&path, agents_toml).unwrap();
        AgentStore::load_from(path).unwrap()
    }

    fn ctx_for(agent: Option<&str>) -> CallCtx {
        let mut c = CallCtx::new(None);
        c.agent = agent.map(|n| crate::ctx::Agent {
            name: n.into(),
            // Deliberately stale: the enforcer must not trust these.
            groups: vec!["ops".into()],
        });
        c
    }

    /// Groups come from the live store at decision time, by name — not
    /// from the identity snapshotted when the caller authenticated.
    #[test]
    fn enforcer_reads_groups_and_revocation_from_the_live_store() {
        let dir = tempfile::tempdir().unwrap();
        let h = "0".repeat(64);
        let agents = store_with(
            &format!("[agent.eve]\ngroups = [\"web\"]\ntoken_sha256 = \"{h}\"\n"),
            dir.path(),
        );
        let pol = Policy::from_toml_str(
            "[[rule]]\nagents = [\"group:ops\"]\nhosts = [\"*\"]\ntools = [\"ssh_exec\"]\n",
            "policy.toml",
        )
        .unwrap();
        let e = Enforcer {
            policy: PolicyStore::new(pol, None),
            agents: agents.clone(),
            approvals: Default::default(),
        };
        let inv = inv();
        let host = Some(("alpha", inv.get("alpha").unwrap()));
        // The ctx claims ops; the live store says web.
        let err = e
            .check(&ctx_for(Some("eve")), "ssh_exec", host, false)
            .unwrap_err();
        assert_eq!(err.class, ErrorClass::RefusedPolicy);
        assert_eq!(err.rule.as_deref(), Some(DEFAULT_DENY));

        std::fs::write(
            dir.path().join("agents.toml"),
            format!("[agent.eve]\ngroups = [\"ops\"]\ntoken_sha256 = \"{h}\"\n"),
        )
        .unwrap();
        agents.reload().unwrap();
        assert_eq!(
            e.check(&ctx_for(Some("eve")), "ssh_exec", host, false)
                .unwrap()
                .rule,
            "policy.toml:1"
        );

        std::fs::write(
            dir.path().join("agents.toml"),
            format!("[agent.eve]\ngroups = [\"ops\"]\ntoken_sha256 = \"{h}\"\ndisabled = true\n"),
        )
        .unwrap();
        agents.reload().unwrap();
        let err = e
            .check(&ctx_for(Some("eve")), "ssh_exec", host, false)
            .unwrap_err();
        assert!(err.message.contains("revoked"), "{}", err.message);

        std::fs::write(dir.path().join("agents.toml"), "").unwrap();
        agents.reload().unwrap();
        let err = e
            .check(&ctx_for(Some("eve")), "ssh_exec", host, false)
            .unwrap_err();
        assert!(
            err.message.contains("not in agents.toml"),
            "{}",
            err.message
        );

        let err = e
            .check(&ctx_for(None), "ssh_exec", host, false)
            .unwrap_err();
        assert_eq!(err.class, ErrorClass::RefusedPolicy);
    }

    #[test]
    fn enforcer_grants_with_the_rules_approval() {
        let pol = Policy::from_toml_str(
            "[[rule]]\nagents = [\"anonymous\"]\nhosts = [\"*\"]\ntools = [\"*\"]\napproval = \"ticket\"\n",
            "policy.toml",
        )
        .unwrap();
        let e = Enforcer {
            policy: PolicyStore::new(pol, None),
            agents: AgentStore::default(),
            approvals: Default::default(),
        };
        let g = e
            .check(&ctx_for(Some("anonymous")), "prompto_gain", None, false)
            .unwrap();
        assert_eq!(
            g,
            Grant {
                rule: "policy.toml:1".into(),
                approval: Approval::Ticket
            }
        );
        // The ticket check is authz's: with none and no key configured,
        // the call is refused naming the rule and why.
        let err = authz::authorize_tool(Some(&e), &ctx_for(Some("anonymous")), "prompto_gain")
            .unwrap_err();
        assert_eq!(err.class, ErrorClass::ApprovalRequired);
        assert_eq!(err.data()["rule"], "policy.toml:1");
        assert!(
            err.message.contains("no ticket key configured"),
            "{}",
            err.message
        );
    }

    #[test]
    fn store_reload_swaps_and_keeps_old_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let grant = "[[rule]]\nagents = [\"dev\"]\nhosts = [\"*\"]\ntools = [\"ssh_exec\"]\n";
        std::fs::write(&path, grant).unwrap();
        let store = PolicyStore::load_from(path.clone()).unwrap();
        assert_eq!(store.snapshot().rules.len(), 1);
        std::fs::write(&path, format!("{grant}{grant}")).unwrap();
        assert_eq!(store.reload().unwrap(), 2);
        std::fs::write(&path, "[[rule]]\nagents = \"dev\"\n").unwrap();
        assert!(store.reload().is_err());
        // Fail closed: the previous (possibly broader) policy is dropped.
        let live = store.snapshot();
        assert!(live.rules.is_empty(), "kept the previous policy");
        let bad = live.invalid.as_ref().expect("marked invalid");
        let d = decide(&live, "dev", &[], Some("alpha"), "ssh_exec", false);
        assert_eq!(d.outcome, Outcome::Deny);
        assert_eq!(d.rule, DEFAULT_DENY);
        assert_eq!(
            d.message,
            format!(
                "refused_policy: agent dev has no grant for ssh_exec on alpha (policy file \
                 invalid since {}). Ask the operator for a policy.toml rule if you need it.",
                bad.since
            )
        );
        // Neither the parser's detail nor the path reaches the agent.
        assert!(!d.message.contains(&bad.error), "{}", d.message);
        assert!(!d.message.contains("policy.toml\""), "{}", d.message);
        assert!(bad.error.contains("invalid type"), "{}", bad.error);
        // A valid file lifts it.
        std::fs::write(&path, grant).unwrap();
        assert_eq!(store.reload().unwrap(), 1);
        assert!(store.snapshot().invalid.is_none());
        std::fs::remove_file(&path).unwrap();
        assert_eq!(store.reload().unwrap(), 0);
        assert!(
            store.snapshot().missing.is_some(),
            "a vanished file is deny-all"
        );
    }

    /// An edit to policy.toml applies to the next decision without
    /// SIGHUP — atomic replace, in-place edit, a broken edit (fail
    /// closed), deletion — and an unchanged file keeps its snapshot.
    #[test]
    fn enforcer_follows_the_policy_file_without_sighup() {
        let dir = tempfile::tempdir().unwrap();
        let h = "0".repeat(64);
        let agents = store_with(
            &format!("[agent.eve]\ntoken_sha256 = \"{h}\"\n"),
            dir.path(),
        );
        let path = dir.path().join("policy.toml");
        let grant = |tool: &str| {
            format!("[[rule]]\nagents = [\"eve\"]\nhosts = [\"*\"]\ntools = [\"{tool}\"]\n")
        };
        std::fs::write(&path, grant("ssh_exec")).unwrap();
        let e = Enforcer {
            policy: PolicyStore::load_from(path.clone()).unwrap(),
            agents,
            approvals: Default::default(),
        };
        let ok = |tool: &str| e.check(&ctx_for(Some("eve")), tool, None, false).is_ok();
        assert!(ok("ssh_exec") && !ok("file_read"));
        // Old enough for its stamp to be trusted (`stamp::Seen`).
        std::thread::sleep(std::time::Duration::from_millis(2100));
        assert!(ok("ssh_exec"));
        let before = e.policy.snapshot();
        assert!(ok("ssh_exec"));
        assert!(
            Arc::ptr_eq(&before, &e.policy.snapshot()),
            "re-read unchanged"
        );

        // Atomic replace (new inode).
        let tmp = dir.path().join("policy.toml.new");
        std::fs::write(&tmp, grant("file_read")).unwrap();
        std::fs::rename(&tmp, &path).unwrap();
        assert!(ok("file_read") && !ok("ssh_exec"));
        // In place, same inode, same size.
        std::fs::write(&path, grant("file_list")).unwrap();
        assert!(ok("file_list") && !ok("file_read"));
        // Broken: deny-all, marked invalid — never the previous rules.
        std::fs::write(&path, "[[rule]]\nagents = \"eve\"\n").unwrap();
        assert!(!ok("file_list"));
        assert!(e.policy.snapshot().invalid.is_some());
        std::fs::write(&path, grant("ssh_exec")).unwrap();
        assert!(ok("ssh_exec"));
        assert!(e.policy.snapshot().invalid.is_none());
        // Gone: deny-all.
        std::fs::remove_file(&path).unwrap();
        assert!(!ok("ssh_exec"));
        assert!(e.policy.snapshot().missing.is_some());
        // SIGHUP still works, and records what it read: no second read.
        std::fs::write(&path, grant("ssh_exec")).unwrap();
        assert_eq!(e.policy.reload().unwrap(), 1);
        assert!(ok("ssh_exec"));
    }

    /// The deny message carries the error's line and column but not the
    /// policy line the `toml` crate quotes.
    #[test]
    fn invalid_error_is_one_line_without_the_source_excerpt() {
        let e = Policy::from_toml_str("[[rule]]\nagents = 1 # some-comment\n", "policy.toml")
            .unwrap_err();
        assert!(format!("{e:#}").contains("some-comment"), "{e:#}");
        let bad = Invalid::new(&e);
        assert_eq!(
            bad.error,
            "parse policy TOML: TOML parse error at line 2, column 10: invalid type: integer \
             `1`, expected a sequence"
        );
        chrono::DateTime::parse_from_rfc3339(&bad.since).unwrap();
    }

    /// The inventory tools show a host when any rule grants the agent a
    /// host-targeting tool there, and the vault path only with a sudo
    /// grant. Hostless grants don't count, whatever their `hosts` say.
    #[test]
    fn visibility_follows_grants() {
        let p = Policy::from_toml_str(
            "[[rule]]\nagents = [\"dev\"]\nhosts = [\"alpha\"]\ntools = [\"host_status\"]\n\
             [[rule]]\nagents = [\"dev\"]\nhosts = [\"bravo\"]\ntools = [\"file_write\"]\nsudo = true\n\
             [[rule]]\nagents = [\"dev\"]\nhosts = [\"*\"]\ntools = [\"inventory_list\"]\n\
             [[rule]]\nagents = [\"eve\"]\nhosts = [\"web-1\"]\ntools = [\"ssh_exec\"]\napproval = \"human\"\n",
            "policy.toml",
        )
        .unwrap();
        let inv = inv();
        let see = |agent: &str, host: &str| {
            p.visibility(
                Subject {
                    name: agent,
                    groups: &[],
                },
                Target::of(host, inv.get(host).unwrap()),
                &tools(),
            )
        };
        let v = |listed, sudo| Visibility { listed, sudo };
        assert_eq!(see("dev", "alpha"), v(true, false));
        assert_eq!(see("dev", "bravo"), v(true, true));
        assert_eq!(
            see("dev", "web-1"),
            v(false, false),
            "inventory_list is hostless"
        );
        assert_eq!(
            see("eve", "web-1"),
            v(true, false),
            "an approval rule is a grant"
        );
        assert_eq!(see("eve", "alpha"), v(false, false));
    }

    #[test]
    fn shipped_example_parses() {
        let p = Policy::from_toml_str(include_str!("../deploy/policy.toml.example"), "policy.toml")
            .unwrap();
        assert_eq!(p.rules.len(), 6);
        assert_eq!(p.rules[0].name(), "policy.toml:33 (infra-router-sudo)");
    }

    #[test]
    fn glob_matching() {
        for (p, s, want) in [
            ("*", "anything", true),
            ("*", "", true),
            ("sbx-*", "sbx-t1", true),
            ("sbx-*", "sbx-", true),
            ("sbx-*", "sbx", false),
            ("*-t?", "sbx-t1", true),
            ("*-t?", "sbx-t12", false),
            ("file_*", "file_write", true),
            ("file_*", "ssh_exec", false),
            ("ssh_exec", "ssh_exec", true),
            ("ssh_exec", "ssh_exec2", false),
            ("*exec", "ssh_sudo_exec", true),
            ("a*b*c", "aXbYbZc", true),
            ("a*b*c", "aXbYcZ", false),
            ("?", "", false),
        ] {
            assert_eq!(Glob::new(p).matches(s), want, "{p} vs {s}");
        }
    }
}
