//! Task → resource routing for `claude_exec`.
//!
//! Maps a semantic tier (`fast` / `balanced` / `deep`) to concrete
//! gateway primitives (`backend`, `model`, `effort`). The gateway
//! ([apytti](../../apytti)) stays a dumb dispatcher; the *opinion*
//! about which model fits which task lives here, where the homelab
//! context already lives.
//!
//! The default tier table below is hand-tuned for Cali's setup
//! (Claude Pro/Max subscription rides through `claude -p`). Override
//! by passing explicit `backend` / `model` / `effort` on a call —
//! the tier is advisory only.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Triage / verify / one-line answers. Cheap, fast, low context.
    Fast,
    /// Diagnostic walks, log analysis, multi-step reasoning. Default.
    #[default]
    Balanced,
    /// Refactors, architecture explanations, real fuckeries.
    Deep,
}

#[derive(Debug, Clone, Serialize)]
pub struct Resolved {
    pub backend: &'static str,
    pub model: &'static str,
    pub effort: &'static str,
}

impl Tier {
    pub fn resolve(self) -> Resolved {
        match self {
            Tier::Fast => Resolved {
                backend: "claude",
                model: "haiku",
                effort: "low",
            },
            Tier::Balanced => Resolved {
                backend: "claude",
                model: "sonnet",
                effort: "medium",
            },
            Tier::Deep => Resolved {
                backend: "claude",
                model: "opus",
                effort: "high",
            },
        }
    }
}

/// Final wire choice for a `claude_exec` call. Explicit fields win
/// over the tier; missing explicit fields fall back to the tier's
/// resolution.
#[derive(Debug, Clone, Serialize)]
pub struct Route {
    pub backend: String,
    pub model: String,
    pub effort: String,
    pub tier: Option<Tier>,
}

/// Resolve a (tier, optional override) pair into the concrete
/// primitives apytti expects.
pub fn route(
    tier: Option<Tier>,
    backend: Option<&str>,
    model: Option<&str>,
    effort: Option<&str>,
) -> Route {
    let t = tier.unwrap_or_default();
    let r = t.resolve();
    Route {
        backend: backend.unwrap_or(r.backend).to_string(),
        model: model.unwrap_or(r.model).to_string(),
        effort: effort.unwrap_or(r.effort).to_string(),
        tier,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_balanced() {
        assert_eq!(Tier::default(), Tier::Balanced);
    }

    #[test]
    fn fast_resolves_to_haiku() {
        let r = Tier::Fast.resolve();
        assert_eq!(r.model, "haiku");
        assert_eq!(r.effort, "low");
    }

    #[test]
    fn deep_resolves_to_opus() {
        let r = Tier::Deep.resolve();
        assert_eq!(r.model, "opus");
        assert_eq!(r.effort, "high");
    }

    #[test]
    fn explicit_overrides_tier() {
        let r = route(Some(Tier::Fast), Some("gemini"), Some("flash"), None);
        assert_eq!(r.backend, "gemini");
        assert_eq!(r.model, "flash");
        assert_eq!(r.effort, "low"); // tier still drove effort
    }

    #[test]
    fn no_tier_no_override_defaults_to_balanced() {
        let r = route(None, None, None, None);
        assert_eq!(r.backend, "claude");
        assert_eq!(r.model, "sonnet");
        assert_eq!(r.effort, "medium");
    }
}
