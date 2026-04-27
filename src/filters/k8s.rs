//! Kubernetes / Helm output compaction. Both tools generate huge tables
//! and verbose describe output; cap conservatively.

use std::borrow::Cow;

use super::CommandFilter;

const KUBECTL_LINE_CAP: usize = 100;
const HELM_LINE_CAP: usize = 50;

pub struct Kubectl;

impl CommandFilter for Kubectl {
    fn name(&self) -> &'static str {
        "kubectl"
    }

    fn matches(&self, cmd: &str) -> bool {
        cmd.split_whitespace()
            .find(|t| !t.contains('='))
            .map(|t| t == "kubectl")
            .unwrap_or(false)
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        cap(stdout, KUBECTL_LINE_CAP, "kubectl")
    }
}

pub struct Helm;

impl CommandFilter for Helm {
    fn name(&self) -> &'static str {
        "helm"
    }

    fn matches(&self, cmd: &str) -> bool {
        cmd.split_whitespace()
            .find(|t| !t.contains('='))
            .map(|t| t == "helm")
            .unwrap_or(false)
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        cap(stdout, HELM_LINE_CAP, "helm")
    }
}

fn cap<'a>(stdout: &'a str, line_cap: usize, label: &str) -> Cow<'a, str> {
    let total = stdout.lines().count();
    if total <= line_cap {
        return Cow::Borrowed(stdout);
    }
    let mut out: String = stdout.lines().take(line_cap).collect::<Vec<_>>().join("\n");
    out.push('\n');
    out.push_str(&format!(
        "… {label} truncated ({line_cap} kept, {total} total)\n"
    ));
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kubectl_caps_at_100() {
        let s: String = (0..200).map(|i| format!("pod-{i} Running\n")).collect();
        let out = Kubectl.filter("kubectl get pods", &s);
        assert!(out.contains("kubectl truncated"));
        assert!(out.contains("200 total"));
    }

    #[test]
    fn kubectl_matches_invocations() {
        assert!(Kubectl.matches("kubectl get pods"));
        assert!(Kubectl.matches("kubectl describe pod foo"));
        assert!(Kubectl.matches("KUBECONFIG=/x kubectl get nodes"));
        assert!(!Kubectl.matches("docker run kubectl"));
        assert!(!Kubectl.matches("k9s"));
    }

    #[test]
    fn helm_caps_at_50() {
        let s: String = (0..80).map(|i| format!("release-{i} deployed\n")).collect();
        let out = Helm.filter("helm list", &s);
        assert!(out.contains("helm truncated"));
        assert!(out.contains("80 total"));
    }
}
