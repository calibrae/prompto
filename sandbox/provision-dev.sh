#!/usr/bin/env bash
# Provision sbx-dev: the sandbox dev agent's workstation. Runs inside the
# guest as `ops`. Idempotent. Log: ~/provision.log.
set -euo pipefail
exec > >(tee -a "$HOME/provision.log") 2>&1
stage() { echo "== $*"; }

stage packages
sudo apt-get -qq update
sudo DEBIAN_FRONTEND=noninteractive apt-get -qq install -y \
  build-essential pkg-config git curl jq ca-certificates musl-tools tmux ripgrep openssh-client >/dev/null
stage "packages ok"

stage rust
[[ -x $HOME/.cargo/bin/cargo ]] || curl -fsSL https://sh.rustup.rs | sh -s -- -y -q --profile default >/dev/null
. "$HOME/.cargo/env"
rustup target add x86_64-unknown-linux-musl >/dev/null
stage "rust ok ($(rustc --version))"

stage claude
command -v claude >/dev/null || [[ -x $HOME/.local/bin/claude ]] || curl -fsSL https://claude.ai/install.sh | bash >/dev/null
grep -q '.local/bin' "$HOME/.bashrc" || echo 'export PATH=$HOME/.local/bin:$HOME/.cargo/bin:$PATH' >> "$HOME/.bashrc"
stage "claude ok ($("$HOME/.local/bin/claude" --version 2>/dev/null || echo installed))"

stage repo
[[ -d $HOME/prompto ]] || git clone -q https://github.com/calibrae/prompto "$HOME/prompto"
stage "repo ok ($(git -C "$HOME/prompto" log --oneline -1))"
stage "ALL DONE"
