#!/usr/bin/env bash
# Provision sbx-core: build toolchain + prompto checkout, OpenBao, Kanidm.
# Runs inside the guest as the `ops` user (passwordless sudo). Idempotent.
# Log: ~/provision.log. Each stage prints "== <stage> ok" when done.
set -euo pipefail
exec > >(tee -a "$HOME/provision.log") 2>&1
stage() { echo "== $*"; }

stage packages
sudo apt-get -qq update
sudo DEBIAN_FRONTEND=noninteractive apt-get -qq install -y \
  build-essential pkg-config git curl jq ca-certificates gnupg musl-tools openssh-client >/dev/null
stage "packages ok"

stage rust
if ! command -v cargo >/dev/null && [[ ! -x $HOME/.cargo/bin/cargo ]]; then
  curl -fsSL https://sh.rustup.rs | sh -s -- -y -q --profile minimal >/dev/null
fi
. "$HOME/.cargo/env"
rustup target add x86_64-unknown-linux-musl >/dev/null
stage "rust ok ($(rustc --version))"

stage prompto
[[ -d $HOME/prompto ]] || git clone -q https://github.com/calibrae/prompto "$HOME/prompto"
git -C "$HOME/prompto" pull -q --ff-only
(cd "$HOME/prompto" && cargo build -q --release --target x86_64-unknown-linux-musl)
stage "prompto ok ($(git -C "$HOME/prompto" log --oneline -1))"

stage openbao
if ! command -v bao >/dev/null; then
  url=$(curl -fsSL https://api.github.com/repos/openbao/openbao/releases/latest \
    | jq -r '.assets[].browser_download_url | select(test("bao_[0-9.]+_linux_amd64\\.deb$"))' | head -1)
  curl -fsSL -o /tmp/bao.deb "$url"
  sudo DEBIAN_FRONTEND=noninteractive apt-get -qq install -y /tmp/bao.deb >/dev/null
  rm -f /tmp/bao.deb
fi
stage "openbao ok ($(bao version | head -1))"

stage kanidm
if ! command -v kanidmd >/dev/null; then
  curl -fsSL https://kanidm.github.io/kanidm_ppa/kanidm_ppa.asc \
    | sudo gpg --dearmor -o /usr/share/keyrings/kanidm_ppa.gpg
  echo "deb [signed-by=/usr/share/keyrings/kanidm_ppa.gpg] https://kanidm.github.io/kanidm_ppa trixie stable" \
    | sudo tee /etc/apt/sources.list.d/kanidm_ppa.list >/dev/null
  sudo apt-get -qq update
  sudo DEBIAN_FRONTEND=noninteractive apt-get -qq install -y kanidm kanidmd >/dev/null
fi
stage "kanidm ok ($(kanidmd version 2>/dev/null | head -1 || echo installed))"

stage "ALL DONE"
