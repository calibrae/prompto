#!/usr/bin/env bash
# Install prompto as a systemd service. Idempotent.
# Usage:  sudo ./install.sh /path/to/prompto-binary
# Places the binary at /opt/prompto/bin/prompto, creates the `prompto` system
# user, installs the unit + env file, and seeds /etc/prompto.toml from the
# example if missing. Does NOT start the service — review config first, then:
#   sudo systemctl enable --now prompto

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

BIN="${1:-}"
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
    echo "usage: sudo $0 <path-to-prompto-binary>" >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"

# System user (no shell, system home for any state).
if ! id prompto >/dev/null 2>&1; then
    useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/prompto \
        --create-home --user-group prompto
fi

install -d -o prompto -g prompto -m 0750 /var/lib/prompto
install -d -m 0755 /opt/prompto /opt/prompto/bin
install -d -o root -g prompto -m 0750 /etc/prompto /etc/prompto/keys

# Binary.
install -m 0755 "$BIN" /opt/prompto/bin/prompto

# Env file: never overwrite an existing one.
if [[ ! -f /etc/prompto/env ]]; then
    install -m 0640 -o root -g prompto "$HERE/env.example" /etc/prompto/env
    echo "wrote default /etc/prompto/env — review before starting"
fi

# Inventory: seed if missing.
if [[ ! -f /etc/prompto.toml ]]; then
    if [[ -f "$HERE/prompto.toml.example" ]]; then
        install -m 0640 -o root -g prompto "$HERE/prompto.toml.example" /etc/prompto.toml
        echo "wrote default /etc/prompto.toml from example — edit it before starting"
    else
        echo "note: no prompto.toml.example next to install.sh — supply /etc/prompto.toml yourself"
    fi
fi

# systemd unit.
install -m 0644 "$HERE/prompto.service" /etc/systemd/system/prompto.service
systemctl daemon-reload

cat <<'EOF'

prompto installed. Next steps:
  1. Drop SSH keys into /etc/prompto/keys/ (chown root:prompto, chmod 0640).
  2. Edit /etc/prompto.toml (host inventory) and /etc/prompto/env.
  3. sudo systemctl enable --now prompto
  4. sudo systemctl status prompto
  5. From any client:  claude mcp add --transport http prompto http://YOUR-HOST:6337/mcp
EOF
