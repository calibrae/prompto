#!/bin/bash
# Build the current checkout (musl) and run it as prompto-dev on sbx-core
# (installed as ~/deploy-core.sh on sbx-dev).
#
#   deploy-core.sh            binary handover (SIGUSR2): the new binary takes
#                             the listening socket, the old process drains its
#                             calls in flight — no gap, no failed call
#   deploy-core.sh --restart  systemctl restart (SIGTERM drain, then start)
#
# Falls back to a restart when the running binary doesn't advertise the
# handover (its systemd status text), e.g. the first deploy of E11.
set -euo pipefail
. ~/.cargo/env
MODE=handover
[ "${1:-}" = --restart ] && MODE=restart
cd ~/prompto
cargo build -q --release --target x86_64-unknown-linux-musl
scp -q target/x86_64-unknown-linux-musl/release/prompto sbx-core:/tmp/prompto-dev.new
ssh sbx-core "MODE=$MODE bash -s" <<'REMOTE'
set -euo pipefail
u=prompto-dev
sudo install -m755 /tmp/prompto-dev.new /usr/local/bin/prompto-dev
status=$(systemctl show -p StatusText --value $u)
if [ "$MODE" = handover ] && systemctl is-active -q $u && [[ $status == *"SIGUSR2 = binary handover"* ]]; then
  old=$(systemctl show -p MainPID --value $u)
  sudo systemctl kill -s SIGUSR2 --kill-whom=main $u
  new=$old
  for _ in $(seq 1 140); do
    new=$(systemctl show -p MainPID --value $u)
    [ "$new" != "$old" ] && [ "$new" != 0 ] && break
    sleep 0.5
  done
  if [ "$new" = "$old" ]; then
    echo "handover did not happen; still running $old. Journal:" >&2
    sudo journalctl -u $u -n 20 --no-pager >&2
    exit 1
  fi
  echo "handover: PID $old -> $new (the old one drains its calls in flight)"
else
  echo "restart ($MODE; status: ${status:-none})"
  sudo systemctl restart $u
fi
sleep 1
systemctl is-active $u
REMOTE
