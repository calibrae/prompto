#!/usr/bin/env bash
# prompto macOS bench (Mac host): tart VM "bench-mac" + dev OpenBao + prompto.
#   run.sh start|stop|status        NET_MODE=softnet (default) | nat
#   run.sh tunnel-start|tunnel-stop|tunnel-status   one-way reverse tunnel into the sandbox host
#     needs $B/tunnel.conf with TUNNEL_HOST=<koichi-lan-ip>, key $B/tunnel_ed25519
# Nothing here auto-starts at boot. Secrets live only under $B/secrets (0600).
set -euo pipefail
B=${BENCH_DIR:-$HOME/bench-mac}
export TART_HOME=${TART_HOME:-/Volumes/2TB/tart}
export PATH=/opt/homebrew/bin:$HOME/.cargo/bin:$PATH
VM=bench-mac; PORT=6399; BAO_PORT=8211
NET_MODE=${NET_MODE:-softnet}
R=$B/run; S=$B/secrets
mkdir -p "$R" "$S"; chmod 700 "$S"
TUNNEL_PORT=2222; TUNNEL_BIND=192.168.122.1
[[ -f $B/tunnel.conf ]] && . "$B/tunnel.conf"
alive() { [[ -f $R/$1.pid ]] && kill -0 "$(cat "$R/$1.pid")" 2>/dev/null; }

start() {
  umask 077
  # 1. VM
  if ! alive vm; then
    flags=(--no-graphics)
    [[ $NET_MODE == softnet ]] && flags+=(--net-softnet)
    nohup tart run "$VM" "${flags[@]}" > "$B/vm.log" 2>&1 &
    echo $! > "$R/vm.pid"
  fi
  IP=$(tart ip "$VM" --wait 180)
  echo "vm ip: $IP (net: $NET_MODE)"
  echo "$IP" > "$R/vm.ip"
  # 2. dev OpenBao (in-memory: secrets rewritten on every start)
  [[ -f $S/bao-root-token ]] || head -c 24 /dev/urandom | base64 | tr -d '/+=\n' > "$S/bao-root-token"
  if ! alive bao; then
    nohup bao server -dev -dev-listen-address=127.0.0.1:$BAO_PORT \
      -dev-root-token-id="$(cat "$S/bao-root-token")" > "$B/bao.log" 2>&1 &
    echo $! > "$R/bao.pid"
  fi
  export BAO_ADDR=http://127.0.0.1:$BAO_PORT
  export BAO_TOKEN; BAO_TOKEN=$(cat "$S/bao-root-token")
  for _ in $(seq 40); do bao status >/dev/null 2>&1 && break; sleep 0.5; done
  tr -d '\n' < "$S/sudo-password" | bao kv put secret/prompto/sudo-default password=- >/dev/null
  printf 'path "secret/data/prompto/*" { capabilities = ["read"] }\n' | bao policy write prompto-read - >/dev/null
  bao token create -policy=prompto-read -period=768h -orphan -field=token > "$S/prompto-vault-token"
  unset BAO_TOKEN
  # 3. prompto
  cat > "$B/prompto.toml" <<TOML
[host.bench-mac]
ip = "$IP"
ssh_user = "ops"
ssh_key = "$B/bench_ed25519"
platform = "macos"
capabilities = ["exec", "sudo_exec"]
sudo_password_vault_path = "prompto/sudo-default"
nopasswd_sudo = false
TOML
  if ! alive prompto; then
    PROMPTO_INVENTORY=$B/prompto.toml PROMPTO_BIND=127.0.0.1:$PORT PROMPTO_ALLOWED_HOSTS='*' \
    PROMPTO_AUTH=off PROMPTO_VAULT_ADDR=http://127.0.0.1:$BAO_PORT \
    PROMPTO_VAULT_TOKEN=$(cat "$S/prompto-vault-token") \
    PROMPTO_USAGE_LOG=$B/usage.jsonl PROMPTO_AUDIT_LOG=$B/audit.jsonl RUST_LOG=prompto=info \
      nohup "$B/prompto/target/release/prompto" > "$B/prompto.log" 2>&1 &
    echo $! > "$R/prompto.pid"
  else
    kill -HUP "$(cat "$R/prompto.pid")"   # inventory reload (VM IP may have changed)
  fi
  sleep 1; status
  tunnel_start
}

stop() {
  tunnel_stop
  for p in prompto bao; do alive $p && kill "$(cat "$R/$p.pid")" || true; rm -f "$R/$p.pid"; done
  tart stop "$VM" 2>/dev/null || true
  alive vm && kill "$(cat "$R/vm.pid")" 2>/dev/null || true
  rm -f "$R/vm.pid"; echo stopped
}

status() {
  for p in vm bao prompto; do alive $p && echo "$p: up (pid $(cat "$R/$p.pid"))" || echo "$p: down"; done
  tart list 2>/dev/null | grep -E "Name|$VM" || true
  [[ -f $R/vm.ip ]] && echo "vm ip: $(cat "$R/vm.ip")"
  echo "prompto: http://127.0.0.1:$PORT/mcp"
}

# Reverse tunnel: sandbox host $TUNNEL_BIND:$TUNNEL_PORT -> VM sshd. Only this one forward is
# permitted by the sandbox host's authorized_keys (permitlisten). Reconnect loop, no autostart.
tunnel_start() {
  : "${TUNNEL_HOST:?set TUNNEL_HOST in $B/tunnel.conf}"
  if alive tunnel; then echo "tunnel: already up"; return; fi
  local ip; ip=$(cat "$R/vm.ip" 2>/dev/null) || { echo "tunnel: no VM ip (start first)" >&2; return 1; }
  nohup bash -c 'while :; do
    ssh -N -i "$1" -o IdentitiesOnly=yes -o BatchMode=yes -o ExitOnForwardFailure=yes \
      -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
      -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$2" \
      -R "$3:$4:$5:22" "sbxtunnel@$6"
    sleep 5
  done' _ "$B/tunnel_ed25519" "$B/known_hosts_tunnel" "$TUNNEL_BIND" "$TUNNEL_PORT" "$ip" "$TUNNEL_HOST" \
    > "$B/tunnel.log" 2>&1 &
  echo $! > "$R/tunnel.pid"; echo "tunnel: started (pid $!)"
}
tunnel_stop() {
  if alive tunnel; then pkill -P "$(cat "$R/tunnel.pid")" 2>/dev/null || true; kill "$(cat "$R/tunnel.pid")" 2>/dev/null || true; fi
  rm -f "$R/tunnel.pid"; echo "tunnel: stopped"
}
tunnel_status() {
  alive tunnel && echo "tunnel: up (pid $(cat "$R/tunnel.pid"))" || echo "tunnel: down"
  tail -n 3 "$B/tunnel.log" 2>/dev/null || true
}

case ${1:-} in start) start;; stop) stop;; status) status;; tunnel-start) tunnel_start;; tunnel-stop) tunnel_stop;; tunnel-status) tunnel_status;; *) echo "usage: $0 start|stop|status|tunnel-start|tunnel-stop|tunnel-status" >&2; exit 2;; esac
