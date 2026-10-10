#!/bin/bash
# Task 022 continuity proof: run examples/loadgen against sandbox prompto
# on sbx-core while, in sequence, 5 SIGHUPs, 3 policy edits and 3 binary
# redeploys (~/deploy-core.sh: binary handover) happen. Every event's time
# goes to events.txt, which loadgen's summary uses for the latency around
# each one.
#
#   sandbox/loadgen/run-proof.sh <out dir> [loadgen secs]
#
# Needs the loadgen agents (group loadgen, tokens in
# ~/.config/prompto/loadgen/, mode 0600) and sandbox/loadgen/policy-loadgen.toml
# appended to sbx-core's policy.
set -euo pipefail
OUT=${1:?out dir}; SECS=${2:-720}
mkdir -p "$OUT"; : > "$OUT/events.txt"; : > "$OUT/calls.jsonl"
cd ~/prompto
. ~/.cargo/env
cargo build -q --release --example loadgen
ev() { echo "$(date +%s%3N) $1" >> "$OUT/events.txt"; echo "== $(date +%T) $1"; }

# A policy edit: add or drop a rule no loadgen call depends on, written
# atomically (temp file + rename, as the README asks).
policy_edit() {
  ssh sbx-core "sudo MODE=$1 bash -s" <<'REMOTE'
set -euo pipefail
p=/etc/prompto/policy.toml
t=$(mktemp /etc/prompto/.policy.XXXXXX)
if [ "$MODE" = add ]; then
  cat $p > $t
  printf '\n[[rule]] # proof-edit\nid = "proof-edit"\nagents = ["sbx-tmp-005"]\nhosts = ["sbx-t1"]\ntools = ["host_status"]\n' >> $t
else
  python3 - "$p" > $t <<'PY'
import re, sys
s = open(sys.argv[1]).read()
print(re.sub(r'\n\[\[rule\]\] # proof-edit\n(?:[^\[\n].*\n?)*', '\n', s).rstrip('\n'))
PY
fi
chown root:prompto $t; chmod 640 $t; mv $t $p
grep -c proof-edit $p || true
REMOTE
}

./target/release/examples/loadgen --url http://sbx-core:6337 \
  --tokens ~/.config/prompto/loadgen --secs "$SECS" \
  --out "$OUT/calls.jsonl" --events "$OUT/events.txt" \
  > "$OUT/summary.md" 2> "$OUT/loadgen.stderr" &
LG=$!
ev "loadgen-start"

at() { local t=$1; while [ $(( $(date +%s) - START )) -lt "$t" ]; do sleep 1; done; }
START=$(date +%s)
at 60;  ev "sighup-1";   ssh sbx-core 'sudo systemctl reload prompto-dev'
at 90;  ev "policy-edit-1"; policy_edit add
at 120; ev "redeploy-1"; ~/deploy-core.sh 2>&1 | sed 's/^/   /'
at 200; ev "sighup-2";   ssh sbx-core 'sudo systemctl reload prompto-dev'
at 230; ev "policy-edit-2"; policy_edit drop
at 260; ev "redeploy-2"; ~/deploy-core.sh 2>&1 | sed 's/^/   /'
at 340; ev "sighup-3";   ssh sbx-core 'sudo systemctl reload prompto-dev'
at 370; ev "policy-edit-3"; policy_edit add
at 400; ev "redeploy-3"; ~/deploy-core.sh 2>&1 | sed 's/^/   /'
at 480; ev "sighup-4";   ssh sbx-core 'sudo systemctl reload prompto-dev'
at 520; ev "sighup-5";   ssh sbx-core 'sudo systemctl reload prompto-dev'
echo "== events done; waiting for loadgen (in-flight long calls finish)"
set +e
wait $LG; rc=$?
policy_edit drop >/dev/null
echo "== loadgen exit $rc"
cat "$OUT/summary.md"
exit $rc
