#!/bin/bash
# Task 024 continuity proof, shorter: examples/loadgen (12 agents) against
# sandbox prompto on sbx-core while 2 binary handovers (~/deploy-core.sh)
# and 1 plain `systemctl restart` happen, plus a SIGHUP and a policy edit.
# A plain restart has no successor: until the old process has drained,
# connections are refused (or answered 503), so loadgen runs with
# --retry-secs, retrying only requests that provably did not run.
#
#   sandbox/loadgen/run-proof-024.sh <out dir> [loadgen secs]
set -euo pipefail
OUT=${1:?out dir}; SECS=${2:-480}
mkdir -p "$OUT"; : > "$OUT/events.txt"; : > "$OUT/calls.jsonl"
cd ~/prompto
. ~/.cargo/env
cargo build -q --release --example loadgen
ev() { echo "$(date +%s%3N) $1" >> "$OUT/events.txt"; echo "== $(date +%T) $1"; }
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
  --long-min 30 --long-max 90 --retry-secs 300 \
  --out "$OUT/calls.jsonl" --events "$OUT/events.txt" \
  > "$OUT/summary.md" 2> "$OUT/loadgen.stderr" &
LG=$!
ev "loadgen-start"
at() { local t=$1; while [ $(( $(date +%s) - START )) -lt "$t" ]; do sleep 1; done; }
START=$(date +%s)
at 40;  ev "sighup-1";      ssh sbx-core 'sudo systemctl reload prompto-dev'
at 70;  ev "handover-1";    ~/deploy-core.sh 2>&1 | sed 's/^/   /'
at 110; ev "policy-edit-1"; policy_edit add
at 150; ev "handover-2";    ~/deploy-core.sh 2>&1 | sed 's/^/   /'
at 220; ev "restart-1"
t0=$(date +%s); ssh sbx-core 'sudo systemctl restart prompto-dev'
echo "   restart took $(( $(date +%s) - t0 ))s"
ev "restart-1-done"
at 400; ev "sighup-2";      ssh sbx-core 'sudo systemctl reload prompto-dev'
echo "== events done; waiting for loadgen"
set +e
wait $LG; rc=$?
policy_edit drop >/dev/null
echo "== loadgen exit $rc"
cat "$OUT/summary.md"
exit $rc
