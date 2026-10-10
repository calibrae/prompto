#!/usr/bin/env bash
# usage: tf.sh <persistent|disposable|init|validate...> <tofu subcommand> [args...]
#   tf.sh disposable plan
#   tf.sh disposable apply -var prefix=tsbx- -var host_offset=30 ...
# Run on the libvirt host as the sandbox owner. Secrets go into the
# environment only; nothing is echoed. Needs sudo -n to read the root-owned
# sudo-password file.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
stack=${1:?stack: persistent|disposable}; shift
S=${SBX_STATE:-$HOME/sandbox}/secrets
PP=$S/tofu-passphrase

if [[ ! -f $PP ]]; then
  (umask 077; head -c 32 /dev/urandom | base64 | tr -d '\n' > "$PP")
fi
export TF_VAR_state_passphrase=$(cat "$PP")
# Deterministic salt (derived from the passphrase) keeps the hash stable
# across runs so plans are not noisy. The clear password never leaves this pipe.
salt=$(printf %s "$TF_VAR_state_passphrase" | sha256sum | cut -c1-16)
if [[ -r $S/sudo-password ]]; then pwf=cat; else pwf="sudo -n cat"; fi
export TF_VAR_sudo_password_hash=$($pwf "$S/sudo-password" | openssl passwd -6 -salt "$salt" -stdin)
export TF_VAR_ssh_pubkey=$(cat "$S/sbx_ed25519.pub")
export PATH=$HOME/.local/bin:$PATH
cd "$here/stacks/$stack"
exec tofu "$@"
