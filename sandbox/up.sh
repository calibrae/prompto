#!/usr/bin/env bash
# prompto sandbox — three Debian 13 KVM guests on one libvirt host.
#
#   sbx-core  control plane: prompto-dev, OpenBao, Kanidm   (passwordless sudo)
#   sbx-t1    managed target: passwordless sudo, static key
#   sbx-t2    managed target: password sudo                 (vault-sudo path)
#
# Everything sandbox-only: its own SSH key, its own sudo password, its own
# network (libvirt "default" NAT). Nothing here can reach a credential that
# works outside the sandbox.
#
# Run as root on the libvirt host:  sudo SBX_OWNER=$USER ./sandbox/up.sh
# Re-running is safe: existing guests are left alone.
set -euo pipefail

OWNER=${SBX_OWNER:?set SBX_OWNER to the unprivileged user that owns the sandbox}
OWNER_HOME=$(getent passwd "$OWNER" | cut -d: -f6)
STATE=${SBX_STATE:-$OWNER_HOME/sandbox}
IMAGES=/var/lib/libvirt/images
BASE_URL=https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2
BASE=$IMAGES/sbx-debian13-base.qcow2
NET=default

#        name      ram   cpu  disk  ip               mac                 sudo
GUESTS=("sbx-core  4096  4    30G   192.168.122.10   52:54:00:5b:00:10   nopasswd"
        "sbx-t1    1024  1    10G   192.168.122.11   52:54:00:5b:00:11   nopasswd"
        "sbx-t2    1024  1    10G   192.168.122.12   52:54:00:5b:00:12   password")

install -d -m 0700 -o "$OWNER" "$STATE" "$STATE/secrets"

# Sandbox SSH identity: the only key that opens the guests.
if [[ ! -f $STATE/secrets/sbx_ed25519 ]]; then
  sudo -u "$OWNER" ssh-keygen -q -t ed25519 -N '' -C prompto-sandbox -f "$STATE/secrets/sbx_ed25519"
fi
PUBKEY=$(cat "$STATE/secrets/sbx_ed25519.pub")

# Sandbox sudo password for password-sudo guests. Never printed.
if [[ ! -f $STATE/secrets/sudo-password ]]; then
  (umask 077; head -c 24 /dev/urandom | base64 | tr -d '/+=' > "$STATE/secrets/sudo-password")
  chown "$OWNER" "$STATE/secrets/sudo-password"
fi
PWHASH=$(openssl passwd -6 -stdin < "$STATE/secrets/sudo-password")

[[ -f $BASE ]] || curl -fsSL -o "$BASE" "$BASE_URL"

for g in "${GUESTS[@]}"; do
  read -r name ram cpu disk ip mac sudo <<<"$g"
  if virsh -q dominfo "$name" >/dev/null 2>&1; then echo "$name exists, skipping"; continue; fi

  virsh net-update "$NET" add ip-dhcp-host \
    "<host mac='$mac' name='$name' ip='$ip'/>" --live --config >/dev/null 2>&1 || true

  disk_path=$IMAGES/$name.qcow2
  qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$disk_path" "$disk"

  if [[ $sudo == nopasswd ]]; then sudo_line='ALL=(ALL) NOPASSWD:ALL'; else sudo_line='ALL=(ALL) ALL'; fi
  ud=$(mktemp); md=$(mktemp)
  cat > "$ud" <<EOF
#cloud-config
hostname: $name
users:
  - name: ops
    shell: /bin/bash
    groups: [sudo]
    sudo: "$sudo_line"
    lock_passwd: false
    passwd: "$PWHASH"
    ssh_authorized_keys: ["$PUBKEY"]
ssh_pwauth: false
package_update: true
packages: [curl, jq, rsync, ca-certificates]
EOF
  printf 'instance-id: %s\nlocal-hostname: %s\n' "$name" "$name" > "$md"

  virt-install -q --name "$name" --memory "$ram" --vcpus "$cpu" --import \
    --disk "path=$disk_path,format=qcow2,bus=virtio" --osinfo detect=on,require=off \
    --network "network=$NET,mac=$mac,model=virtio" --cloud-init "user-data=$ud,meta-data=$md" \
    --graphics none --noautoconsole
  rm -f "$ud" "$md"
  echo "$name created ($ip, sudo=$sudo)"
done

cat > "$STATE/ssh_config" <<EOF
Host sbx-*
  User ops
  IdentityFile $STATE/secrets/sbx_ed25519
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
  UserKnownHostsFile $STATE/known_hosts
Host sbx-core
  HostName 192.168.122.10
Host sbx-t1
  HostName 192.168.122.11
Host sbx-t2
  HostName 192.168.122.12
EOF
chown "$OWNER" "$STATE/ssh_config"
echo "ssh -F $STATE/ssh_config sbx-core"
