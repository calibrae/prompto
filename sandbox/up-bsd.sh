#!/usr/bin/env bash
# prompto sandbox — sbx-bsd: FreeBSD 14 target guest (S12.1).
#
#   sbx-bsd   managed target: FreeBSD, login shell /bin/csh (mimics OPNsense),
#             PASSWORD sudo (same sandbox sudo password as sbx-t2).
#
# Separate from up.sh because the Debian base-image logic (genericcloud qcow2,
# cloud-init with apt) does not apply: FreeBSD ships its own BASIC-CLOUDINIT
# image and uses nuageinit instead of cloud-init.
#
# Prereqs: up.sh and configure-core.sh already ran (sandbox key, sudo
# password, ca.crt, sbx-core's prompto key all exist).
# Run as root on the libvirt host:  sudo SBX_OWNER=$USER ./sandbox/up-bsd.sh
# Re-running is safe: an existing guest is left alone (post-config is idempotent).
set -euo pipefail

OWNER=${SBX_OWNER:?set SBX_OWNER to the unprivileged user that owns the sandbox}
OWNER_HOME=$(getent passwd "$OWNER" | cut -d: -f6)
STATE=${SBX_STATE:-$OWNER_HOME/sandbox}
IMAGES=/var/lib/libvirt/images
REL=${SBX_BSD_REL:-14.5-RELEASE}
BASE_URL=https://download.freebsd.org/releases/VM-IMAGES/$REL/amd64/Latest
IMG=FreeBSD-$REL-amd64-BASIC-CLOUDINIT-ufs.qcow2
BASE=$IMAGES/sbx-freebsd-${REL%%-*}-base.qcow2
NET=default

#      name     ram   cpu  disk  ip              mac
name=sbx-bsd; ram=1024; cpu=1; disk=10G; ip=192.168.122.13; mac=52:54:00:5b:00:13

PUBKEY=$(cat "$STATE/secrets/sbx_ed25519.pub")
PWHASH=$(openssl passwd -6 -stdin < "$STATE/secrets/sudo-password")

if [[ ! -f $BASE ]]; then
  w=$(mktemp -d)
  curl -fsSL -o "$w/$IMG.xz" "$BASE_URL/$IMG.xz"
  curl -fsSL -o "$w/CHECKSUM.SHA256" "$BASE_URL/CHECKSUM.SHA256"
  (cd "$w" && grep -F "($IMG.xz)" CHECKSUM.SHA256 | sha256sum -c -)
  xz -d "$w/$IMG.xz"
  install -m 0644 "$w/$IMG" "$BASE"
  rm -rf "$w"
fi

if virsh -q dominfo "$name" >/dev/null 2>&1; then
  echo "$name exists, skipping create"
else
  virsh net-update "$NET" add ip-dhcp-host \
    "<host mac='$mac' name='$name' ip='$ip'/>" --live --config >/dev/null 2>&1 || true

  disk_path=$IMAGES/$name.qcow2
  qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$disk_path" "$disk"

  # nuageinit: user + key + csh + hash, sudo package, password sudoers via runcmd
  # (the sudoers.d dir only exists once the package is installed).
  ud=$(mktemp); md=$(mktemp)
  cat > "$ud" <<EOF
#cloud-config
hostname: $name
users:
  - name: ops
    shell: /bin/csh
    groups: [wheel]
    passwd: "$PWHASH"
    ssh_authorized_keys: ["$PUBKEY"]
ssh_pwauth: false
packages: [sudo, curl, jq, rsync, ca_root_nss]
runcmd:
  - mkdir -p /usr/local/etc/sudoers.d
  - echo 'ops ALL=(ALL) ALL' > /usr/local/etc/sudoers.d/ops
  - chmod 440 /usr/local/etc/sudoers.d/ops
EOF
  printf 'instance-id: %s\nlocal-hostname: %s\n' "$name" "$name" > "$md"

  virt-install -q --name "$name" --memory "$ram" --vcpus "$cpu" --import \
    --disk "path=$disk_path,format=qcow2,bus=virtio" --osinfo detect=on,require=off \
    --network "network=$NET,mac=$mac,model=virtio" --cloud-init "user-data=$ud,meta-data=$md" \
    --graphics none --noautoconsole
  rm -f "$ud" "$md"
  # virt-install --cloud-init leaves the first boot with on_poweroff=destroy,
  # and FreeBSD's first boot ends powered off: start it again once it stops.
  for _ in $(seq 60); do
    [ "$(virsh -q domstate "$name")" = "shut off" ] && { virsh -q start "$name"; break; }
    sleep 5
  done
  virsh -q autostart "$name"
  echo "$name created ($ip, sudo=password, shell=/bin/csh)"
fi

# ssh_config entry (up.sh's Host sbx-* block already supplies User/IdentityFile).
grep -q '^Host sbx-bsd$' "$STATE/ssh_config" || printf 'Host sbx-bsd\n  HostName %s\n' "$ip" >> "$STATE/ssh_config"
chown "$OWNER" "$STATE/ssh_config"

# Post-config over ssh as the owner: sandbox CA + /etc/hosts + prompto key.
# Mirrors configure-core.sh step_1 (CA/hosts) and step_6 (prompto pubkey).
S="sudo -u $OWNER ssh -F $STATE/ssh_config -o ConnectTimeout=5"
for _ in $(seq 60); do $S sbx-bsd true 2>/dev/null && break; sleep 5; done
# wait for first-boot packages (sudo) to finish
for _ in $(seq 60); do $S sbx-bsd 'test -x /usr/local/bin/sudo' 2>/dev/null && break; sleep 5; done

# ops logs in with csh, so remote commands stay csh-safe: real work goes via
# `sh -s` on stdin. One sudo invocation: password line first, then the script.
{ cat "$STATE/secrets/sudo-password"
  echo 'mkdir -p /usr/local/share/certs'
  echo "cat > /usr/local/share/certs/sbx-ca.crt <<'CA'"
  cat "$STATE/ca.crt"
  echo 'CA'
  echo 'certctl rehash >/dev/null 2>&1'
  echo 'grep -q bao.sbx.lan /etc/hosts || echo "192.168.122.10 sbx-core idm.sbx.lan bao.sbx.lan" >> /etc/hosts'
} | $S sbx-bsd 'sudo -S -p "" sh -s'

PUB=$($S sbx-core 'sudo cat /etc/prompto/keys/prompto_ed25519.pub')
{ echo 'k=$(cat <<'"'"'K'"'"''; echo "$PUB"; echo 'K'; echo ')'
  echo 'grep -qxF "$k" ~/.ssh/authorized_keys || echo "$k" >> ~/.ssh/authorized_keys'
} | $S sbx-bsd 'sh -s'
echo "sbx-bsd ready: ssh -F $STATE/ssh_config sbx-bsd"
