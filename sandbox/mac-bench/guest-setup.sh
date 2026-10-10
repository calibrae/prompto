#!/bin/bash
# Runs INSIDE the VM as admin (via tart exec). Reads /tmp/ops.pw /tmp/admin.pw /tmp/ops.pub.
set -eu
OPW=$(cat /tmp/ops.pw); OPUB=$(cat /tmp/ops.pub)
id ops >/dev/null 2>&1 || sudo sysadminctl -addUser ops -fullName ops -shell /bin/zsh -password "$OPW" -admin
sudo dscl . -create /Users/ops UserShell /bin/zsh
sudo install -d -m 700 -o ops /Users/ops/.ssh
printf '%s\n' "$OPUB" | sudo tee /Users/ops/.ssh/authorized_keys >/dev/null
sudo chown ops /Users/ops/.ssh/authorized_keys; sudo chmod 600 /Users/ops/.ssh/authorized_keys
sudo systemsetup -setremotelogin on >/dev/null 2>&1 || true
sudo mkdir -p /etc/ssh/sshd_config.d
printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\n' | sudo tee /etc/ssh/sshd_config.d/050-bench.conf >/dev/null
# One root invocation: reset admin password, then drop NOPASSWD rules (so sudo cannot fail midway).
cat > /tmp/final.sh <<'FIN'
set -u
APW=$(cat /tmp/admin.pw)
sysadminctl -resetPasswordFor admin -newPassword "$APW" -adminUser admin -adminPassword admin 2>&1 | tail -1
for f in $(grep -l NOPASSWD /etc/sudoers.d/* 2>/dev/null); do mv "$f" "/var/root/$(basename "$f").disabled-bench"; done
grep -n NOPASSWD /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v ':[0-9]*:#' || echo "no active NOPASSWD"
rm -f /tmp/ops.pw /tmp/admin.pw /tmp/final.sh
FIN
sudo bash /tmp/final.sh
