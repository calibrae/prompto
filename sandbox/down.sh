#!/usr/bin/env bash
# Destroy the prompto sandbox guests and their disks. Keeps the base image
# and $SBX_STATE (sandbox key and password) unless --purge is given.
set -euo pipefail
for name in sbx-core sbx-t1 sbx-t2; do
  virsh -q destroy "$name" 2>/dev/null || true
  virsh -q undefine "$name" --remove-all-storage 2>/dev/null && echo "removed $name" || true
done
if [[ ${1:-} == --purge ]]; then
  OWNER_HOME=$(getent passwd "${SBX_OWNER:?}" | cut -d: -f6)
  rm -rf "${SBX_STATE:-$OWNER_HOME/sandbox}" /var/lib/libvirt/images/sbx-debian13-base.qcow2
  echo "purged sandbox state and base image"
fi
