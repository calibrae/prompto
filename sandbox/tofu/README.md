# Sandbox as code (OpenTofu)

Reproduces `sandbox/up.sh` + `sandbox/up-bsd.sh`: qcow2 overlay on a base image, virtio disk + NIC on libvirt
`default`, fixed MAC, DHCP reservation, cloud-init NoCloud ISO, autostart.

- OpenTofu >= 1.7 (tested 1.13.1), provider `dmacvicar/libvirt` pinned `~> 0.8.3` (0.9 rewrote the schema).
- Run **on the libvirt host** as the sandbox owner (needs `virsh`, `sudo -n` to read the root-owned
  `~/sandbox/secrets/sudo-password`).
- Guests must stay on `default` (192.168.122.0/24): the nftables wall only covers that subnet.

## Layout
- `modules/guest` one guest (volume, cloud-init ISO, domain, DHCP reservation).
- `stacks/persistent` sbx-dev + the base images (never destroyed casually).
- `stacks/disposable` sbx-core, sbx-t1, sbx-t2, sbx-bsd. Consumes the base volumes by name.
- `tf.sh <stack> <tofu cmd> [args]` loads secrets into the environment (never echoed).

## Order
1. `./tf.sh persistent init && ./tf.sh persistent apply`  (bases + sbx-dev; `-var manage_base=false` if bases already exist)
2. `./tf.sh disposable init && ./tf.sh disposable apply`
3. Existing scripts, unchanged: `configure-core.sh` (OpenBao init/unseal, Kanidm recover, prompto deploy), then the
   bsd post-config part of `up-bsd.sh` (CA, /etc/hosts, prompto key) and `provision-*.sh`. Tofu only builds the guests.

## Secrets
- `~/sandbox/secrets/tofu-passphrase` is generated on first run (0600) and encrypts state and plan (`enforced = true`).
  Lose it and the state is gone.
- The sudo password never enters tofu: `tf.sh` passes a `$6$` hash (deterministic salt, so plans stay quiet).
  The hash is part of the cloud-init user-data and so lives in the (encrypted) state. No clear password, no private key.
- Cloud-init changes are ignored after creation (scripts leave existing guests alone). Rebuild with
  `-replace='module.guest["t1"].libvirt_domain.this' -replace='module.guest["t1"].libvirt_cloudinit_disk.ci' -replace='module.guest["t1"].libvirt_volume.disk'`.

## Parallel copy
`./tf.sh disposable apply -var prefix=tsbx- -var host_offset=30 -var mac_prefix=52:54:00:5b:01 -var memory_cap_mb=512 -var 'guests_enabled=["t1","bsd"]'`
gives tsbx-t1 .41 and tsbx-bsd .43 (separate state per stack dir; copy the dir to run two copies at once).
