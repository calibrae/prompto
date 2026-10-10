# mac-bench: prompto against a macOS target (on a Mac host)

Throwaway tart VM `bench-mac` (macOS Tahoe, zsh login shell, password sudo, BSD userland)
driven by a locally built prompto. Lives on the Mac host under `~/bench-mac/`; these files are
copies of the scripts there. Uncommitted by design. Not related to the koichi sandbox.

Topology (all on the Mac host):

    smoke.sh --HTTP MCP--> prompto 127.0.0.1:6399 --ssh (ops, bench key)--> tart VM bench-mac
                              \--vault--> dev OpenBao 127.0.0.1:8211 (secret/prompto/sudo-default)

- tart VM storage: `TART_HOME=/Volumes/2TB/tart` (4 vCPU, 6 GB RAM). Clone of
  `ghcr.io/cirruslabs/macos-tahoe-base:latest` (guest admin account provisioned by `guest-setup.sh`).
- Guest: user `ops` (admin group, /bin/zsh, key-only SSH, password sudo), sshd password auth off,
  admin password rotated, NOPASSWD rule moved out of /etc/sudoers.d.
- Secrets (0600, never printed): `~/bench-mac/secrets/{sudo-password,admin-password,bao-root-token,prompto-vault-token}`,
  key `~/bench-mac/bench_ed25519`.
- Nothing auto-starts. `~/bench-mac/run.sh start|stop|status` (`NET_MODE=nat` is what ran; see below).
- `smoke.sh` -> `smoke.py`: PASS/FAIL per item, raw result on failure.

## Network isolation result

`--net-softnet` (and `--net-host`, which also uses softnet) FAILED: "root privileges are required to
run and passwordless sudo was not available". Softnet needs a one-time root step on the Mac host
(`sudo softnet --set-suid`, or a sudoers NOPASSWD entry for /opt/homebrew/bin/softnet; see tart docs).
root on the host via prompto is not granted, so the bench runs on default NAT (`NET_MODE=nat`).
From inside the VM under NAT: <LAN gateway>:443 OPEN, <LAN server>:22 OPEN, 1.1.1.1:443 OPEN, i.e. the
VM CAN reach the LAN. Once softnet is set up, `./run.sh start` with `NET_MODE=softnet` (the default)
blocks 10/8, 172.16/12, 192.168/16; the VM IP still reaches the host.
