# mac-bench: prompto against a macOS target (on a Mac host)

Throwaway tart VM `bench-mac` (macOS Tahoe, zsh login shell, password sudo, BSD userland)
driven by a locally built prompto. Lives on the Mac host under `~/bench-mac/`; these files are
copies of the scripts there. Uncommitted by design. Optionally wired into the koichi sandbox (last section).

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

Softnet needs a one-time root step on the Mac host: make the real softnet binary setuid root
(`sudo chown root:wheel "$(realpath /opt/homebrew/bin/softnet)" && sudo chmod u+s …`; a brew
upgrade of softnet resets it). Without it the VM falls back to plain NAT and CAN reach the LAN —
never wire a NAT-mode VM into the sandbox.

With softnet (`NET_MODE=softnet`, the default), verified from inside the VM: the LAN gateway, a LAN
server, 192.168.1.1:80 and 172.16.0.1:80 are blocked, the sandbox host's LAN address is blocked,
1.1.1.1:443 and https://github.com work. The VM's DNS is set to public resolvers (1.1.1.1, 9.9.9.9)
because a LAN resolver is unreachable by design.

## Wired into the sandbox (one-way tunnel)

The sandbox prompto (in the Linux sandbox) manages this VM as host `sbx-mac`. The VM cannot reach
any LAN, so the path is a reverse SSH tunnel opened FROM the Mac host:

    sbx-core --tcp--> <sandbox-bridge-ip>:2222 (sandbox host) ==ssh -R== Mac host --> VM sshd :22
                      ^ only sbx-core may connect (nft + firewalld)    ^ outbound only

- Sandbox host: system user `sbxtunnel` (nologin, no password). Its authorized_keys line is
  `restrict,port-forwarding,permitlisten="<sandbox-bridge-ip>:2222" <tunnel pubkey>`; sshd drop-in
  `koichi-sshd-60-sbxtunnel.conf` (Match User only, remote forwarding only, ForceCommand nologin).
- Firewall: see `koichi-firewall.txt` (nft accept from sbx-core only + drop for other guests, plus
  the firewalld libvirt-zone rich rule that is actually required).
- Mac host: key `~/bench-mac/tunnel_ed25519` (generated there, never copied), `tunnel.conf` with
  `TUNNEL_HOST=<koichi-lan-ip>`. `run.sh tunnel-start|tunnel-stop|tunnel-status`; `start`/`stop`
  include it. Reconnect loop with keepalives; nothing auto-starts at boot.
- VM: `ops` authorized_keys additionally holds the sandbox key and sandbox prompto's public key.
  VM DNS is set to 1.1.1.1/9.9.9.9 (`networksetup -setdnsservers Ethernet ...`).
- Sandbox side: `Host sbx-mac` (HostName <sandbox-bridge-ip>, Port 2222) in the sandbox ssh_config;
  the VM host key for `[<sandbox-bridge-ip>]:2222` goes into sbx-core's prompto known_hosts.
- The VM's sudo password is the one in `~/bench-mac/secrets/sudo-password` on the Mac host; load it
  into the sandbox OpenBao as `prompto/sudo-mac` (it differs from the Linux guests').

The only new path into the sandbox network is that one outbound-initiated forward; the VM still
cannot open connections to the LAN (softnet), and the tunnel key can do nothing but that forward.

Rollback while editing sshd on the sandbox host: arm
`systemd-run --on-active=5m --unit=sbxtunnel-rollback sh -c 'rm -f /etc/ssh/sshd_config.d/60-sbxtunnel.conf; systemctl reload sshd'`,
`sshd -t`, `systemctl reload sshd` (never restart), confirm a fresh login, then
`systemctl stop sbxtunnel-rollback.timer`.

Teardown: `run.sh tunnel-stop`; on the sandbox host remove the drop-in (reload sshd), `userdel -r sbxtunnel`,
the nft lines (reload table), the firewalld rich rule (runtime + permanent), the `Host sbx-mac` stanza and
the known_hosts entry; on the Mac host delete `tunnel_ed25519*`, `tunnel.conf`, `known_hosts_tunnel`.
