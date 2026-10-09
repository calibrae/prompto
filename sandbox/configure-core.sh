#!/bin/bash
# Record of how sbx-core was configured. Run from koichi (needs ~/sandbox/ssh_config, secrets/sudo-password).
# Steps: CA/TLS, OpenBao, Kanidm, dev prompto. t2 (password sudo) CA install is in step 1b.
set -euo pipefail
S="ssh -F $HOME/sandbox/ssh_config"
step_1() {
$S sbx-core 'sudo bash -s' <<'REMOTE'
set -euo pipefail
install -d -m755 /etc/sbx-ca
cd /etc/sbx-ca
if [ ! -f ca.key ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out ca.key
  chmod 600 ca.key
  openssl req -x509 -new -key ca.key -sha256 -days 3650 -subj "/CN=Sandbox CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt
fi
if [ ! -f server.crt ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out server.key
  chmod 600 server.key
  openssl req -new -key server.key -subj "/CN=sbx-core" -out server.csr
  printf 'subjectAltName=DNS:sbx-core,DNS:idm.sbx.lan,DNS:bao.sbx.lan,IP:192.168.122.10\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > ext.cnf
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 730 -sha256 -extfile ext.cnf -out server.crt
fi
chmod 644 ca.crt server.crt
REMOTE
$S sbx-core 'cat /etc/sbx-ca/ca.crt' > $HOME/sandbox/ca.crt
for g in sbx-core sbx-t1 sbx-t2 sbx-dev; do
  $S $g 'sudo tee /usr/local/share/ca-certificates/sbx-ca.crt >/dev/null && sudo update-ca-certificates >/dev/null && (grep -q "bao.sbx.lan" /etc/hosts || echo "192.168.122.10 sbx-core idm.sbx.lan bao.sbx.lan" | sudo tee -a /etc/hosts >/dev/null)' < $HOME/sandbox/ca.crt
  echo "$g ok"
done
# 1b: sbx-t2 needs password sudo, one sudo invocation, password piped on stdin
(cat $HOME/sandbox/secrets/sudo-password; cat $HOME/sandbox/ca.crt) | $S sbx-t2 'sudo -S -p "" bash -c "cat > /usr/local/share/ca-certificates/sbx-ca.crt; update-ca-certificates >/dev/null 2>&1; grep -q bao.sbx.lan /etc/hosts || echo \"192.168.122.10 sbx-core idm.sbx.lan bao.sbx.lan\" >> /etc/hosts"'
}
step_2() {
$S sbx-core 'sudo bash -s' <<'REMOTE'
set -euo pipefail
install -d -o openbao -g openbao -m750 /opt/openbao/tls /opt/openbao/data
install -m640 -o openbao -g openbao /etc/sbx-ca/server.crt /opt/openbao/tls/tls.crt
install -m640 -o openbao -g openbao /etc/sbx-ca/server.key /opt/openbao/tls/tls.key
cat > /etc/openbao/openbao.hcl <<'HCL'
ui = true
api_addr = "https://bao.sbx.lan:8200"
cluster_addr = "https://bao.sbx.lan:8201"
storage "pebbledb" {
  path = "/opt/openbao/data"
}
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/opt/openbao/tls/tls.crt"
  tls_key_file  = "/opt/openbao/tls/tls.key"
}
HCL
chown root:openbao /etc/openbao/openbao.hcl; chmod 640 /etc/openbao/openbao.hcl
systemctl enable --now openbao
sleep 3
export BAO_ADDR=https://bao.sbx.lan:8200
if [ ! -s /root/bao-init.json ]; then
  ( umask 077; bao operator init -key-shares=1 -key-threshold=1 -format=json > /root/bao-init.json )
fi
chmod 600 /root/bao-init.json
cat > /usr/local/sbin/bao-unseal.sh <<'SH'
#!/bin/bash
set -eu
export BAO_ADDR=https://bao.sbx.lan:8200
for i in $(seq 30); do bao status >/dev/null 2>&1 && break; [ $? -eq 2 ] && break; sleep 1; done
jq -c '{key:.unseal_keys_b64[0]}' /root/bao-init.json | curl -sf -X PUT -d @- $BAO_ADDR/v1/sys/unseal >/dev/null
SH
chmod 700 /usr/local/sbin/bao-unseal.sh
cat > /etc/systemd/system/bao-unseal.service <<'UNIT'
[Unit]
Description=Sandbox-only OpenBao auto-unseal
After=openbao.service
Requires=openbao.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/bao-unseal.sh
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable bao-unseal.service
systemctl restart bao-unseal.service
bao status -format=json | jq '{initialized,sealed,version}'
REMOTE
}
step_3() {
$S sbx-core 'sudo install -m600 /dev/stdin /root/sbx-sudo-pw' < $HOME/sandbox/secrets/sudo-password
$S sbx-core 'sudo bash -s' <<'REMOTE'
set -euo pipefail
id prompto >/dev/null 2>&1 || useradd --system --home-dir /var/lib/prompto --create-home --shell /usr/sbin/nologin prompto
install -d -m750 -o root -g prompto /etc/prompto
export BAO_ADDR=https://bao.sbx.lan:8200
export BAO_TOKEN=$(jq -r .root_token /root/bao-init.json)
bao secrets list -format=json | jq -e '."secret/"' >/dev/null || bao secrets enable -path=secret -version=2 kv >/dev/null
# prompto refuses a multi-line password: store it without the file's trailing newline
( umask 077; tr -d '\n' < /root/sbx-sudo-pw > /root/sbx-sudo-pw.trim )
bao kv put secret/prompto/sudo-default password=@/root/sbx-sudo-pw.trim >/dev/null
rm -f /root/sbx-sudo-pw.trim
bao policy write prompto-read - >/dev/null <<'HCL'
path "secret/data/prompto/*" { capabilities = ["read"] }
HCL
if ! grep -q '^PROMPTO_VAULT_TOKEN=' /etc/prompto/env 2>/dev/null; then
  J=$(bao token create -orphan -period=768h -policy=prompto-read -format=json)
  TOK=$(echo "$J" | jq -r .auth.client_token)
  ( umask 027
    cat > /etc/prompto/env <<ENV
PROMPTO_INVENTORY=/etc/prompto.toml
PROMPTO_BIND=0.0.0.0:6337
PROMPTO_ALLOWED_HOSTS=*
PROMPTO_USAGE_LOG=/var/lib/prompto/usage.jsonl
RUST_LOG=prompto=info
PROMPTO_VAULT_ADDR=https://bao.sbx.lan:8200
PROMPTO_VAULT_MOUNT=secret
PROMPTO_VAULT_CACERT=/etc/sbx-ca/ca.crt
PROMPTO_VAULT_TOKEN=$TOK
ENV
  )
  chown root:prompto /etc/prompto/env; chmod 640 /etc/prompto/env
  echo "accessor: $(echo "$J" | jq -r .auth.accessor)"
fi
bao kv get -field=password secret/prompto/sudo-default | wc -c
REMOTE
}
step_4() {
$S sbx-core 'sudo bash -s' <<'REMOTE'
set -euo pipefail
ls -ld /etc/kanidmd
install -d -m750 -o root -g kanidmd /etc/kanidmd/tls
install -m640 -g kanidmd /etc/sbx-ca/server.crt /etc/kanidmd/tls/chain.pem
install -m640 -g kanidmd /etc/sbx-ca/server.key /etc/kanidmd/tls/key.pem
cat > /etc/kanidmd/server.toml <<'TOML'
version = "2"
bindaddress = "0.0.0.0:8443"
domain = "idm.sbx.lan"
origin = "https://idm.sbx.lan:8443"
tls_chain = "/etc/kanidmd/tls/chain.pem"
tls_key = "/etc/kanidmd/tls/key.pem"
db_path = "/var/lib/kanidmd/kanidm.db"
[online_backup]
path = "/var/lib/kanidmd/backups/"
schedule = "00 22 * * *"
TOML
chgrp kanidmd /etc/kanidmd/server.toml; chmod 640 /etc/kanidmd/server.toml
install -d -m755 /etc/kanidm
cat > /etc/kanidm/config <<'CFG'
uri = "https://idm.sbx.lan:8443"
ca_path = "/etc/sbx-ca/ca.crt"
CFG
systemctl enable --now kanidmd
sleep 4
systemctl is-active kanidmd
REMOTE
}
step_5() {
$S sbx-core 'sudo bash -s' <<'REMOTE'
set -u
for a in admin idm_admin; do
  ( umask 077; kanidmd recover-account $a -c /etc/kanidmd/server.toml > /root/kanidm-$a.txt 2>&1 ); echo "$a exit=$? bytes=$(wc -c < /root/kanidm-$a.txt)"
done
chmod 600 /root/kanidm-*.txt
# only show whether a password-looking line exists, not it
grep -c -i "new_password" /root/kanidm-admin.txt /root/kanidm-idm_admin.txt
ls -la /var/lib/private/kanidmd | head
REMOTE
}
step_6() {
$S sbx-core 'sudo bash -s' <<'REMOTE'
set -euo pipefail
install -m755 /home/ops/prompto/target/x86_64-unknown-linux-musl/release/prompto /usr/local/bin/prompto-dev
install -d -m750 -o root -g prompto /etc/prompto
install -d -m700 -o prompto -g prompto /etc/prompto/keys
[ -f /etc/prompto/keys/prompto_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -C prompto-dev -f /etc/prompto/keys/prompto_ed25519
chown prompto:prompto /etc/prompto/keys/prompto_ed25519*; chmod 600 /etc/prompto/keys/prompto_ed25519
install -d -m700 -o prompto -g prompto /var/lib/prompto/.ssh
ssh-keyscan -T 5 192.168.122.11 192.168.122.12 2>/dev/null > /var/lib/prompto/.ssh/known_hosts
chown prompto:prompto /var/lib/prompto/.ssh/known_hosts; chmod 600 /var/lib/prompto/.ssh/known_hosts
cat > /etc/prompto.toml <<'TOML'
[host.sbx-t1]
ip = "192.168.122.11"
ssh_user = "ops"
ssh_key  = "/etc/prompto/keys/prompto_ed25519"
ssh_port = 22
capabilities = ["exec", "sudo_exec"]

[host.sbx-t2]
ip = "192.168.122.12"
ssh_user = "ops"
ssh_key  = "/etc/prompto/keys/prompto_ed25519"
ssh_port = 22
capabilities = ["exec", "sudo_exec"]
sudo_password_vault_path = "prompto/sudo-default"
TOML
chgrp prompto /etc/prompto.toml; chmod 640 /etc/prompto.toml
cat > /etc/systemd/system/prompto-dev.service <<'UNIT'
[Unit]
Description=prompto (sandbox dev)
After=network-online.target
Wants=network-online.target
[Service]
User=prompto
Group=prompto
EnvironmentFile=/etc/prompto/env
Environment=HOME=/var/lib/prompto
ExecStart=/usr/local/bin/prompto-dev
Restart=on-failure
WorkingDirectory=/var/lib/prompto
StateDirectory=prompto
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
REMOTE
# authorize pubkey on t1 (NOPASSWD) and t2 (password sudo not needed for user file)
PUB=$($S sbx-core 'sudo cat /etc/prompto/keys/prompto_ed25519.pub')
for g in sbx-t1 sbx-t2; do
  echo "$PUB" | $S $g 'k=$(cat); grep -qxF "$k" ~/.ssh/authorized_keys || echo "$k" >> ~/.ssh/authorized_keys'
done
$S sbx-core 'sudo systemctl enable --now prompto-dev; sleep 2; systemctl is-active prompto-dev'
}
step_1; step_2; step_3; step_4; step_5; step_6
# Smoke test: sandbox/smoke (curl JSON-RPC from sbx-dev) - see /tmp/smoke.sh on sbx-dev.
