# Server setup

## Requirements

- Ubuntu 22.04, 24.04 or newer, x86_64, kernel 6.2+.
- Root access, public IPv4 and, preferably, public IPv6.
- A DNS name such as `vpn.example.com` with both `A` and `AAAA` records
  pointing at the VPS. The `ws-tls` transport and the decoy site need it; the
  `obfs-udp` transport works without a domain.
- Ports `443/tcp`, `443/udp`, `80/tcp` (ACME) and SSH open.
- The VPS IP/AS must not already be blocked; test before relying on it.

## Install

```bash
git clone <repository> rtun
cd rtun
cargo build --release
sudo packaging/server/install.sh --domain vpn.example.com --email admin@example.com
```

The installer is idempotent. It:

1. installs nginx, unbound, certbot and nftables;
2. creates the `rtun` system user and `/etc/rtun`;
3. generates `/etc/rtun/server.toml` with a fresh WireGuard key and random
   obfs headers when the file is absent;
4. installs sysctls for IPv4/IPv6 forwarding and reverse-path filtering;
5. installs the base firewall and loads it;
6. installs `unbound` restricted to `10.66.0.1` and `fd66:1::1` with DNSSEC,
   qname minimisation and query logging disabled;
7. installs the decoy site, an ACME HTTP vhost, requests a certificate and
   switches to the TLS vhost with `/ws` proxied to `127.0.0.1:9443`;
8. enables and starts `rtund`.

If you already have an nginx configuration, review
`/etc/nginx/sites-available/rtun` after installation. The installer only
disables the default site and does not touch other vhosts.

## Add devices

```bash
sudo rt-ctl add-peer --peers-dir /etc/rtun/peers --name laptop \
  --index 2 --server-config /etc/rtun/server.toml
```

The command writes `/etc/rtun/peers/laptop.toml` (public key only), prints the
client private key once and, with `--psk`, a preshared key. The `--index`
selects the client address: IPv4 `10.66.0.<index>`, IPv6 `fd66:1::<index>`.
Keep indices unique.

Reload peers without dropping existing sessions:

```bash
sudo systemctl reload rtund
```

`SIGHUP` re-reads `/etc/rtun/peers`, keeps tunnels for known public keys and
adds new peers.

## Generate the client config

```bash
sudo rt-ctl gen-client --out laptop.toml --endpoint vpn.example.com \
  --server-public-key "$(sudo rt-ctl server-public-key --config /etc/rtun/server.toml)" \
  --server-config /etc/rtun/server.toml --index 2
```

Use the private key printed by `add-peer` via `--private-key` and the PSK via
`--psk` if one was generated. The resulting file contains the same obfs
parameters as the server and is written with mode `0600`. Copy it to the
client, for example with `scp`.

## Verify

```bash
systemctl status rtund
ss -lunp | grep ':443'
ss -ltnp | grep ':9443'
nft list table inet rtun_srv
curl -sS https://vpn.example.com/ | head
curl -sS -o /dev/null -w '%{http_code}\n' https://vpn.example.com/
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H 'Sec-WebSocket-Protocol: rtun.v1' \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  https://vpn.example.com/ws
```

The decoy site must return `200`. A WebSocket request without the subprotocol
must be rejected; a valid `rtun.v1` upgrade returns `101`.

UDP obfs can be checked from the client once connected; there is no
unauthenticated server reply by design, so active probes see silence.

## Certificates

`certbot` installs a renewal timer. nginx reads the certificate on reload, so
add a deploy hook:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh >/dev/null <<'EOF'
#!/bin/sh
systemctl reload nginx
EOF
sudo chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
```

## Firewall and forwarding

`rtund` manages its own table `inet rtun_srv` with:

- NAT44 for `10.66.0.0/24` and NAT66 for `fd66:1::/64`;
- MSS clamping to the tunnel MTU;
- an input rate limit for new UDP/443 flows.

`packaging/server/nftables-rtun.nft` is a minimal base firewall. If you use
UFW, Docker or another firewall, merge those rules instead of loading the file
blindly. Keep SSH open before reloading a drop-policy firewall.

## Hardening

`rtund.service` runs as the unprivileged `rtun` user with only
`CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW`, plus
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `NoNewPrivileges` and a
restricted address-family set. Peers and the server config are readable only
by that user.

Do not enable DNS query logging in unbound, and do not add destination
logging to nginx. `access_log off` is set in the shipped vhost.

## Updating

```bash
git pull
cargo build --release
sudo install -m 0755 target/release/rtund /usr/bin/rtund
sudo install -m 0755 target/release/rt-ctl /usr/bin/rt-ctl
sudo systemctl restart rtund
```

GeoIP data on the client is refreshed by `rt-ctl geoip-update`; schedule it
weekly with a systemd timer or cron.

## Uninstall

```bash
sudo systemctl disable --now rtund
sudo rm -f /etc/systemd/system/rtund.service
sudo rm -rf /etc/rtun /var/lib/rtun
sudo rm -f /etc/nginx/sites-enabled/rtun /etc/nginx/sites-available/rtun
sudo rm -f /etc/unbound/unbound.conf.d/rtun.conf
sudo rm -f /etc/nftables.d/rtun.nft
sudo systemctl daemon-reload
sudo nft delete table inet rtun_srv 2>/dev/null || true
```

Review `/etc/nftables.conf` if the installer appended the include line.
