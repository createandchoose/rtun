#!/usr/bin/env bash
set -euo pipefail

DOMAIN=""
EMAIL=""
PEER_NAME=""
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
  cat <<'EOF'
Usage: install.sh --domain vpn.example.com --email admin@example.com [--peer alice]

Installs and configures nginx, unbound, nftables, rtund and a Let's Encrypt
certificate on an Ubuntu VPS. Safe to re-run; existing configuration and
certificates are preserved.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --email) EMAIL="${2:-}"; shift 2 ;;
    --peer) PEER_NAME="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "install.sh must run as root" >&2
  exit 1
fi
if [[ -z "${DOMAIN}" ]]; then
  echo "--domain is required" >&2
  exit 2
fi
# Email необязателен: без него certbot регистрируется без адреса.
# Уведомления о сроке действия тогда не придут, продление работает автоматически.

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends nginx unbound dns-root-data certbot nftables iproute2 procps curl ca-certificates

if ! id -u rtun >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin rtun
fi

install -d -m 0750 -o rtun -g rtun /etc/rtun /etc/rtun/peers /var/lib/rtun /run/rtun
install -d -m 0755 /var/www/rtun-decoy /etc/nftables.d

if [[ -x "${ROOT_DIR}/target/release/rtund" ]]; then
  install -m 0755 "${ROOT_DIR}/target/release/rtund" /usr/bin/rtund
fi
if [[ -x "${ROOT_DIR}/target/release/rt-ctl" ]]; then
  install -m 0755 "${ROOT_DIR}/target/release/rt-ctl" /usr/bin/rt-ctl
fi
if [[ ! -x /usr/bin/rtund || ! -x /usr/bin/rt-ctl ]]; then
  echo "rtund and rt-ctl must be installed in /usr/bin (cargo build --release)" >&2
  exit 1
fi

if [[ ! -f /etc/rtun/server.toml ]]; then
  rt-ctl gen-server --out /etc/rtun/server.toml --endpoint "${DOMAIN}" --peers-dir /etc/rtun/peers
fi
chown -R rtun:rtun /etc/rtun
chmod 0700 /etc/rtun/peers
chmod 0600 /etc/rtun/server.toml

cat >/etc/sysctl.d/99-rtun.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
EOF
sysctl --system >/dev/null

install -m 0644 "${ROOT_DIR}/packaging/server/nftables-rtun.nft" /etc/nftables.d/rtun.nft
if ! grep -q 'include "/etc/nftables.d/\*.nft"' /etc/nftables.conf 2>/dev/null; then
  printf '\ninclude "/etc/nftables.d/*.nft"\n' >>/etc/nftables.conf
fi
systemctl enable nftables
# Replace only our table in one transaction, so reruns do not append rules.
FIREWALL_BATCH="$(mktemp)"
trap 'rm -f "${FIREWALL_BATCH}"' EXIT
if nft list table inet rtun_base >/dev/null 2>&1; then
  echo 'delete table inet rtun_base' >"${FIREWALL_BATCH}"
fi
cat /etc/nftables.d/rtun.nft >>"${FIREWALL_BATCH}"
nft --check -f "${FIREWALL_BATCH}"
nft -f "${FIREWALL_BATCH}"

# With --no-install-recommends Ubuntu may not install dns-root-data. Also,
# unbound's service helper has not necessarily run before checkconf is called.
# Seed the writable RFC 5011 anchor from the distro's trusted package first.
install -d -m 0755 -o unbound -g unbound /var/lib/unbound
if [[ ! -s /var/lib/unbound/root.key ]]; then
  install -m 0644 -o unbound -g unbound /usr/share/dns/root.key /var/lib/unbound/root.key
fi
rt-ctl unbound-config >/etc/unbound/unbound.conf.d/rtun.conf
unbound-checkconf
systemctl enable unbound
systemctl restart unbound

install -m 0644 "${ROOT_DIR}/packaging/decoy/index.html" /var/www/rtun-decoy/index.html

cat >/etc/nginx/sites-available/rtun <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    root /var/www/rtun-decoy;
    access_log off;
    location /.well-known/acme-challenge/ { root /var/www/rtun-decoy; }
    location / { try_files \$uri \$uri/ =404; }
}
EOF
ln -sf /etc/nginx/sites-available/rtun /etc/nginx/sites-enabled/rtun
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl restart nginx

if [[ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]]; then
  if [[ -n "${EMAIL}" ]]; then
    certbot certonly --webroot -w /var/www/rtun-decoy -d "${DOMAIN}" \
      --non-interactive --agree-tos --email "${EMAIL}" --keep-until-expiring
  else
    certbot certonly --webroot -w /var/www/rtun-decoy -d "${DOMAIN}" \
      --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring
  fi
fi

sed "s/__DOMAIN__/${DOMAIN}/g" "${ROOT_DIR}/packaging/server/nginx-rtun.conf.template" \
  >/etc/nginx/sites-available/rtun
nginx -t
systemctl reload nginx

install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat >/etc/letsencrypt/renewal-hooks/deploy/rtun-reload-nginx <<'EOF'
#!/bin/sh
set -eu
nginx -t
systemctl reload nginx
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/rtun-reload-nginx

install -m 0644 "${ROOT_DIR}/packaging/server/rtund.service" /etc/systemd/system/rtund.service
systemctl daemon-reload
systemctl enable rtund
systemctl restart rtund
# Type=simple can report active before the daemon has bound its sockets.
for attempt in {1..15}; do
  if (exec 3<>/dev/tcp/127.0.0.1/9443) 2>/dev/null; then
    break
  fi
  if [[ "${attempt}" -eq 15 ]]; then
    journalctl -u rtund -n 30 --no-pager >&2
    echo "rtund did not open its WebSocket backend" >&2
    exit 1
  fi
  sleep 1
done

if [[ -n "${PEER_NAME}" && ! -f "/etc/rtun/peers/${PEER_NAME}.toml" ]]; then
  runuser -u rtun -- rt-ctl add-peer --peers-dir /etc/rtun/peers --name "${PEER_NAME}" --index 2 --server-config /etc/rtun/server.toml
  systemctl reload rtund
fi

systemctl is-active --quiet rtund nginx unbound
rtund --config /etc/rtun/server.toml --check-config

echo
echo "RTUN server is installed."
echo "  decoy:      https://${DOMAIN}/"
echo "  websocket:  wss://${DOMAIN}/ws"
echo "  obfs UDP:   ${DOMAIN}:443/udp"
echo "  peers:      /etc/rtun/peers"
echo
echo "Add a device with:"
echo "  runuser -u rtun -- rt-ctl add-peer --peers-dir /etc/rtun/peers --name NAME --index N --server-config /etc/rtun/server.toml"
echo "  systemctl reload rtund"
echo "Then create the client config with rt-ctl gen-client."
