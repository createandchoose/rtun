#!/usr/bin/env bash
set -euo pipefail

CONFIG_SOURCE=""
ENDPOINT=""
SERVER_PUBLIC_KEY=""
PRIVATE_KEY=""
PSK=""
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
  cat <<'EOF'
Usage: install.sh [--config client.toml | --endpoint HOST --server-public-key KEY]
                  [--private-key KEY] [--psk KEY]

Installs the RTUN client, D-Bus service, polkit policy and systemd units.
If --config is given, the file is installed as /etc/rtun/client.toml.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG_SOURCE="${2:-}"; shift 2 ;;
    --endpoint) ENDPOINT="${2:-}"; shift 2 ;;
    --server-public-key) SERVER_PUBLIC_KEY="${2:-}"; shift 2 ;;
    --private-key) PRIVATE_KEY="${2:-}"; shift 2 ;;
    --psk) PSK="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

install -d -m 0750 /etc/rtun /run/rtun /var/lib/rtun

if [[ -x "${ROOT_DIR}/target/release/rt-clientd" ]]; then
  install -m 0755 "${ROOT_DIR}/target/release/rt-clientd" /usr/bin/rt-clientd
  install -m 0755 "${ROOT_DIR}/target/release/rt-client-gui" /usr/bin/rt-client-gui
  install -m 0755 "${ROOT_DIR}/target/release/rt-ctl" /usr/bin/rt-ctl
fi
if [[ ! -x /usr/bin/rt-clientd || ! -x /usr/bin/rt-client-gui ]]; then
  echo "client binaries must be installed in /usr/bin (cargo build --release)" >&2
  exit 1
fi

if [[ -n "${CONFIG_SOURCE}" ]]; then
  install -m 0600 "${CONFIG_SOURCE}" /etc/rtun/client.toml
elif [[ ! -f /etc/rtun/client.toml ]]; then
  if [[ -z "${ENDPOINT}" || -z "${SERVER_PUBLIC_KEY}" ]]; then
    echo "provide --config or both --endpoint and --server-public-key" >&2
    exit 2
  fi
  rm -f /etc/rtun/os.toml
  rt-ctl gen-server --out /etc/rtun/os.toml --endpoint "${ENDPOINT}" --peers-dir /etc/rtun/peers >/dev/null
  rt-ctl gen-client --out /etc/rtun/client.toml --endpoint "${ENDPOINT}" \
    --server-public-key "${SERVER_PUBLIC_KEY}" --server-config /etc/rtun/os.toml \
    ${PRIVATE_KEY:+--private-key "${PRIVATE_KEY}"} ${PSK:+--psk "${PSK}"}
  shred -u /etc/rtun/os.toml 2>/dev/null || rm -f /etc/rtun/os.toml
fi
chmod 0600 /etc/rtun/client.toml
chmod 0700 /etc/rtun

install -m 0644 "${ROOT_DIR}/packaging/client/rt-clientd.service" /etc/systemd/system/rt-clientd.service
install -m 0644 "${ROOT_DIR}/packaging/client/rtun-geoip.service" /etc/systemd/system/rtun-geoip.service
install -m 0644 "${ROOT_DIR}/packaging/client/rtun-geoip.timer" /etc/systemd/system/rtun-geoip.timer
install -m 0644 "${ROOT_DIR}/packaging/client/org.rtun.Client1.conf" /usr/share/dbus-1/system.d/org.rtun.Client1.conf
install -m 0644 "${ROOT_DIR}/packaging/client/org.rtun.client.policy" /usr/share/polkit-1/actions/org.rtun.client.policy
install -m 0644 "${ROOT_DIR}/packaging/client/rt-client-gui.desktop" /usr/share/applications/rt-client-gui.desktop
install -d -m 0755 /etc/xdg/autostart
install -m 0644 "${ROOT_DIR}/packaging/client/rtun-gui-autostart.desktop" /etc/xdg/autostart/rtun-gui.desktop
install -m 0644 "${ROOT_DIR}/packaging/client/client.toml.example" /usr/share/rtun/client.toml.example

systemctl daemon-reload
systemctl reload dbus 2>/dev/null || true
systemctl enable rt-clientd.service
systemctl enable --now rtun-geoip.timer
systemctl restart rt-clientd.service

echo "RTUN client installed. Start the GUI with 'rt-client-gui'."
