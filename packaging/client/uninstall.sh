#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "uninstall.sh must run as root" >&2
  exit 1
fi

systemctl stop rt-clientd.service 2>/dev/null || true
systemctl disable rt-clientd.service 2>/dev/null || true

if [[ -f /run/rtun/resolved-marker.json ]]; then
  echo "a systemd-resolved takeover marker still exists; run rt-clientd once and stop it, or restore the drop-in manually" >&2
fi

systemctl disable --now rtun-geoip.timer 2>/dev/null || true
rm -f /etc/systemd/system/rt-clientd.service
rm -f /etc/systemd/system/rtun-geoip.service
rm -f /etc/systemd/system/rtun-geoip.timer
rm -f /usr/share/dbus-1/system.d/org.rtun.Client1.conf
rm -f /usr/share/polkit-1/actions/org.rtun.client.policy
rm -f /usr/share/applications/rt-client-gui.desktop
rm -f /etc/xdg/autostart/rtun-gui.desktop
rm -f /usr/bin/rt-clientd /usr/bin/rt-client-gui /usr/bin/rt-ctl
rm -rf /etc/rtun /var/lib/rtun /run/rtun

systemctl daemon-reload
systemctl reload dbus 2>/dev/null || true
systemctl restart systemd-resolved 2>/dev/null || true

echo "RTUN client removed."
