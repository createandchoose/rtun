#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

VERSION="$(awk -F'"' '/^version = / {print $2; exit}' Cargo.toml)"
ARCH="$(dpkg --print-architecture)"
STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT

cargo build --release -p rt-clientd -p rt-client-gui -p rt-ctl

install -d "${STAGE}/DEBIAN" "${STAGE}/usr/bin"
install -d "${STAGE}/lib/systemd/system"
install -d "${STAGE}/usr/share/dbus-1/system.d"
install -d "${STAGE}/usr/share/polkit-1/actions"
install -d "${STAGE}/usr/share/applications"
install -d "${STAGE}/etc/xdg/autostart"
install -d "${STAGE}/usr/share/rtun"
install -d "${STAGE}/usr/share/doc/rtun-client"

install -m 0755 target/release/rt-clientd "${STAGE}/usr/bin/"
install -m 0755 target/release/rt-client-gui "${STAGE}/usr/bin/"
install -m 0755 target/release/rt-ctl "${STAGE}/usr/bin/"

install -m 0644 packaging/client/rt-clientd.service "${STAGE}/lib/systemd/system/"
install -m 0644 packaging/client/rtun-geoip.service "${STAGE}/lib/systemd/system/"
install -m 0644 packaging/client/rtun-geoip.timer "${STAGE}/lib/systemd/system/"
install -m 0644 packaging/client/org.rtun.Client1.conf "${STAGE}/usr/share/dbus-1/system.d/"
install -m 0644 packaging/client/org.rtun.client.policy "${STAGE}/usr/share/polkit-1/actions/"
install -m 0644 packaging/client/rt-client-gui.desktop "${STAGE}/usr/share/applications/"
install -m 0644 packaging/client/rtun-gui-autostart.desktop "${STAGE}/etc/xdg/autostart/rtun-gui.desktop"
install -m 0644 packaging/client/client.toml.example "${STAGE}/usr/share/rtun/client.toml.example"
install -m 0644 LICENSE-MIT "${STAGE}/usr/share/doc/rtun-client/copyright"

chmod 0755 "${STAGE}"

cat >"${STAGE}/DEBIAN/control" <<EOF
Package: rtun-client
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: libc6, libgcc-s1, libfontconfig1, libfreetype6, libxkbcommon0, libwayland-client0, libx11-6, libegl1, libgl1, nftables, dbus, systemd, systemd-resolved, policykit-1 | polkitd
Recommends: ca-certificates
Maintainer: RTUN contributors
Description: DPI-resistant VPN client for Linux
 RTUN client with obfs-udp and ws-tls transports, split routing,
 split DNS, kill switch, a Slint desktop UI and a system tray icon.
EOF

cat >"${STAGE}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
install -d -m 0750 /etc/rtun /run/rtun /var/lib/rtun
systemctl daemon-reload || true
systemctl enable rt-clientd.service || true
systemctl enable --now rtun-geoip.timer || true
if [ -f /etc/rtun/client.toml ]; then
  systemctl restart rt-clientd.service || true
fi
exit 0
EOF

cat >"${STAGE}/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
systemctl stop rt-clientd.service || true
systemctl disable --now rtun-geoip.timer || true
exit 0
EOF

cat >"${STAGE}/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload || true
if [ "$1" = "purge" ]; then
  rm -rf /etc/rtun /var/lib/rtun /run/rtun
fi
exit 0
EOF

chmod 0755 "${STAGE}/DEBIAN/postinst" "${STAGE}/DEBIAN/prerm" "${STAGE}/DEBIAN/postrm"

OUTPUT="${ROOT_DIR}/rtun-client_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "${STAGE}" "${OUTPUT}"
echo "built ${OUTPUT}"
