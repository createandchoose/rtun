#!/usr/bin/env bash
# Fresh Ubuntu + real systemd smoke test. Run on a Linux Docker host.
# ACME is covered on the real VPS; this isolated test supplies a self-signed cert.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UBUNTU_VERSION="${UBUNTU_VERSION:-24.04}"
CONTAINER=""
cleanup() {
  if [[ -n "${CONTAINER}" ]]; then docker rm -f "${CONTAINER}" >/dev/null; fi
}
trap cleanup EXIT
CONTAINER="$(docker run -d --privileged --cgroupns=host \
  --tmpfs /run --tmpfs /run/lock \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --mount "type=bind,src=${ROOT_DIR},dst=/opt/rtun,readonly" \
  "ubuntu:${UBUNTU_VERSION}" bash -c '
    apt-get update >/tmp/bootstrap.log 2>&1 &&
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      systemd systemd-sysv openssl >>/tmp/bootstrap.log 2>&1 && exec /sbin/init
  ')"
ready=0
for attempt in {1..180}; do
  if [[ "$(docker exec "${CONTAINER}" cat /proc/1/comm)" == systemd ]]; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "${ready}" -ne 1 ]]; then
  docker logs "${CONTAINER}"
  echo 'systemd bootstrap timed out' >&2
  exit 1
fi
docker exec "${CONTAINER}" bash -c '
  set -euo pipefail
  mkdir -p /etc/letsencrypt/live/install-test.example.com
  openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=install-test.example.com \
    -days 1 -keyout /etc/letsencrypt/live/install-test.example.com/privkey.pem \
    -out /etc/letsencrypt/live/install-test.example.com/fullchain.pem >/tmp/cert.log 2>&1
  install_server() {
    if ! bash /opt/rtun/packaging/server/install.sh \
      --domain install-test.example.com --peer smoke > /tmp/install.log 2>&1; then
      # add-peer may print a private key; do not dump the installation log.
      journalctl -u rtund -u nginx -u unbound -n 30 --no-pager
      echo "installer failed; inspect /tmp/install.log in the test container" >&2
      exit 1
    fi
  }
  install_server
  systemctl is-active --quiet rtund nginx unbound
  unbound-checkconf
  test -s /var/lib/unbound/root.key
  test "$(stat -c "%U %a" /etc/rtun/peers/smoke.toml)" = "rtun 600"
  keys_before="$(sha256sum /etc/rtun/server.toml /etc/rtun/peers/smoke.toml)"
  rules_before="$(nft -s list table inet rtun_base)"
  install_server
  test "${keys_before}" = "$(sha256sum /etc/rtun/server.toml /etc/rtun/peers/smoke.toml)"
  test "${rules_before}" = "$(nft -s list table inet rtun_base)"
  systemctl restart rtund nginx unbound
  systemctl is-active --quiet rtund nginx unbound
  curl --fail --silent --insecure --resolve install-test.example.com:443:127.0.0.1 \
    https://install-test.example.com/ >/dev/null
  echo "Fresh installation, rerun, peer ownership, firewall stability and service restart: PASS"
'
