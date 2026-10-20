#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${BIN_DIR:-${ROOT_DIR}/target/release}"
PROFILE="${PROFILE:-none}"
WORK="$(mktemp -d /tmp/rtun-netns.XXXXXX)"
PIDS=()
CLIENT_NS="rt-client"
NET_NS="rt-net"
SERVER_NS="rt-server"

log() { printf '[netns] %s\n' "$*"; }
fail() { printf '[netns] FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  for pid in "${PIDS[@]}"; do
    kill "${pid}" 2>/dev/null || true
  done
  for ns in "${CLIENT_NS}" "${NET_NS}" "${SERVER_NS}"; do
    ip netns del "${ns}" 2>/dev/null || true
  done
  if [[ "${KEEP_WORK:-0}" == "1" ]]; then
    log "artifacts kept in ${WORK}"
  else
    rm -rf "${WORK}"
  fi
}
trap cleanup EXIT

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi
for tool in ip nft python3 curl ping; do
  command -v "${tool}" >/dev/null || fail "missing tool: ${tool}"
done

if [[ ! -x "${BIN_DIR}/rtund" || ! -x "${BIN_DIR}/rt-clientd" || ! -x "${BIN_DIR}/rt-ctl" ]]; then
  log "building release binaries"
  (cd "${ROOT_DIR}" && cargo build --release -p rt-server -p rt-clientd -p rt-ctl)
fi

json_field() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2" 2>/dev/null || true
}
state() { json_field "${WORK}/client-run/status.json" state; }

setup_namespaces() {
  for ns in "${CLIENT_NS}" "${NET_NS}" "${SERVER_NS}"; do
    ip netns add "${ns}"
    ip -n "${ns}" link set lo up
  done

  ip link add veth-client type veth peer name veth-client-net
  ip link set veth-client netns "${CLIENT_NS}"
  ip link set veth-client-net netns "${NET_NS}"
  ip -n "${CLIENT_NS}" link set veth-client up
  ip -n "${NET_NS}" link set veth-client-net up
  ip -n "${CLIENT_NS}" addr add 10.200.1.2/24 dev veth-client
  ip -n "${CLIENT_NS}" addr add 2001:db8:1::2/64 dev veth-client nodad
  ip -n "${NET_NS}" addr add 10.200.1.1/24 dev veth-client-net
  ip -n "${NET_NS}" addr add 2001:db8:1::1/64 dev veth-client-net nodad

  ip link add veth-server type veth peer name veth-server-net
  ip link set veth-server netns "${SERVER_NS}"
  ip link set veth-server-net netns "${NET_NS}"
  ip -n "${SERVER_NS}" link set veth-server up
  ip -n "${NET_NS}" link set veth-server-net up
  ip -n "${SERVER_NS}" addr add 10.200.2.2/24 dev veth-server
  ip -n "${SERVER_NS}" addr add 2001:db8:2::2/64 dev veth-server nodad
  ip -n "${NET_NS}" addr add 10.200.2.1/24 dev veth-server-net
  ip -n "${NET_NS}" addr add 2001:db8:2::1/64 dev veth-server-net nodad

  ip -n "${CLIENT_NS}" route add default via 10.200.1.1
  ip -n "${CLIENT_NS}" -6 route add default via 2001:db8:1::1
  ip -n "${SERVER_NS}" route add default via 10.200.2.1
  ip -n "${SERVER_NS}" -6 route add default via 2001:db8:2::1

  ip -n "${NET_NS}" addr add 203.0.113.1/32 dev lo
  ip -n "${NET_NS}" addr add 5.5.5.5/32 dev lo
  ip -n "${NET_NS}" addr add 2001:db8:99::1/128 dev lo

  ip netns exec "${NET_NS}" sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec "${NET_NS}" sysctl -q -w net.ipv6.conf.all.forwarding=1
  ip netns exec "${SERVER_NS}" sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec "${SERVER_NS}" sysctl -q -w net.ipv6.conf.all.forwarding=1
}

configure_keys() {
  local client_json server_public
  client_json="$("${BIN_DIR}/rt-ctl" keygen)"
  CLIENT_PRIVATE="$(printf '%s' "${client_json}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["private_key"])')"
  CLIENT_PUBLIC="$(printf '%s' "${client_json}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')"

  mkdir -p "${WORK}/peers" "${WORK}/server-run" "${WORK}/client-run" "${WORK}/www"
  "${BIN_DIR}/rt-ctl" gen-server --out "${WORK}/server.toml" --endpoint 10.200.2.2 --peers-dir "${WORK}/peers" >/dev/null
  server_public="$("${BIN_DIR}/rt-ctl" server-public-key --config "${WORK}/server.toml")"

  cat >"${WORK}/peers/client.toml" <<EOF
name = "client"
public_key = "${CLIENT_PUBLIC}"
address_v4 = "10.66.0.2"
address_v6 = "fd66:1::2"
enabled = true
EOF

  "${BIN_DIR}/rt-ctl" gen-client --out "${WORK}/client.toml" --endpoint 10.200.2.2 \
    --server-public-key "${server_public}" --server-config "${WORK}/server.toml" \
    --index 2 --private-key "${CLIENT_PRIVATE}" >/dev/null

  sed -i 's|^direct_cidrs = \[\]|direct_cidrs = ["5.5.5.5/32"]|' "${WORK}/client.toml"
  sed -i 's|^direct_upstreams = \[\]|direct_upstreams = ["10.200.1.1"]|' "${WORK}/client.toml"
  printf 'rtun-ok\n' >"${WORK}/www/index.html"
}

apply_profile() {
  case "${PROFILE}" in
    none) ;;
    udp-drop)
      ip netns exec "${NET_NS}" nft -f - <<EOF
table inet dpi {
  chain forward {
    type filter hook forward priority -10; policy accept;
    udp dport 443 drop
  }
}
EOF
      ;;
    wg-signature)
      ip netns exec "${NET_NS}" nft -f - <<EOF
table inet dpi {
  chain forward {
    type filter hook forward priority -10; policy accept;
    udp dport 443 meta length 148 drop
  }
}
EOF
      ;;
    tcp-drop)
      ip netns exec "${NET_NS}" nft -f - <<EOF
table inet dpi {
  chain forward {
    type filter hook forward priority -10; policy accept;
    tcp dport 443 drop
  }
}
EOF
      ;;
    throttle)
      ip netns exec "${NET_NS}" tc qdisc add dev veth-server-net root tbf rate 2mbit burst 32k latency 50ms
      ;;
    ipv6-blackhole)
      ip -n "${CLIENT_NS}" -6 route replace blackhole default
      ;;
    *)
      fail "unknown PROFILE=${PROFILE}"
      ;;
  esac
}

start_stack() {
  ip netns exec "${NET_NS}" python3 -m http.server 8000 --bind 203.0.113.1 --directory "${WORK}/www" >"${WORK}/http.log" 2>&1 &
  PIDS+=("$!")

  ip netns exec "${SERVER_NS}" "${BIN_DIR}/rtund" --config "${WORK}/server.toml" --run-dir "${WORK}/server-run" >"${WORK}/server.log" 2>&1 &
  PIDS+=("$!")
  sleep 1

  ip netns exec "${CLIENT_NS}" "${BIN_DIR}/rt-clientd" --config "${WORK}/client.toml" --headless \
    --run-dir "${WORK}/client-run" --status-file "${WORK}/client-run/status.json" --no-dns \
    >"${WORK}/client.log" 2>&1 &
  PIDS+=("$!")

  if [[ "${DEBUG_CAPTURE:-0}" == "1" ]]; then
    ip netns exec "${NET_NS}" timeout 90 tcpdump -ni veth-server-net -Z root -vv udp >"${WORK}/capture-net.txt" 2>&1 &
    ip netns exec "${NET_NS}" timeout 90 tcpdump -ni veth-client-net -Z root -vv icmp >"${WORK}/capture-net-icmp.txt" 2>&1 &
    PIDS+=("$!")
    ip netns exec "${CLIENT_NS}" timeout 90 tcpdump -ni veth-client -Z root -vv icmp >"${WORK}/capture-client-icmp.txt" 2>&1 &
    PIDS+=("$!")
  fi
}

wait_for_state() {
  local wanted="$1" attempts="${2:-60}" current=""
  for _ in $(seq 1 "${attempts}"); do
    current="$(state)"
    [[ "${current}" == "${wanted}" ]] && return 0
    sleep 0.5
  done
  return 1
}

show_logs() {
  for file in client.log server.log; do
    echo "--- ${file} ---" >&2
    tail -80 "${WORK}/${file}" >&2 || true
  done
  echo "--- status ---" >&2
  cat "${WORK}/client-run/status.json" >&2 || true
  if ip netns list | grep -q "${CLIENT_NS}"; then
    echo "--- ip rule ---" >&2
    ip netns exec "${CLIENT_NS}" ip rule show >&2 || true
    echo "--- route 5.5.5.5 ---" >&2
    ip netns exec "${CLIENT_NS}" ip route get 5.5.5.5 >&2 || true
    ip netns exec "${CLIENT_NS}" ip route get 5.5.5.5 mark 0x1 >&2 || true
    echo "--- nft ---" >&2
    ip netns exec "${CLIENT_NS}" nft list ruleset >&2 || true
    echo "--- gateway ping ---" >&2
    ip netns exec "${CLIENT_NS}" ping -c1 -W2 10.200.1.1 >&2 || true
    echo "--- local service ping ---" >&2
    ip netns exec "${NET_NS}" ping -c1 -W2 5.5.5.5 >&2 || true
  fi
}

assert_ok() {
  local description="$1"
  shift
  if ! "$@"; then
    show_logs
    fail "${description}"
  fi
  log "ok: ${description}"
}

run_connected_checks() {
  assert_ok "tunnel IPv4 gateway" ip netns exec "${CLIENT_NS}" ping -c1 -W3 10.66.0.1
  assert_ok "IPv4 through server" ip netns exec "${CLIENT_NS}" ping -c1 -W3 203.0.113.1
  assert_ok "IPv6 through server" ip netns exec "${CLIENT_NS}" ping -6 -c1 -W3 2001:db8:99::1
  assert_ok "HTTP through tunnel" bash -c "ip netns exec '${CLIENT_NS}' curl -fsS --max-time 8 http://203.0.113.1:8000/ | grep -q rtun-ok"
  assert_ok "direct traffic" ip netns exec "${CLIENT_NS}" ping -c1 -W3 5.5.5.5
  assert_ok "MTU 1360 without fragmentation" ip netns exec "${CLIENT_NS}" ping -M do -s 1332 -c1 -W3 203.0.113.1

  local direct tunnel
  direct="$("${BIN_DIR}/rt-ctl" route 5.5.5.5 --config "${WORK}/client.toml" --geoip-dir "${WORK}/geo")"
  tunnel="$("${BIN_DIR}/rt-ctl" route 8.8.8.8 --config "${WORK}/client.toml" --geoip-dir "${WORK}/geo")"
  printf '%s' "${direct}" | grep -q '"action": "direct"' || { show_logs; fail "5.5.5.5 should be direct"; }
  printf '%s' "${tunnel}" | grep -q '"action": "tunnel"' || { show_logs; fail "8.8.8.8 should be tunneled"; }
  log "ok: dry-run routing"

  if [[ "${PROFILE}" == "none" || "${PROFILE}" == "wg-signature" || "${PROFILE}" == "throttle" ]]; then
    local transport
    transport="$(json_field "${WORK}/client-run/status.json" transport)"
    [[ "${transport}" == "obfs-udp" ]] || fail "expected obfs-udp transport, got ${transport}"
    log "ok: obfs-udp transport"
  fi
}

run_degraded_checks() {
  assert_ok "direct traffic still works while degraded" ip netns exec "${CLIENT_NS}" ping -c1 -W3 5.5.5.5
}

log "profile=${PROFILE}"
setup_namespaces
configure_keys
apply_profile
start_stack

if [[ "${PROFILE}" == "udp-drop" ]]; then
  for _ in $(seq 1 40); do
    current="$(state)"
    [[ "${current}" == "degraded" || "${current}" == "disconnected" ]] && break
    sleep 0.5
  done
  log "final state: ${current:-unknown}"
  run_degraded_checks
else
  wait_for_state connected 80 || { show_logs; fail "client did not connect"; }
  run_connected_checks

  server_pid="${PIDS[1]}"
  kill "${server_pid}" 2>/dev/null || true
  sleep 2
  assert_ok "kill switch blocks tunneled traffic" bash -c "! ip netns exec '${CLIENT_NS}' curl -fsS --max-time 3 http://203.0.113.1:8000/ >/dev/null 2>&1"
  assert_ok "direct traffic survives server loss" ip netns exec "${CLIENT_NS}" ping -c1 -W3 5.5.5.5
fi

log "all checks passed"
