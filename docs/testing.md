# Automated tests

## Unit and static checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
```

The unit suite covers:

- obfs encode/decode for all four WireGuard message types, padding bounds,
  junk packet sizes, invalid magic and plaintext WireGuard rejection;
- WebSocket batch framing and strict length checks;
- config validation, key parsing, MTU and ALPN constraints;
- routing precedence, suffix boundaries, Unicode/punycode suffixes, GeoIP,
  `tunnel_override` and degraded mode;
- nftables ruleset and ip-rule generation, rollback, crash recovery and server
  NAT rules;
- split DNS classification, cache TTL/bounds, upstream routing, systemd
  resolved takeover and restoration;
- a real `boringtun` handshake between two tunnel instances, transport data in
  both directions, PSK mismatch and garbage input;
- obfs UDP over loopback, failover state machine with a fake clock and
  per-network preferences;
- server peer loading, duplicate detection and inner source/destination
  parsing.

## netns rig

`tests/netns/run.sh` builds three network namespaces:

```text
rt-client (10.200.1.2/24, 2001:db8:1::2/64)
   |
rt-net    (10.200.1.1, 10.200.2.1, service addresses, DPI rules)
   |
rt-server (10.200.2.2/24, 2001:db8:2::2/64)
```

It starts `rtund` in `rt-server`, `rt-clientd --headless` in `rt-client` and
runs connectivity, routing, MTU and kill-switch checks. Profiles select DPI
behaviour in `rt-net`.

```bash
sudo tests/netns/run.sh                 # no DPI
sudo PROFILE=udp-drop tests/netns/run.sh
sudo PROFILE=wg-signature tests/netns/run.sh
sudo PROFILE=throttle tests/netns/run.sh
sudo PROFILE=ipv6-blackhole tests/netns/run.sh
```

The rig requires `CAP_NET_ADMIN`, `iproute2`, `nftables`, `tc` and `python3`.
On a development machine without root it can run in a user namespace:

```bash
unshare -Urnm --map-root-user bash -c \
  'mount -t tmpfs tmpfs /run && mkdir -p /run/netns && tests/netns/run.sh'
```

It uses only the obfs transport because a trusted TLS certificate is required
for `ws-tls`; WSS failover and decoy behaviour are validated on a real domain.

### DPI profiles

| Profile | Rule | Expected result |
|---|---|---|
| `none` | no filtering | connected over `obfs-udp` |
| `udp-drop` | drop UDP/443 | health checks fail, state `degraded`, direct traffic still works |
| `wg-signature` | drop UDP/443 with length 148 | obfs traffic passes |
| `throttle` | `tbf` 2 Mbit/s on UDP path | handshake and small transfers still work |
| `ipv6-blackhole` | blackhole IPv6 default route | endpoint falls back to IPv4 |
| `tcp-drop` | drop TCP/443 | obfs remains connected |

## Real-domain checks

On a VPS with a certificate:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://vpn.example.com/
rt-ctl decoy-check --url https://vpn.example.com/
```

Run the client with `priority = ["obfs-udp", "ws-tls"]`, block UDP/443 on a
test network and confirm the transport switches to `ws-tls` within five
seconds. Then remove the block and confirm the anti-flap window prevents an
immediate switch back.

DNS leak checks:

```bash
resolvectl query example.ru
resolvectl query example.com
sudo rt-ctl route example.ru
sudo rt-ctl route example.com
```

Capture on the physical interface and verify that `.ru` queries go to the
physical DNS server while other names go only inside the tunnel.

## Performance

```bash
iperf3 -s                      # on the server, bound to 10.66.0.1
iperf3 -c 10.66.0.1 -P 4 -t 30 # on the client
iperf3 -c 10.66.0.1 -P 4 -R -t 30
```

Targets: at least 300 Mbit/s with `obfs-udp` on one vCPU and 100 Mbit/s with
`ws-tls`; handshake under 300 ms on a nearby VPS; reconnect under two seconds.
Use `perf top` and `ss -s` to check CPU and packet drops.

## Field matrix

Record for each carrier/home ISP:

- transport that succeeded at startup and after five minutes;
- handshake time and RTT;
- whether UDP/443 was throttled;
- `.ru` and GeoIP routing correctness;
- DNS mode (`split` or degraded);
- IPv4-only, IPv6-only and dual-stack networks;
- suspend/resume and Wi-Fi/Ethernet changes.

Keep the raw `status.json` and `journalctl` output without keys.
