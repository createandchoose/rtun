# Implementation status

This repository implements the plan through T5, with T6 artifacts and T7
extension points. The unit and static gates are green locally:

```text
cargo fmt --all -- --check        ok
cargo clippy --workspace --all-targets -- -D warnings   ok
cargo test --workspace            101 tests passed
cargo audit                       no vulnerabilities
cargo build --release --workspace ok
packaging/deb/build-deb.sh        rtun-client_0.1.0_amd64.deb built
```

## Milestones

| Milestone | State | Evidence |
|---|---|---|
| T0 workspace, configs, CI | done | 9 crates, `Cargo.lock`, CI workflow, fmt/clippy/tests/audit |
| T1 tunnel and connectivity | verified | dual-stack handshake/data tests; netns IPv4/IPv6/HTTP/MTU/kill-switch checks pass |
| T2 `obfs-udp` | verified | magic/padding/junk tests; netns profiles `none`, `wg-signature`, `throttle`, `tcp-drop`, `ipv6-blackhole`, `udp-drop` pass |
| T3 routing, DNS, kill switch | verified | per-destination routes in table 51820, GeoIP parser, split DNS + resolved takeover/restore, kill switch, crash recovery tests |
| T4 `ws-tls`, decoy, failover | implemented | rustls/tungstenite client, `rtun.v1` subprotocol, batching, nginx/unbound templates, failover state machine |
| T5 GUI, D-Bus, packaging | implemented | Slint window, ksni tray, zbus + polkit, systemd units, `.deb` builder |
| T6 performance/hardening/docs | partial | hardening, docs, audit; syscall batching and 24 h soak not measured |
| T7 optional | extension points | `Transport` trait, config lists; QUIC/REALITY/multi-server/per-app not built |

## Not verifiable in this environment

- `tests/netns/run.sh` was executed in a rootless user/mount/network
  namespace on kernel 7.0. All profiles pass. It still needs `CAP_NET_ADMIN`
  (root or a user namespace with `unshare -Urnm`).
- `ws-tls` needs a real domain with A/AAAA and a trusted certificate. Code and
  nginx/assets are present, but the WSS handshake/decoy check must run on the
  VPS.
- Real-carrier DPI and throughput numbers need field testing.
- The GUI was compiled but not launched because this environment has no display.

## Known limitations

- rustls does not reproduce a browser ClientHello byte-for-byte; see
  `docs/threat-model.md` R3.
- UDP batching (`recvmmsg`/`sendmmsg`) and multi-queue tuning are not
  implemented yet; the hot path uses Tokio per-datagram calls.
- DoH is used for endpoint bootstrap, not as the normal resolver. Application
  DoH/DoT bypasses domain classification and falls back to GeoIP.
- The kill switch intentionally stays installed after `SIGKILL`; recovery is on
  the next daemon start.
- `rt-ctl geoip-update` uses `curl` for HTTPS downloads and validates the
  parsed zones before atomic replacement.
