# RTUN

RTUN is a personal VPN built in Rust for an Ubuntu client and a Linux VPS. It
tunnels through DPI-heavy networks with two pluggable transports, while keeping
Russian and LAN traffic direct.

## Features

- WireGuard data plane via `boringtun`, with per-device keys and optional PSK.
- `obfs-udp`: random 32-bit message headers, padding and AmneziaWG-style junk
  packets; protocol failures are silently dropped.
- `ws-tls`: WebSocket over TLS 1.3/1.2 behind nginx, `rtun.v1` subprotocol, a
  static decoy site and HTTP/1.1 ALPN on the client.
- Automatic failover between transports with handshake health checks,
  anti-flapping and per-network preferences.
- Dual-stack tunnel (`10.66.0.0/24`, `fd66:1::/64`) with NAT44 and NAT66.
- Smart routing: `.ru`, `.рф`, `.su`, `.xn--p1ai`, Moscow suffixes, GeoIP RU
  and LAN go direct; everything else is tunneled.
- Split DNS on `127.0.0.53:53` with a safe systemd-resolved takeover and a
  GeoIP-only degraded mode.
- Kill switch applied before the TUN device and removed after it.
- Slint desktop window, `ksni` tray, D-Bus API and polkit authorization.
- `rt-ctl` for keys, configs, peers, route dry-runs, GeoIP updates and decoy
  checks.
- Packaging: systemd units, D-Bus/polkit policy, nginx/unbound/nftables
  templates, server/client installers and a `.deb` builder.

## Workspace

| Crate | Purpose |
|---|---|
| `rt-proto` | Config, keys, obfs codec, WS framing, routing decisions |
| `rt-transport` | `Transport` trait, obfs UDP, WSS, Happy Eyeballs resolver, failover |
| `rt-tunnel` | `boringtun` wrapper and TUN device |
| `rt-routing` | nftables/ip rules, kill switch, GeoIP, crash recovery |
| `rt-dns` | Split DNS proxy and systemd-resolved takeover |
| `rt-clientd` | Privileged client daemon, state machine, D-Bus service |
| `rt-server` | `rtund`: TUN, obfs UDP, WS backend, peers, NAT |
| `rt-client-gui` | Slint window and tray UI |
| `rt-ctl` | Operator CLI |

## Build

```bash
rustup toolchain install stable --component rustfmt clippy
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Slint needs `pkg-config`, `libfontconfig1-dev`, `libfreetype-dev`,
`libxkbcommon-dev` and `libwayland-dev` at build time.

## Quick start

Server (Ubuntu VPS, root, domain pointed at the server):

```bash
cargo build --release
sudo packaging/server/install.sh --domain vpn.example.com --email admin@example.com
sudo rt-ctl add-peer --peers-dir /etc/rtun/peers --name laptop --index 2 \
  --server-config /etc/rtun/server.toml
```

Client:

```bash
cargo build --release
sudo packaging/client/install.sh --config ./client.toml
rt-client-gui
```

The client config can be produced on the server with `rt-ctl gen-client`; see
[docs/client.md](docs/client.md).

## Documentation

- [Server setup](docs/server-setup.md)
- [Client usage](docs/client.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Threat model](docs/threat-model.md)
- [Testing and the netns rig](docs/testing.md)
- [Implementation status](docs/implementation-status.md)

## Security notes

Private keys are written with mode `0600` and never logged. The server stores
only public keys. DNS and destination addresses are not logged. The decoy site
is mandatory for `ws-tls`, and the transport ignores packets with an unknown
obfuscation header without replying.

The user is responsible for complying with local law and provider terms.

## License

MIT. See [LICENSE-MIT](LICENSE-MIT).
