# Client installation and usage

## Windows: Russian sites outside the VPN

With `SmartRouting = true` in `.conf` (`routing.smart_routing = true` in TOML),
the Windows client runs a local UDP/TCP DNS proxy. Russian suffixes from
`DirectSuffixes`, including `.ru`, `.рф` and `.su`, resolve through the physical
adapter's DNS. Other names resolve through the tunnel. Before returning an
answer, the client installs physical host routes for Russian domains and for
addresses in the Russian GeoIP database. Other addresses keep using the VPN;
`TunnelOverrideCidrs` takes precedence over automatic bypass.

The country database is downloaded before connecting and cached under
`%LOCALAPPDATA%\rtun\geoip`, refreshed at the configured interval. If refreshing
fails, an existing cache is used. If no country database or direct DNS server
is available, the connection reports the problem rather than silently disabling
the bypass. Routes learned during the connection are removed on disconnect.
Native IPv6 is used when the physical adapter has an IPv6 default gateway;
otherwise Russian AAAA answers are suppressed so applications use direct IPv4.

Domain learning requires system DNS. Applications using their own DoH/DoT,
private DNS caches or literal IP addresses can bypass DNS-based classification.
An IP route applies to every site sharing that address. Restart the client and
reconnect after updating; a running process keeps its previous code.

## Requirements

- Ubuntu 22.04, 24.04 or newer, x86_64.
- systemd and systemd-resolved.
- nftables and `iproute2`.
- A `client.toml` produced by `rt-ctl gen-client` on the server.

## Install

From a `.deb`:

```bash
sudo apt install ./rtun-client_0.1.0_amd64.deb
```

From the source tree:

```bash
cargo build --release
sudo packaging/client/install.sh --config ./client.toml
```

The installer places:

| Path | Purpose |
|---|---|
| `/usr/bin/rt-clientd` | privileged daemon |
| `/usr/bin/rt-client-gui` | Slint window and tray |
| `/usr/bin/rt-ctl` | diagnostics CLI |
| `/etc/rtun/client.toml` | mode `0600`, root only |
| `/etc/systemd/system/rt-clientd.service` | daemon unit |
| `/usr/share/dbus-1/system.d/org.rtun.Client1.conf` | D-Bus policy |
| `/usr/share/polkit-1/actions/org.rtun.client.policy` | polkit action |
| `/etc/xdg/autostart/rtun-gui.desktop` | autostart for the tray |

Start the GUI with `rt-client-gui`. The daemon starts automatically; the GUI
sends `Connect` over D-Bus.

## Configuration

`/etc/rtun/client.toml`:

```toml
[endpoint]
host = "vpn.example.com"
port = 443
ws_path = "/ws"
alpn = "http/1.1"          # ws-tls uses WebSocket over HTTP/1.1

[device]
private_key = "..."
peer_public_key = "..."
preshared_key = "..."       # optional
address_v4 = "10.66.0.2"
address_v6 = "fd66:1::2"
mtu_obfs = 1360
mtu_ws = 1280
persistent_keepalive = 25

[obfs]
h1 = 3054197761             # must match the server
h2 = 3054197762
h3 = 3054197763
h4 = 3054197764
padding_max = 8
junk_count = 4
junk_min = 80
junk_max = 300

[transports]
priority = ["obfs-udp", "ws-tls"]
ws_start_delay_ms = 300
health_interval_secs = 5
health_misses = 3
handshake_timeout_ms = 4000

[routing]
direct_suffixes = ["ru", "рф", "xn--p1ai", "su", "moscow", "москва", "xn--80adxhks"]
direct_cidrs = []
tunnel_override_cidrs = []
smart_routing = true

[dns]
listen = ["127.0.0.53:53", "127.0.0.1:53", "[::1]:53"]
intercept_stub = true
doh_fallback = true

kill_switch = true
log_level = "info"
```

Obfs magic values are generated per server by `rt-ctl gen-server` and copied
into every client config. A mismatch produces silent drops.

## Transports

- **obfs-udp** is the primary transport on `UDP/443`. Before the first
  handshake it sends junk datagrams, then pads each WireGuard message and
  replaces the WireGuard header with a random 32-bit magic.
- **ws-tls** is the fallback on `TCP/443` behind nginx. It negotiates the
  `rtun.v1` WebSocket subprotocol, batches up to 32 datagrams per binary frame,
  sends a ping every 20 s and reconnects with jittered backoff. Client ALPN is
  `http/1.1`; browsers still get HTTP/2 on the decoy site.

The daemon tries the configured priority at startup. A handshake timeout or
three missed health checks switches transport. Switching back requires a
lower RTT by more than 30% and respects the five-minute anti-flap interval.
Preferences are remembered per network (SSID plus default gateway).

## Smart routing

Rules, first match wins:

1. loopback, LAN, private, link-local, multicast, broadcast -> direct;
2. endpoint addresses -> direct;
3. `tunnel_override` CIDRs -> tunnel;
4. direct CIDRs (including DNS answers for `.ru` domains) -> direct;
5. GeoIP RU -> direct;
6. everything else -> tunnel.

The client installs an nftables table `inet rtun` and marks direct packets
with `fwmark 0x1` for the kill switch. Routing itself does not depend on that
mark: direct prefixes are installed as more-specific routes in table `51820`
via the physical default gateway, while `10.66.0.0/24` and `fd66:1::/64` get
explicit `dev rtun0` routes. The table's default route points at `rtun0`, so
unlisted destinations are tunneled even though the physical default route is
still in the main table.

```text
ip rule pref 200 lookup 51820
ip route show table 51820
```

This avoids relying on nftables mark rewrites for locally generated packets,
which do not reroute reliably on all kernels. Marking remains useful for the
kill switch and for diagnostics. Internal tunnel ranges are never placed in
the direct sets, so DNS and tunnel traffic cannot escape.

Dry-run a destination:

```bash
sudo rt-ctl route 8.8.8.8
sudo rt-ctl route www.example.ru
```

## DNS

On start the daemon:

1. restores any stale takeover from a previous crash;
2. disables the systemd-resolved stub listener through
   `/etc/systemd/resolved.conf.d/rtun.conf` (`DNSStubListener=no`);
3. restarts systemd-resolved;
4. binds `127.0.0.53:53`, `127.0.0.1:53` and `[::1]:53` (UDP and TCP).

`.ru`/`.рф`/`.su` queries go to the physical link's DNS servers (discovered
before the takeover). Everything else goes to `10.66.0.1`/`fd66:1::1` through
the tunnel, where unbound resolves with DNSSEC.

A/AAAA answers feed the nftables sets with TTL-based timeouts. A non-RU domain
that resolves to a RU address is added to `tunnel_override` so that the CDN
address is not accidentally sent direct.

Plaintext DNS to destinations outside the direct sets is dropped. DoH/DoT
traffic from browsers cannot be classified by name; those connections fall
back to GeoIP rules. The UI shows `DNS: split` or `DNS: degraded (GeoIP)`.

Fallback: if the stub listener cannot be disabled, the proxy binds
`127.0.0.1:5533` and resolved is pointed at it with `DNS=127.0.0.1:5533`,
`Domains=~.`. If even that fails, the daemon runs without domain rules
(GeoIP-only, degraded). On normal stop it removes the drop-in, restores the
previous file (or deletes it if it did not exist) and restarts resolved.

## Kill switch

Enabled by default. The `inet rtun_ks` table drops all output except:

- established/related traffic;
- loopback and `rtun0`;
- packets marked direct by the routing table;
- DNS to the local proxy and to the tunnel DNS server;
- DHCP, DHCPv6 and IPv6 neighbour discovery.

The kill-switch table is installed before the TUN device and removed only
after it is closed. A crashed daemon therefore leaves the machine without
leaks; systemd restarts the daemon, which recovers stale routing state.

## GUI and tray

- status, endpoint, transport, RTT and byte counters;
- Connect/Disconnect;
- transport selection (`UDP (obfs)` / `WSS (резерв)`);
- kill-switch toggle;
- DNS mode and the last error.

The tray menu mirrors connect/disconnect, transport selection and quit. D-Bus
methods are authorized through polkit action `org.rtun.client.control`; root is
always allowed. The GUI never receives private keys.

## Commands

```bash
sudo rt-clientd --config /etc/rtun/client.toml --check-config
sudo rt-clientd --config /etc/rtun/client.toml --headless   # no D-Bus
sudo rt-ctl status
sudo rt-ctl route example.com
sudo rt-ctl geoip-update
sudo rt-ctl decoy-check --url https://vpn.example.com/
systemctl status rt-clientd
journalctl -u rt-clientd -f
```

`rt-clientd --headless` is intended for the netns test rig and debugging.
`--no-dns` skips the systemd-resolved takeover and the local DNS proxy, which
is required inside a network namespace because `systemctl` would otherwise act
on the host.

## Uninstall

```bash
sudo apt purge rtun-client
# or
sudo packaging/client/uninstall.sh
```

Verify `/etc/systemd/resolved.conf.d/rtun.conf` is gone and
`systemctl status systemd-resolved` is healthy. If the daemon was killed with
`SIGKILL`, run it once normally and stop it, or delete the drop-in manually and
restart resolved.
