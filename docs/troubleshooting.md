# Troubleshooting

## First checks

```bash
systemctl status rt-clientd
journalctl -u rt-clientd -n 200 --no-pager
sudo rt-ctl status
ip -brief address show rtun0
ip rule show
ip route show table 51820
nft list table inet rtun
nft list table inet rtun_ks
```

`/run/rtun/status.json` contains the state, transport, endpoint, RTT, byte
counters and the last error. States are `disconnected`, `resolving`,
`handshaking`, `connected`, `degraded` and `reconnecting`.

## The daemon cannot create rtun0

- Check that `rt-clientd` runs as root or has `CAP_NET_ADMIN`.
- Check that `/dev/net/tun` exists (`ls -l /dev/net/tun`), and that the `tun`
  module is available (`modprobe tun`).
- `ProtectSystem=strict` requires `/run/rtun` and `/var/lib/rtun` to be
  writable; the shipped unit lists them in `ReadWritePaths`.

## Handshake never completes

1. Confirm the client and server obfs magic values are identical.
2. Confirm the client `peer_public_key` is the server public key, and that the
   peer file on the server contains the client public key.
3. If a preshared key is configured on one side, it must be on both.
4. Check server reachability:

```bash
nc -vzu vpn.example.com 443
nc -vz vpn.example.com 443
```

UDP silence is expected from unauthenticated probes; use the client logs and
server `journalctl -u rtund`.

5. Verify the server clock. WireGuard handshakes fail with a large clock skew.

## UDP is blocked, WSS is not used

- Confirm `priority = ["obfs-udp", "ws-tls"]`.
- Check nginx: `curl -I https://vpn.example.com/` must return `200`, and the
  certificate must be valid.
- A WebSocket upgrade must include `Sec-WebSocket-Protocol: rtun.v1`; nginx
  returns an error for connections without it.
- `ws-tls` requires the domain and a valid certificate. Without them, only
  `obfs-udp` is available.

## Both transports fail

- The VPS IP may be blocked. Test from another network and check whether the
  TCP handshake reaches nginx (`tcpdump -ni any port 443`).
- Try IPv4-only and IPv6-only networks. The resolver interleaves A/AAAA and
  falls back to the last known good address.
- Check server disk, conntrack table and rate limiting:

```bash
nft list table inet rtun_srv
conntrack -S
journalctl -u rtund -n 100
```

## DNS broke after a crash

The daemon writes `/run/rtun/resolved-marker.json` before touching resolved.
On next start it restores the previous drop-in. Manual recovery:

```bash
sudo rm -f /etc/systemd/resolved.conf.d/rtun.conf
sudo rm -f /run/rtun/resolved-marker.json
sudo systemctl restart systemd-resolved
resolvectl status
```

If you used the degraded fallback, also remove any `DNS=127.0.0.1:5533` line
from the drop-in before restarting.

## `DNS: degraded (GeoIP)` is shown

Domain rules are disabled. Common causes:

- the stub listener could not be disabled (resolved is managed by another
  tool, or the drop-in directory is read-only under the unit sandbox);
- port 53 was occupied by another resolver;
- no direct upstream DNS server was discovered in
  `/run/systemd/resolve/resolv.conf` or `/etc/resolv.conf`.

GeoIP routing and the tunnel still work; `.ru` domains may be tunneled if
their addresses are not in the GeoIP database. Fix the resolver and restart
`rt-clientd`.

## Traffic to a Russian site goes through the tunnel

- The domain may resolve through DoH/DoT inside a browser, bypassing the
  proxy; GeoIP fallback applies.
- The site may use a CDN with a non-RU address. Add it to
  `tunnel_override_cidrs` only if it must always be tunneled; add it to
  `direct_cidrs` if it must always be direct.
- Check the decision: `sudo rt-ctl route <domain-or-ip>`.
- Refresh GeoIP data: `sudo rt-ctl geoip-update`.

## MTU and PMTU

- `obfs-udp` uses MTU 1360; test with `ping -M do -s 1332 <host>`.
- `ws-tls` uses MTU 1280; test with `ping -M do -s 1252 <host>`.
- If large packets stall but small ones work, a middlebox is dropping
  fragments. Reduce the MTU in `/etc/rtun/client.toml` (keep 1280 minimum) and
  restart the daemon.
- MSS clamping is installed on both client and server; applications that
  ignore path MTU still depend on it.

## IPv6 does not work

- Confirm the client has a global IPv6 address and a default route outside
  the tunnel.
- Confirm the server has IPv6 connectivity and that the VPS provider does not
  filter protocol 41 or IPv6 UDP.
- When the IPv6 path is blackholed, the resolver should fall back to IPv4 for
  the endpoint. Inside the tunnel both families still work through NAT66.
- Check `ping -6 -c1 fd66:1::1` and `ip -6 rule show`.

## Kill switch blocks everything after a crash

This is intentional. The daemon recovers state on start. If it cannot start:

```bash
sudo nft list table inet rtun_ks
sudo nft delete table inet rtun_ks
sudo nft delete table inet rtun
sudo ip rule del pref 100 fwmark 0x1 lookup main 2>/dev/null || true
sudo ip rule del pref 200 lookup 51820 2>/dev/null || true
sudo ip route flush table 51820
```

Then fix the daemon before reconnecting. Removing the kill-switch table without
fixing routing can leak traffic.

## GUI says the daemon is unavailable

- `systemctl status rt-clientd`
- `busctl introspect org.rtun.Client1 /org/rtun/Client1`
- Check `/usr/share/dbus-1/system.d/org.rtun.Client1.conf` is installed and
  reload D-Bus (`systemctl reload dbus`).
- Non-root operations require polkit. On a desktop, an authentication agent
  must be running; on a headless system use `sudo rt-clientd --headless` or
  run the CLI as root.

## Collecting diagnostics

```bash
sudo rt-ctl status
sudo rt-clientd --config /etc/rtun/client.toml --check-config
sudo nft list ruleset > /tmp/rtun-nft.txt
ip -details link show rtun0
ip rule show
ip route show table 51820
journalctl -u rt-clientd -u systemd-resolved -n 300 --no-pager > /tmp/rtun-log.txt
```

Do not paste private keys or full configs into issue reports.
