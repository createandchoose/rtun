# Threat model

## Assets

- WireGuard private keys and preshared keys.
- The server IP, domain and long-lived transport parameters (obfs headers,
  ports, WS path).
- Metadata: which client connects when, and which destinations it uses.
- Availability of the client's direct (Russian) connectivity.

## Adversary

1. **On-path DPI (TSPU/ISP)** that classifies UDP/TCP flows, throttles unknown
   UDP, inspects TLS SNI and resets suspicious connections.
2. **Active prober** that connects to the server's IP and port and tries to
   identify a VPN.
3. **Passive observer** recording flow sizes, timings and endpoints.
4. **Local unprivileged user** on the client machine trying to read keys or
   control the tunnel.
5. **Compromised or seized VPS** (out of scope for cryptographic protection;
   keys are per-device and can be revoked by removing a peer file).

## Mitigations

| Threat | Mitigation |
|---|---|
| WireGuard signature on UDP | Random 32-bit magic header, padding, junk packets, silent drops on bad magic |
| Active UDP probing | No response to invalid headers; no plaintext protocol banner |
| TLS/SNI blocking | Decoy HTTPS site with a valid certificate; WebSocket path behind nginx; `ws-tls` fallback |
| Active HTTPS probing | Decoy returns a normal static site; `/ws` requires the `rtun.v1` subprotocol |
| Traffic analysis | Batching and padding; no fixed small-packet cadence; configurable padding |
| DNS leaks | Local split resolver, plaintext DNS to non-direct destinations dropped, tunnel DNS through unbound |
| IPv6 leaks | Dual-stack kill switch and default route in table 51820 |
| Key theft at rest | Config mode `0600`, keys never logged, private keys only on clients |
| Local tampering | Root-only daemon, polkit authorization, D-Bus name owned by root |
| Crash leaks | Kill switch installed before TUN and removed after it; state recovery on start |
| Server compromise | Per-device public keys; no client private keys on the server; remove peer files and reload |

## Residual risks

- **IP/AS blocking.** No transport survives an IP block. Keep a second
  endpoint and rotate.
- **Foreign UDP throttling.** `obfs-udp` may be throttled regardless of
  payload. `ws-tls` is the required fallback; if both are blocked, a REALITY
  class transport would be needed (the `Transport` trait is designed for it).
- **TLS fingerprint.** rustls does not perfectly match a browser ClientHello.
  This is a known limitation; BoringSSL or a REALITY-class transport is future
  work.
- **TLS-in-TLS entropy.** WebSocket-over-TLS inside TLS can be detected
  statistically. Batching and padding reduce but do not eliminate the signal.
- **DoH/DoT bypass.** Applications that ignore the system resolver cannot be
  classified by domain; GeoIP fallback may tunnel Russian CDN addresses.
- **Compromised client.** A local root attacker can read keys and traffic.
- **Legal.** The user is responsible for complying with applicable law and
  provider terms.

## Non-goals

- Anonymity against a global passive adversary.
- Hiding the fact that a VPN client is installed.
- Multi-user billing, subscriptions or account management.
- Protecting traffic after the server is fully compromised.
