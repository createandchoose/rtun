# netns rig

`run.sh` creates the three namespaces described in `docs/testing.md`, starts
`rtund` and `rt-clientd --headless`, and runs connectivity, MTU, routing and
kill-switch checks.

```bash
sudo tests/netns/run.sh
sudo PROFILE=udp-drop KEEP_WORK=1 tests/netns/run.sh
```

Environment:

- `PROFILE` — `none`, `udp-drop`, `wg-signature`, `tcp-drop`, `throttle` or
  `ipv6-blackhole`.
- `BIN_DIR` — directory with `rtund`, `rt-clientd`, `rt-ctl`; defaults to
  `target/release` and builds it if missing.
- `KEEP_WORK` — keep logs and generated configs under `/tmp/rtun-netns.*`.

The client runs with `--no-dns` because the netns cannot safely exercise the
host's systemd-resolved. The DNS takeover, split upstreams and leak checks are
covered by `rt-dns` unit tests and by the real-machine procedure in
`docs/testing.md`.

`ws-tls` is not exercised here: it requires nginx plus a certificate trusted
by rustls. Use a real domain for WSS failover checks.

Cleanup removes all namespaces, processes and temporary files unless
`KEEP_WORK=1` is set.
