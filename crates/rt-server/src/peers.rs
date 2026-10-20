use std::net::IpAddr;
use std::path::Path;

use rt_proto::PeerConfig;

pub fn load_peers(dir: &Path) -> Result<Vec<PeerConfig>, String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|error| format!("cannot read peers directory {}: {error}", dir.display()))?;
    let mut peers = Vec::new();
    let mut names = Vec::new();
    let mut addresses: Vec<IpAddr> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read peers directory: {error}"))?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let peer = PeerConfig::from_toml(&text)
            .map_err(|error| format!("invalid peer {}: {error}", path.display()))?;
        if names.contains(&peer.name) {
            return Err(format!("duplicate peer name {}", peer.name));
        }
        if addresses.contains(&IpAddr::V4(peer.address_v4))
            || addresses.contains(&IpAddr::V6(peer.address_v6))
        {
            return Err(format!("duplicate peer address for {}", peer.name));
        }
        names.push(peer.name.clone());
        addresses.push(IpAddr::V4(peer.address_v4));
        addresses.push(IpAddr::V6(peer.address_v6));
        if peer.enabled {
            peers.push(peer);
        }
    }
    peers.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(peers)
}

pub fn source_ip(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => Some(IpAddr::from([
            packet[12], packet[13], packet[14], packet[15],
        ])),
        Some(6) if packet.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[8..24]);
            Some(IpAddr::from(octets))
        }
        _ => None,
    }
}

pub fn destination_ip(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => Some(IpAddr::from([
            packet[16], packet[17], packet[18], packet[19],
        ])),
        Some(6) if packet.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            Some(IpAddr::from(octets))
        }
        _ => None,
    }
}

pub fn unbound_config(server_v4: &str, server_v6: &str) -> String {
    format!(
        "server:\n  interface: {server_v4}\n  interface: {server_v6}\n  access-control: 10.66.0.0/24 allow\n  access-control: fd66:1::/64 allow\n  access-control: 127.0.0.0/8 allow\n  access-control: ::1/128 allow\n  do-not-query-localhost: no\n  qname-minimisation: yes\n  hide-identity: yes\n  hide-version: yes\n  harden-glue: yes\n  harden-dnssec-stripped: yes\n  use-caps-for-id: yes\n  val-clean-additional: yes\n  log-queries: no\n  logfile: \"\"\n  verbosity: 0\n  ip-freebind: yes\n\nforward-zone:\n  name: \".\"\n  forward-tcp-upstream: yes\n  forward-addr: 1.1.1.1\n  forward-addr: 8.8.8.8\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rt_proto::keys::public_key_from_private;

    fn peer(name: &str, last: u8) -> PeerConfig {
        let private = rt_proto::keys::generate_private_key();
        PeerConfig {
            name: name.into(),
            public_key: public_key_from_private(&private).unwrap(),
            preshared_key: None,
            address_v4: format!("10.66.0.{last}").parse().unwrap(),
            address_v6: format!("fd66:1::{last}").parse().unwrap(),
            enabled: true,
        }
    }

    #[test]
    fn loads_and_validates_peers() {
        let dir = tempfile::tempdir().unwrap();
        for peer in [peer("alpha", 2), peer("beta", 3)] {
            std::fs::write(
                dir.path().join(format!("{}.toml", peer.name)),
                peer.to_toml().unwrap(),
            )
            .unwrap();
        }
        std::fs::write(dir.path().join("ignored.txt"), "garbage").unwrap();
        let peers = load_peers(dir.path()).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].name, "alpha");
    }

    #[test]
    fn rejects_duplicate_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let a = peer("alpha", 2);
        let mut b = peer("beta", 2);
        b.address_v4 = a.address_v4;
        std::fs::write(dir.path().join("a.toml"), a.to_toml().unwrap()).unwrap();
        std::fs::write(dir.path().join("b.toml"), b.to_toml().unwrap()).unwrap();
        assert!(load_peers(dir.path()).is_err());
    }

    #[test]
    fn extracts_ipv4_and_ipv6_addresses() {
        let mut v4 = vec![0u8; 20];
        v4[0] = 0x45;
        v4[12..16].copy_from_slice(&[10, 66, 0, 2]);
        v4[16..20].copy_from_slice(&[8, 8, 8, 8]);
        assert_eq!(source_ip(&v4), Some("10.66.0.2".parse().unwrap()));
        assert_eq!(destination_ip(&v4), Some("8.8.8.8".parse().unwrap()));

        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[8..24].copy_from_slice(&[0xfd, 0x66, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        v6[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(source_ip(&v6), Some("fd66:1::2".parse().unwrap()));
        assert_eq!(destination_ip(&v6), Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn malformed_packets_have_no_addresses() {
        assert!(source_ip(&[0x45]).is_none());
        assert!(destination_ip(&[]).is_none());
    }

    #[test]
    fn unbound_config_restricts_access() {
        let config = unbound_config("10.66.0.1", "fd66:1::1");
        assert!(config.contains("interface: 10.66.0.1"));
        assert!(config.contains("access-control: 10.66.0.0/24 allow"));
        assert!(config.contains("log-queries: no"));
        assert!(config.contains("qname-minimisation: yes"));
        assert!(config.contains("ip-freebind: yes"));
        assert!(config.contains("forward-tcp-upstream: yes"));
        assert!(config.contains("access-control: 127.0.0.0/8 allow"));
    }
}
