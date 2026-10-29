//! Opt-in check against an installed VPS; never changes local routes or DNS.
//! RTUN_LIVE_CONFIG=/path/client.toml cargo test -p rt-server --test live_server -- --ignored
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use rt_proto::{ClientConfig, ObfsCodec};
use rt_tunnel::{TunnelConfig, TunnelEvent, WgTunnel};

#[test]
fn daemon_exits_when_server_startup_fails() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("server.toml");
    let config = rt_proto::ServerConfig {
        private_key: rt_proto::keys::generate_private_key(),
        peers_dir: dir
            .path()
            .join("missing-peers")
            .to_string_lossy()
            .into_owned(),
        ..rt_proto::ServerConfig::default()
    };
    config.save(&config_path).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_rtund"))
        .arg("--config")
        .arg(config_path)
        .arg("--run-dir")
        .arg(dir.path().join("run"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("daemon hid a failed server task instead of exiting");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|b| u16::from_be_bytes([b[0], *b.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn query(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let dns =
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let mut packet = vec![0u8; 28 + dns.len()];
    packet[0] = 0x45;
    let len = packet.len() as u16;
    packet[2..4].copy_from_slice(&len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    let sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet[20..22].copy_from_slice(&53001u16.to_be_bytes());
    packet[22..24].copy_from_slice(&53u16.to_be_bytes());
    packet[24..26].copy_from_slice(&(8u16 + dns.len() as u16).to_be_bytes());
    packet[28..].copy_from_slice(dns);
    packet
}

#[test]
#[ignore = "requires RTUN_LIVE_CONFIG and an installed server"]
fn udp_tunnel_resolves_dns_and_forwards_internet_traffic() {
    let config =
        ClientConfig::load(std::env::var("RTUN_LIVE_CONFIG").expect("RTUN_LIVE_CONFIG")).unwrap();
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket
        .connect((config.endpoint.host.as_str(), config.endpoint.port))
        .unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let codec = ObfsCodec::new(&config.obfs).unwrap();
    let mut tunnel = WgTunnel::new(
        TunnelConfig::from_base64(
            &config.device.private_key,
            &config.device.peer_public_key,
            config.device.preshared_key.as_deref(),
            Some(25),
            1,
        )
        .unwrap(),
    );
    let send = |packet: &[u8]| {
        socket
            .send(&codec.encode(packet, &mut rand::thread_rng()).unwrap())
            .unwrap();
    };
    let TunnelEvent::Network(init) = tunnel.force_handshake() else {
        panic!("handshake initiation");
    };
    send(&init);
    let mut buffer = [0u8; 65535];
    let len = socket
        .recv(&mut buffer)
        .expect("handshake response from VPS");
    let decoded = codec.decode(&buffer[..len]).unwrap();
    for event in tunnel.decrypt(None, decoded.wireguard) {
        if let TunnelEvent::Network(packet) = event {
            send(&packet);
        }
    }
    assert!(tunnel.stats().last_handshake.is_some());
    for destination in [config.dns.server_v4.octets(), [1, 1, 1, 1]] {
        let packet = query(config.device.address_v4.octets(), destination);
        let TunnelEvent::Network(encrypted) = tunnel.encrypt(&packet) else {
            panic!("encrypted query");
        };
        send(&encrypted);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(Instant::now() < deadline, "DNS reply timed out");
            let len = socket.recv(&mut buffer).expect("DNS reply through VPS");
            let decoded = codec.decode(&buffer[..len]).unwrap();
            let mut answered = false;
            for event in tunnel.decrypt(None, decoded.wireguard) {
                match event {
                    TunnelEvent::Network(packet) => send(&packet),
                    TunnelEvent::Ip(packet) if packet.len() >= 40 && packet[9] == 17 => {
                        let offset = (packet[0] as usize & 15) * 4 + 8;
                        if packet.len() >= offset + 12 && packet[offset..offset + 2] == [0x12, 0x34]
                        {
                            assert_eq!(packet[offset + 3] & 15, 0, "DNS error");
                            assert!(
                                u16::from_be_bytes([packet[offset + 6], packet[offset + 7]]) > 0
                            );
                            answered = true;
                        }
                    }
                    _ => {}
                }
            }
            if answered {
                break;
            }
        }
    }
}
