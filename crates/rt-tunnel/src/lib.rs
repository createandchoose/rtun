pub mod device;
pub mod error;
pub mod keys;

pub use device::{open_tun, TunnelStats};
pub use error::TunnelError;
pub use keys::{keypair, tunnel_keypair};

use std::net::IpAddr;
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use error::classify;

#[derive(Clone)]
pub struct TunnelConfig {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<u16>,
    pub index: u32,
}

impl TunnelConfig {
    pub fn from_base64(
        private_key: &str,
        peer_public_key: &str,
        preshared_key: Option<&str>,
        persistent_keepalive: Option<u16>,
        index: u32,
    ) -> Result<Self, TunnelError> {
        Ok(Self {
            private_key: rt_proto::keys::parse_private_key(private_key)
                .map_err(|error| TunnelError::InvalidKey(error.to_string()))?,
            peer_public_key: rt_proto::keys::parse_public_key(peer_public_key)
                .map_err(|error| TunnelError::InvalidKey(error.to_string()))?,
            preshared_key: match preshared_key {
                Some(value) => Some(
                    rt_proto::keys::parse_private_key(value)
                        .map_err(|error| TunnelError::InvalidKey(error.to_string()))?,
                ),
                None => None,
            },
            persistent_keepalive,
            index,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TunnelEvent {
    Network(Vec<u8>),
    Ip(Vec<u8>),
    Error(String),
    None,
}

pub struct WgTunnel {
    tunn: Tunn,
    index: u32,
    buffer: Vec<u8>,
}

impl WgTunnel {
    pub fn new(config: TunnelConfig) -> Self {
        let private = StaticSecret::from(config.private_key);
        let peer = PublicKey::from(config.peer_public_key);
        let tunn = Tunn::new(
            private,
            peer,
            config.preshared_key,
            config.persistent_keepalive,
            config.index,
            None,
        );
        Self {
            tunn,
            index: config.index,
            buffer: vec![0u8; 65_535],
        }
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn initiate(&mut self) -> TunnelEvent {
        let result = self.tunn.encapsulate(&[], &mut self.buffer);
        into_event(result)
    }

    pub fn force_handshake(&mut self) -> TunnelEvent {
        let result = self
            .tunn
            .format_handshake_initiation(&mut self.buffer, true);
        into_event(result)
    }

    pub fn encrypt(&mut self, packet: &[u8]) -> TunnelEvent {
        let result = self.tunn.encapsulate(packet, &mut self.buffer);
        into_event(result)
    }

    pub fn decrypt(&mut self, src: Option<IpAddr>, datagram: &[u8]) -> Vec<TunnelEvent> {
        let mut events = Vec::new();
        let mut result = self.tunn.decapsulate(src, datagram, &mut self.buffer);
        for _ in 0..64 {
            let event = into_event(result);
            let network = matches!(event, TunnelEvent::Network(_));
            if !matches!(event, TunnelEvent::None) {
                events.push(event);
            }
            if !network {
                break;
            }
            result = self.tunn.decapsulate(None, &[], &mut self.buffer);
        }
        events
    }

    pub fn tick(&mut self) -> Vec<TunnelEvent> {
        let mut events = Vec::new();
        let mut result = self.tunn.update_timers(&mut self.buffer);
        for _ in 0..16 {
            let event = into_event(result);
            let network = matches!(event, TunnelEvent::Network(_));
            if !matches!(event, TunnelEvent::None) {
                events.push(event);
            }
            if !network {
                break;
            }
            result = self.tunn.update_timers(&mut self.buffer);
        }
        events
    }

    pub fn stats(&self) -> TunnelStats {
        let (last_handshake, tx_bytes, rx_bytes, loss, rtt) = self.tunn.stats();
        TunnelStats {
            last_handshake,
            tx_bytes,
            rx_bytes,
            loss,
            rtt: rtt.map(|value| Duration::from_millis(u64::from(value))),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.tunn.is_expired()
    }
}

fn into_event(result: TunnResult<'_>) -> TunnelEvent {
    match result {
        TunnResult::Done => TunnelEvent::None,
        TunnResult::Err(error) => TunnelEvent::Error(classify(&error)),
        TunnResult::WriteToNetwork(packet) => TunnelEvent::Network(packet.to_vec()),
        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
            TunnelEvent::Ip(packet.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair_with_psk(psk: Option<[u8; 32]>) -> (WgTunnel, WgTunnel) {
        let a_private = [7u8; 32];
        let b_private = [9u8; 32];
        let a_public = *PublicKey::from(&StaticSecret::from(a_private)).as_bytes();
        let b_public = *PublicKey::from(&StaticSecret::from(b_private)).as_bytes();
        let a = WgTunnel::new(TunnelConfig {
            private_key: a_private,
            peer_public_key: b_public,
            preshared_key: psk,
            persistent_keepalive: None,
            index: 1,
        });
        let b = WgTunnel::new(TunnelConfig {
            private_key: b_private,
            peer_public_key: a_public,
            preshared_key: psk,
            persistent_keepalive: None,
            index: 2,
        });
        (a, b)
    }

    fn ipv4_packet(payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 66, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..].copy_from_slice(payload);
        packet
    }

    fn ipv6_packet(payload: &[u8]) -> Vec<u8> {
        let total = 40 + payload.len();
        let mut packet = vec![0u8; total];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0xfd, 0x66, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[24..40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[40..].copy_from_slice(payload);
        packet
    }

    fn exchange_handshake(a: &mut WgTunnel, b: &mut WgTunnel) {
        let TunnelEvent::Network(init) = a.initiate() else {
            panic!("initiator did not produce a handshake");
        };
        let events = b.decrypt(None, &init);
        let response = events
            .into_iter()
            .find_map(|event| match event {
                TunnelEvent::Network(packet) => Some(packet),
                _ => None,
            })
            .expect("responder did not produce a response");
        let events = a.decrypt(None, &response);
        assert!(events
            .iter()
            .all(|event| !matches!(event, TunnelEvent::Error(_))));
    }

    #[test]
    fn handshake_and_transport_both_directions() {
        let (mut a, mut b) = pair_with_psk(None);
        exchange_handshake(&mut a, &mut b);
        let packet = ipv4_packet(b"hello rtun");
        let TunnelEvent::Network(encrypted) = a.encrypt(&packet) else {
            panic!("no encrypted packet");
        };
        let events = b.decrypt(None, &encrypted);
        let plain = events
            .into_iter()
            .find_map(|event| match event {
                TunnelEvent::Ip(packet) => Some(packet),
                _ => None,
            })
            .expect("no inner packet");
        assert_eq!(plain, packet);
        let reply = ipv6_packet(b"reply");
        let TunnelEvent::Network(encrypted) = b.encrypt(&reply) else {
            panic!("no encrypted reply");
        };
        let events = a.decrypt(None, &encrypted);
        let plain = events
            .into_iter()
            .find_map(|event| match event {
                TunnelEvent::Ip(packet) => Some(packet),
                _ => None,
            })
            .expect("no inner reply");
        assert_eq!(plain, reply);
        let stats = a.stats();
        assert!(stats.last_handshake.is_some());
        assert!(stats.tx_bytes > 0);
    }

    #[test]
    fn psk_mismatch_does_not_establish_session() {
        let (mut a, _) = pair_with_psk(None);
        let (_, mut b) = pair_with_psk(Some([5u8; 32]));
        let TunnelEvent::Network(init) = a.initiate() else {
            panic!("no handshake");
        };
        let response = b
            .decrypt(None, &init)
            .into_iter()
            .find_map(|event| match event {
                TunnelEvent::Network(packet) => Some(packet),
                _ => None,
            })
            .expect("responder sends a response before PSK verification");
        let _ = a.decrypt(None, &response);
        assert!(a.stats().last_handshake.is_none());
    }

    #[test]
    fn garbage_input_is_rejected_without_panic() {
        let (mut a, _) = pair_with_psk(None);
        let events = a.decrypt(None, &[0xffu8; 148]);
        assert!(events
            .iter()
            .any(|event| matches!(event, TunnelEvent::Error(_))));
        let events = a.decrypt(None, &[0u8; 3]);
        assert!(events
            .iter()
            .any(|event| matches!(event, TunnelEvent::Error(_))));
    }

    #[test]
    fn tunnel_config_parses_base64_keys() {
        let private = rt_proto::keys::generate_private_key();
        let public = rt_proto::keys::public_key_from_private(&private).unwrap();
        let config = TunnelConfig::from_base64(&private, &public, None, Some(25), 7).unwrap();
        assert_eq!(config.index, 7);
        assert_eq!(config.persistent_keepalive, Some(25));
    }
}
