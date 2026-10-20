use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::config::ObfsParams;
use crate::errors::ObfsError;

pub const HEADER_LEN: usize = 5;
pub const MAX_PADDING: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WgKind {
    HandshakeInitiation,
    HandshakeResponse,
    CookieReply,
    TransportData,
}

impl WgKind {
    pub fn header_index(self) -> usize {
        match self {
            Self::HandshakeInitiation => 0,
            Self::HandshakeResponse => 1,
            Self::CookieReply => 2,
            Self::TransportData => 3,
        }
    }

    pub fn wireguard_type(self) -> u32 {
        match self {
            Self::HandshakeInitiation => 1,
            Self::HandshakeResponse => 2,
            Self::CookieReply => 3,
            Self::TransportData => 4,
        }
    }

    pub fn minimum_len(self) -> usize {
        match self {
            Self::HandshakeInitiation => 148,
            Self::HandshakeResponse => 92,
            Self::CookieReply => 64,
            Self::TransportData => 32,
        }
    }

    pub fn from_packet(packet: &[u8]) -> Option<Self> {
        if packet.len() < 8 {
            return None;
        }
        let kind = match u32::from_le_bytes(packet[0..4].try_into().ok()?) {
            1 => Self::HandshakeInitiation,
            2 => Self::HandshakeResponse,
            3 => Self::CookieReply,
            4 => Self::TransportData,
            _ => return None,
        };
        if packet.len() < kind.minimum_len() {
            return None;
        }
        Some(kind)
    }
}

pub fn looks_like_wireguard(packet: &[u8]) -> bool {
    WgKind::from_packet(packet).is_some()
}

#[derive(Debug, PartialEq, Eq)]
pub struct ObfsPacket<'a> {
    pub kind: WgKind,
    pub wireguard: &'a [u8],
    pub padding: usize,
}

#[derive(Debug, Clone)]
pub struct ObfsCodec {
    headers: [u32; 4],
    padding_max: u8,
    junk_count: u16,
    junk_min: u16,
    junk_max: u16,
    junk_delay_min_ms: u16,
    junk_delay_max_ms: u16,
}

impl ObfsCodec {
    pub fn new(params: &ObfsParams) -> Result<Self, ObfsError> {
        if params.padding_max as usize > MAX_PADDING
            || params.junk_min > params.junk_max
            || params.junk_min < 32
            || params.junk_delay_min_ms > params.junk_delay_max_ms
        {
            return Err(ObfsError::BadPadding);
        }
        let headers = [params.h1, params.h2, params.h3, params.h4];
        if headers.contains(&0) {
            return Err(ObfsError::UnknownMagic);
        }
        for (index, header) in headers.iter().enumerate() {
            if headers[..index].contains(header) {
                return Err(ObfsError::UnknownMagic);
            }
        }
        Ok(Self {
            headers,
            padding_max: params.padding_max,
            junk_count: params.junk_count,
            junk_min: params.junk_min,
            junk_max: params.junk_max,
            junk_delay_min_ms: params.junk_delay_min_ms,
            junk_delay_max_ms: params.junk_delay_max_ms,
        })
    }

    pub fn header(&self, kind: WgKind) -> u32 {
        self.headers[kind.header_index()]
    }

    pub fn padding_max(&self) -> u8 {
        self.padding_max
    }

    pub fn junk_count(&self) -> u16 {
        self.junk_count
    }

    pub fn junk_delay(&self, rng: &mut impl Rng) -> std::time::Duration {
        std::time::Duration::from_millis(
            rng.gen_range(self.junk_delay_min_ms..=self.junk_delay_max_ms) as u64,
        )
    }

    pub fn encode(&self, packet: &[u8], rng: &mut impl Rng) -> Result<Vec<u8>, ObfsError> {
        let mut output = Vec::with_capacity(HEADER_LEN + packet.len() + self.padding_max as usize);
        self.encode_into(packet, &mut output, rng)?;
        Ok(output)
    }

    pub fn encode_into(
        &self,
        packet: &[u8],
        output: &mut Vec<u8>,
        rng: &mut impl Rng,
    ) -> Result<(), ObfsError> {
        let kind = WgKind::from_packet(packet).ok_or(ObfsError::BadWireGuard)?;
        let padding = if self.padding_max == 0 {
            0
        } else {
            rng.gen_range(0..=self.padding_max) as usize
        };
        output.clear();
        output.reserve(HEADER_LEN + packet.len() + padding);
        output.extend_from_slice(&self.header(kind).to_be_bytes());
        output.push(padding as u8);
        output.extend_from_slice(packet);
        let start = output.len();
        output.resize(start + padding, 0);
        rng.fill(&mut output[start..]);
        Ok(())
    }

    pub fn decode<'a>(&self, datagram: &'a [u8]) -> Result<ObfsPacket<'a>, ObfsError> {
        if datagram.len() < HEADER_LEN + 8 {
            return Err(ObfsError::TooShort);
        }
        let magic = u32::from_be_bytes(datagram[0..4].try_into().expect("four bytes"));
        if !self.headers.contains(&magic) {
            return Err(ObfsError::UnknownMagic);
        }
        let padding = datagram[4] as usize;
        if padding > self.padding_max as usize {
            return Err(ObfsError::BadPadding);
        }
        let wireguard_len = datagram
            .len()
            .checked_sub(HEADER_LEN + padding)
            .ok_or(ObfsError::BadPadding)?;
        let wireguard = &datagram[HEADER_LEN..HEADER_LEN + wireguard_len];
        let kind = WgKind::from_packet(wireguard).ok_or(ObfsError::BadWireGuard)?;
        Ok(ObfsPacket {
            kind,
            wireguard,
            padding,
        })
    }

    pub fn junk(&self, rng: &mut impl Rng) -> Vec<u8> {
        let len = rng.gen_range(self.junk_min..=self.junk_max) as usize;
        let mut packet = vec![0u8; len];
        rng.fill(&mut packet[..]);
        packet
    }

    pub fn junk_packets(&self, rng: &mut impl Rng) -> Vec<Vec<u8>> {
        (0..self.junk_count).map(|_| self.junk(rng)).collect()
    }
}

pub fn build_wireguard_packet(kind: WgKind, len: usize) -> Vec<u8> {
    let len = len.max(kind.minimum_len());
    let mut packet = vec![0u8; len];
    packet[0..4].copy_from_slice(&kind.wireguard_type().to_le_bytes());
    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn codec() -> ObfsCodec {
        ObfsCodec::new(&ObfsParams::default()).unwrap()
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn roundtrip_all_message_types() {
        let codec = codec();
        let mut rng = rng();
        for kind in [
            WgKind::HandshakeInitiation,
            WgKind::HandshakeResponse,
            WgKind::CookieReply,
            WgKind::TransportData,
        ] {
            let packet = build_wireguard_packet(kind, kind.minimum_len() + 13);
            let encoded = codec.encode(&packet, &mut rng).unwrap();
            let decoded = codec.decode(&encoded).unwrap();
            assert_eq!(decoded.kind, kind);
            assert_eq!(decoded.wireguard, packet.as_slice());
            assert!(decoded.padding <= 8);
            assert!(encoded.len() <= packet.len() + 13);
        }
    }

    #[test]
    fn reject_plain_wireguard() {
        let codec = codec();
        let packet = build_wireguard_packet(WgKind::HandshakeInitiation, 148);
        assert!(looks_like_wireguard(&packet));
        assert_eq!(codec.decode(&packet).unwrap_err(), ObfsError::UnknownMagic);
    }

    #[test]
    fn unknown_magic_is_silent_error() {
        let codec = codec();
        let mut datagram = codec
            .encode(
                &build_wireguard_packet(WgKind::TransportData, 32),
                &mut rng(),
            )
            .unwrap();
        datagram[0] ^= 0xff;
        assert_eq!(
            codec.decode(&datagram).unwrap_err(),
            ObfsError::UnknownMagic
        );
    }

    #[test]
    fn invalid_padding_rejected() {
        let codec = codec();
        let packet = build_wireguard_packet(WgKind::TransportData, 32);
        let mut encoded = codec.encode(&packet, &mut rng()).unwrap();
        encoded[4] = 0x40;
        assert_eq!(codec.decode(&encoded).unwrap_err(), ObfsError::BadPadding);
    }

    #[test]
    fn wireguard_signature_is_not_present_on_wire() {
        let codec = codec();
        let packet = build_wireguard_packet(WgKind::HandshakeInitiation, 148);
        let encoded = codec.encode(&packet, &mut rng()).unwrap();
        assert!(!looks_like_wireguard(&encoded));
        assert_ne!(encoded[0..4], packet[0..4]);
    }

    #[test]
    fn junk_sizes_and_count() {
        let codec = codec();
        let mut rng = rng();
        let junk = codec.junk_packets(&mut rng);
        assert_eq!(junk.len(), 4);
        for packet in junk {
            assert!((80..=300).contains(&packet.len()));
            assert!(!looks_like_wireguard(&packet));
        }
        let delay = codec.junk_delay(&mut rng);
        assert!((5..=15).contains(&delay.as_millis()));
    }

    #[test]
    fn invalid_params_rejected() {
        let params = ObfsParams {
            padding_max: 200,
            ..ObfsParams::default()
        };
        assert!(ObfsCodec::new(&params).is_err());
        let params = ObfsParams::default();
        let params = ObfsParams {
            h3: params.h1,
            ..params
        };
        assert!(ObfsCodec::new(&params).is_err());
    }
}
