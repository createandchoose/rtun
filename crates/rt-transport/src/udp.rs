use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use rand::rngs::OsRng;
use rt_proto::{ObfsCodec, ObfsParams, TransportKind};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::error::{Result, TransportError};
use crate::{recv_with_timeout, Transport};

pub struct ObfsUdpTransport {
    socket: UdpSocket,
    codec: ObfsCodec,
    peer: SocketAddr,
    mtu: u16,
    junk_sent: AtomicBool,
    recv_timeout: std::time::Duration,
}

impl ObfsUdpTransport {
    pub async fn connect(peer: SocketAddr, params: &ObfsParams, mtu: u16) -> Result<Self> {
        let codec = ObfsCodec::new(params)
            .map_err(|error| TransportError::Config(format!("invalid obfs parameters: {error}")))?;
        let socket = bind_connected(peer)?;
        Ok(Self {
            socket,
            codec,
            peer,
            mtu,
            junk_sent: AtomicBool::new(false),
            recv_timeout: std::time::Duration::from_secs(10),
        })
    }

    pub fn with_recv_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.recv_timeout = timeout;
        self
    }

    async fn send_junk(&self) -> Result<()> {
        let mut rng = OsRng;
        for junk in self.codec.junk_packets(&mut rng) {
            self.socket.send(&junk).await?;
            let delay = self.codec.junk_delay(&mut rng);
            tokio::time::sleep(delay).await;
        }
        Ok(())
    }
}

fn bind_connected(peer: SocketAddr) -> Result<UdpSocket> {
    let domain = if peer.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
    let local: SocketAddr = if peer.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid address")
    } else {
        "[::]:0".parse().expect("valid address")
    };
    socket.bind(&local.into())?;
    socket.connect(&peer.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_socket)?)
}

#[async_trait]
impl Transport for ObfsUdpTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::ObfsUdp
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn peer(&self) -> Option<SocketAddr> {
        Some(self.peer)
    }

    async fn send(&self, datagram: &[u8]) -> Result<()> {
        if !self.junk_sent.swap(true, Ordering::SeqCst) {
            self.send_junk().await?;
        }
        let mut rng = OsRng;
        let encoded = self.codec.encode(datagram, &mut rng)?;
        if encoded.len() > 1500 {
            return Err(TransportError::Config(format!(
                "obfuscated datagram of {} bytes exceeds the wire MTU",
                encoded.len()
            )));
        }
        self.socket.send(&encoded).await?;
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let len = match tokio::time::timeout(self.recv_timeout, self.socket.recv(&mut buffer))
                .await
            {
                Ok(result) => result?,
                Err(_) => return Err(TransportError::Timeout),
            };
            match self.codec.decode(&buffer[..len]) {
                Ok(packet) => return Ok(packet.wireguard.to_vec()),
                Err(_) => continue,
            }
        }
    }

    async fn close(&self) {}
}

pub async fn recv_udp_with_timeout(
    transport: &ObfsUdpTransport,
    timeout: std::time::Duration,
) -> Result<Vec<u8>> {
    recv_with_timeout(transport, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rt_proto::obfs::{build_wireguard_packet, WgKind};

    #[tokio::test]
    async fn sends_obfuscated_datagrams_over_udp() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let params = ObfsParams::generate();
        let codec = ObfsCodec::new(&params).unwrap();
        let client = ObfsUdpTransport::connect(addr, &params, 1360)
            .await
            .unwrap();
        let packet = build_wireguard_packet(WgKind::TransportData, 64);
        client.send(&packet).await.unwrap();
        let mut buffer = vec![0u8; 2048];
        let mut found = false;
        for _ in 0..16 {
            let (len, _) = server.recv_from(&mut buffer).await.unwrap();
            if let Ok(decoded) = codec.decode(&buffer[..len]) {
                assert_eq!(decoded.wireguard, packet.as_slice());
                found = true;
                break;
            }
        }
        assert!(found);
    }

    #[tokio::test]
    async fn rejects_oversized_datagrams() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let params = ObfsParams::generate();
        let client = ObfsUdpTransport::connect(addr, &params, 1280)
            .await
            .unwrap();
        let packet = build_wireguard_packet(WgKind::TransportData, 1500);
        assert!(client.send(&packet).await.is_err());
    }
}
