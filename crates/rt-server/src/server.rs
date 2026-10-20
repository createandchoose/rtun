use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rt_proto::{decode_batch, encode_batch, ObfsCodec, PeerConfig, ServerConfig};
use rt_routing::{RuleManager, ServerPlan};
use rt_tunnel::{open_tun, TunnelConfig, TunnelEvent, WgTunnel};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::error::ServerError;
use crate::peers::{destination_ip, load_peers, source_ip};

const WS_SUBPROTOCOL: &str = "rtun.v1";
const HANDSHAKE_RATE: u32 = 50;

#[derive(Debug, Clone)]
pub struct ServerPaths {
    pub state_file: PathBuf,
    pub run_dir: PathBuf,
}

impl Default for ServerPaths {
    fn default() -> Self {
        Self {
            state_file: PathBuf::from("/run/rtun/server-state.json"),
            run_dir: PathBuf::from("/run/rtun"),
        }
    }
}

#[derive(Clone)]
enum Reply {
    Udp {
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        codec: ObfsCodec,
    },
    Ws {
        tx: mpsc::Sender<Vec<u8>>,
    },
}

impl Reply {
    async fn send(&self, packet: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Udp {
                socket,
                peer,
                codec,
            } => {
                let encoded = codec
                    .encode(packet, &mut rand::rngs::OsRng)
                    .map_err(|error| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
                    })?;
                socket.send_to(&encoded, *peer).await?;
                Ok(())
            }
            Self::Ws { tx } => tx.send(packet.to_vec()).await.map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "websocket closed")
            }),
        }
    }
}

struct PeerNode {
    config: PeerConfig,
    tunnel: WgTunnel,
    reply: Option<Reply>,
}

enum Inbound {
    Wg {
        data: Vec<u8>,
        src: Option<IpAddr>,
        reply: Reply,
    },
}

struct Server {
    config: ServerConfig,
    peers: Vec<PeerNode>,
    next_index: u32,
    manager: Arc<RuleManager>,
    tun_name: String,
}

pub async fn run(
    config: ServerConfig,
    paths: ServerPaths,
    mut shutdown: watch::Receiver<bool>,
    mut reload: mpsc::Receiver<()>,
) -> Result<(), ServerError> {
    config
        .validate()
        .map_err(|error| ServerError::Config(error.to_string()))?;
    let manager = Arc::new(RuleManager::new(
        Arc::new(rt_routing::ProcessExecutor),
        paths.state_file.clone(),
        paths.run_dir.clone(),
    ));
    manager.recover().await?;
    let peer_configs =
        load_peers(std::path::Path::new(&config.peers_dir)).map_err(ServerError::Config)?;
    if peer_configs.is_empty() {
        warn!("no peers configured");
    }
    let mut peers = Vec::new();
    let mut next_index = 1u32;
    for peer in peer_configs {
        peers.push(PeerNode {
            tunnel: build_tunnel(&config, &peer, next_index)?,
            config: peer,
            reply: None,
        });
        next_index += 1;
    }

    let mut server = Server {
        tun_name: config.tun_name.clone(),
        config,
        peers,
        next_index,
        manager,
    };
    let v4 = format!("{}/{}", server.config.address_v4, server.config.prefix_v4);
    let v6 = format!("{}/{}", server.config.address_v6, server.config.prefix_v6);
    let plan = ServerPlan {
        tun_name: server.tun_name.clone(),
        mtu: server.config.mtu,
        v4: v4
            .parse::<ipnet::Ipv4Net>()
            .map_err(|error| ServerError::Config(format!("{error}")))?
            .trunc(),
        v6: v6
            .parse::<ipnet::Ipv6Net>()
            .map_err(|error| ServerError::Config(format!("{error}")))?
            .trunc(),
        v4_address: server.config.address_v4,
        v6_address: server.config.address_v6,
        udp_port: server.config.listen_port,
        handshake_rate: HANDSHAKE_RATE,
    };
    if let Err(error) = server.manager.apply_server_sysctls().await {
        let _ = server.manager.cleanup_server().await;
        return Err(error.into());
    }
    let device = open_tun(&server.tun_name, server.config.mtu)?;
    if let Err(error) = server.manager.apply_server(&plan).await {
        let _ = server.manager.cleanup_server().await;
        return Err(error.into());
    }
    let (mut tun_rx, mut tun_tx) = tokio::io::split(device);

    let codec = ObfsCodec::new(&server.config.obfs)
        .map_err(|error| ServerError::Config(error.to_string()))?;
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Inbound>(1024);
    let mut udp_sockets = Vec::new();
    for address in server.config.obfs_listen.clone() {
        let socket = Arc::new(bind_udp(address)?);
        udp_sockets.push(socket.clone());
        spawn_udp_listener(socket, codec.clone(), inbound_tx.clone());
    }
    let ws_listener = TcpListener::bind(server.config.ws_listen)
        .await
        .map_err(|error| ServerError::Config(format!("cannot bind websocket backend: {error}")))?;
    spawn_ws_listener(ws_listener, inbound_tx.clone());

    info!(
        tun = %server.tun_name,
        udp = ?udp_sockets.iter().filter_map(|socket| socket.local_addr().ok()).collect::<Vec<_>>(),
        ws = %server.config.ws_listen,
        peers = server.peers.len(),
        "rtund started"
    );

    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut buffer = vec![0u8; 65_535];

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = reload.recv() => {
                server.reload().await;
            }
            result = tun_rx.read(&mut buffer) => {
                let len = result?;
                if len == 0 {
                    continue;
                }
                server.handle_outbound(&buffer[..len]).await;
            }
            inbound = inbound_rx.recv() => {
                if let Some(Inbound::Wg { data, src, reply }) = inbound {
                    server.handle_inbound(&data, src, reply, &mut tun_tx).await;
                }
            }
            _ = ticker.tick() => {
                for index in 0..server.peers.len() {
                    let events = server.peers[index].tunnel.tick();
                    for event in events {
                        if let TunnelEvent::Network(packet) = event {
                            if let Some(reply) = server.peers[index].reply.clone() {
                                if let Err(error) = reply.send(&packet).await {
                                    debug!(%error, peer = %server.peers[index].config.name, "send failed");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    drop(tun_tx);
    drop(tun_rx);
    let _ = server.manager.cleanup_server().await;
    info!("rtund stopped");
    Ok(())
}

impl Server {
    async fn handle_inbound(
        &mut self,
        data: &[u8],
        src: Option<IpAddr>,
        reply: Reply,
        tun_tx: &mut (impl AsyncWriteExt + Unpin),
    ) {
        let mut matched: Option<(usize, Vec<TunnelEvent>)> = None;
        for (index, peer) in self.peers.iter_mut().enumerate() {
            let events = peer.tunnel.decrypt(src, data);
            if events
                .iter()
                .any(|event| matches!(event, TunnelEvent::Ip(_) | TunnelEvent::Network(_)))
            {
                matched = Some((index, events));
                break;
            }
        }
        let Some((index, events)) = matched else {
            return;
        };
        self.peers[index].reply = Some(reply.clone());
        for event in events {
            match event {
                TunnelEvent::Network(packet) => {
                    if let Err(error) = reply.send(&packet).await {
                        debug!(%error, "reply send failed");
                    }
                }
                TunnelEvent::Ip(packet) => {
                    let Some(source) = source_ip(&packet) else {
                        debug!("dropping inner packet without a source address");
                        continue;
                    };
                    let peer = &self.peers[index];
                    if source != IpAddr::V4(peer.config.address_v4)
                        && source != IpAddr::V6(peer.config.address_v6)
                    {
                        warn!(%source, peer = %peer.config.name, "dropping spoofed inner packet");
                        continue;
                    }
                    if let Err(error) = tun_tx.write_all(&packet).await {
                        warn!(%error, "cannot write packet to TUN");
                    }
                }
                TunnelEvent::Error(error) => debug!(%error, "peer decrypt error"),
                TunnelEvent::None => {}
            }
        }
    }

    async fn handle_outbound(&mut self, packet: &[u8]) {
        let Some(destination) = destination_ip(packet) else {
            return;
        };
        let Some(peer) = self.peers.iter_mut().find(|peer| {
            destination == IpAddr::V4(peer.config.address_v4)
                || destination == IpAddr::V6(peer.config.address_v6)
        }) else {
            return;
        };
        let Some(reply) = peer.reply.clone() else {
            return;
        };
        let event = peer.tunnel.encrypt(packet);
        if let TunnelEvent::Network(packet) = event {
            if let Err(error) = reply.send(&packet).await {
                debug!(%error, "outbound send failed");
            }
        }
    }

    async fn reload(&mut self) {
        let path = std::path::Path::new(&self.config.peers_dir);
        let configs = match load_peers(path) {
            Ok(configs) => configs,
            Err(error) => {
                warn!(%error, "peer reload failed");
                return;
            }
        };
        let mut existing: HashMap<String, PeerNode> = self
            .peers
            .drain(..)
            .map(|peer| (peer.config.public_key.clone(), peer))
            .collect();
        let mut peers = Vec::new();
        for config in configs {
            if let Some(mut peer) = existing.remove(&config.public_key) {
                peer.config = config;
                peers.push(peer);
            } else {
                match build_tunnel(&self.config, &config, self.next_index) {
                    Ok(tunnel) => {
                        self.next_index += 1;
                        peers.push(PeerNode {
                            tunnel,
                            config,
                            reply: None,
                        });
                    }
                    Err(error) => warn!(%error, name = %config.name, "cannot add peer"),
                }
            }
        }
        info!(peers = peers.len(), "peers reloaded");
        self.peers = peers;
    }
}

fn build_tunnel(
    config: &ServerConfig,
    peer: &PeerConfig,
    index: u32,
) -> Result<WgTunnel, ServerError> {
    let tunnel_config = TunnelConfig::from_base64(
        &config.private_key,
        &peer.public_key,
        peer.preshared_key.as_deref(),
        Some(25),
        index,
    )
    .map_err(ServerError::Tunnel)?;
    Ok(WgTunnel::new(tunnel_config))
}

fn bind_udp(address: SocketAddr) -> Result<UdpSocket, ServerError> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
    socket.bind(&address.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_socket)?)
}

fn spawn_udp_listener(socket: Arc<UdpSocket>, codec: ObfsCodec, inbound: mpsc::Sender<Inbound>) {
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buffer).await else {
                continue;
            };
            let Ok(decoded) = codec.decode(&buffer[..len]) else {
                continue;
            };
            let reply = Reply::Udp {
                socket: socket.clone(),
                peer,
                codec: codec.clone(),
            };
            if inbound
                .send(Inbound::Wg {
                    data: decoded.wireguard.to_vec(),
                    src: Some(peer.ip()),
                    reply,
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });
}

fn spawn_ws_listener(listener: TcpListener, inbound: mpsc::Sender<Inbound>) {
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                continue;
            };
            let inbound = inbound.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_ws(stream, peer, inbound).await {
                    debug!(%error, "websocket connection closed");
                }
            });
        }
    });
}

#[allow(clippy::result_large_err)]
async fn handle_ws(
    stream: TcpStream,
    peer: SocketAddr,
    inbound: mpsc::Sender<Inbound>,
) -> Result<(), ServerError> {
    let _ = stream.set_nodelay(true);
    let config = WebSocketConfig::default();
    let ws = tokio_tungstenite::accept_hdr_async_with_config(
        stream,
        move |request: &Request, mut response: Response| {
            let offered = request
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.split(',').any(|item| item.trim() == WS_SUBPROTOCOL))
                .unwrap_or(false);
            if !offered {
                return Err(ErrorResponse::new(Some(
                    "rtun.v1 subprotocol required".to_string(),
                )));
            }
            response.headers_mut().insert(
                "sec-websocket-protocol",
                HeaderValue::from_static(WS_SUBPROTOCOL),
            );
            Ok(response)
        },
        Some(config),
    )
    .await
    .map_err(|error| ServerError::WebSocket(error.to_string()))?;

    let (mut write, mut read) = ws.split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    let writer = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(20));
        loop {
            tokio::select! {
                message = rx.recv() => {
                    let Some(first) = message else { break; };
                    let mut batch = vec![first];
                    while batch.len() < 32 {
                        match rx.try_recv() {
                            Ok(packet) => batch.push(packet),
                            Err(_) => break,
                        }
                    }
                    let Ok(frame) = encode_batch(batch.iter().map(Vec::as_slice)) else { break; };
                    if write.send(Message::Binary(frame)).await.is_err() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if write.send(Message::Ping(Vec::new())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    while let Some(message) = read.next().await {
        let Ok(message) = message else {
            break;
        };
        match message {
            Message::Binary(frame) => {
                let Ok(datagrams) = decode_batch(&frame) else {
                    break;
                };
                for datagram in datagrams {
                    if inbound
                        .send(Inbound::Wg {
                            data: datagram.to_vec(),
                            src: Some(peer.ip()),
                            reply: Reply::Ws { tx: tx.clone() },
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) | Message::Text(_) => {}
            Message::Frame(_) => {}
        }
    }
    drop(tx);
    writer.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rt_proto::obfs::{build_wireguard_packet, WgKind};

    fn packet_v4(src: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
        packet
    }

    #[test]
    fn obfs_wireguard_handshake_and_data_reach_server_tunnel() {
        let server_private = rt_proto::keys::generate_private_key();
        let server_public = rt_proto::keys::public_key_from_private(&server_private).unwrap();
        let client_private = rt_proto::keys::generate_private_key();
        let client_public = rt_proto::keys::public_key_from_private(&client_private).unwrap();
        let config = ServerConfig {
            private_key: server_private,
            ..ServerConfig::default()
        };
        let peer = PeerConfig {
            name: "client".into(),
            public_key: client_public,
            preshared_key: None,
            address_v4: "10.66.0.2".parse().unwrap(),
            address_v6: "fd66:1::2".parse().unwrap(),
            enabled: true,
        };
        let mut server_tunnel = build_tunnel(&config, &peer, 1).unwrap();
        let mut client_tunnel = WgTunnel::new(
            TunnelConfig::from_base64(&client_private, &server_public, None, Some(25), 2).unwrap(),
        );
        let codec = ObfsCodec::new(&config.obfs).unwrap();
        let mut rng = rand::thread_rng();

        let TunnelEvent::Network(init) = client_tunnel.force_handshake() else {
            panic!("client did not create a handshake");
        };
        let wire = codec.encode(&init, &mut rng).unwrap();
        let decoded = codec.decode(&wire).unwrap();
        assert_eq!(decoded.kind, WgKind::HandshakeInitiation);
        let response = server_tunnel
            .decrypt(None, decoded.wireguard)
            .into_iter()
            .find_map(|event| match event {
                TunnelEvent::Network(packet) => Some(packet),
                _ => None,
            })
            .expect("server response");
        let wire = codec.encode(&response, &mut rng).unwrap();
        let decoded = codec.decode(&wire).unwrap();
        let events = client_tunnel.decrypt(None, decoded.wireguard);
        for event in events {
            if let TunnelEvent::Network(packet) = event {
                let _ = packet;
            }
        }
        assert!(client_tunnel.stats().last_handshake.is_some());

        let inner = packet_v4([10, 66, 0, 2]);
        let TunnelEvent::Network(encrypted) = client_tunnel.encrypt(&inner) else {
            panic!("no data packet");
        };
        let wire = codec.encode(&encrypted, &mut rng).unwrap();
        let decoded = codec.decode(&wire).unwrap();
        let events = server_tunnel.decrypt(Some("10.200.1.2".parse().unwrap()), decoded.wireguard);
        let plain = events
            .into_iter()
            .find_map(|event| match event {
                TunnelEvent::Ip(packet) => Some(packet),
                _ => None,
            })
            .expect("inner packet");
        assert_eq!(source_ip(&plain), Some("10.66.0.2".parse().unwrap()));
        assert_eq!(destination_ip(&plain), Some("8.8.8.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn udp_reply_is_obfuscated() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let params = rt_proto::ObfsParams::generate();
        let codec = ObfsCodec::new(&params).unwrap();
        let reply = Reply::Udp {
            socket: sender,
            peer: receiver.local_addr().unwrap(),
            codec: codec.clone(),
        };
        let packet = build_wireguard_packet(WgKind::HandshakeResponse, 92);
        reply.send(&packet).await.unwrap();
        let mut buffer = vec![0u8; 2048];
        let (len, _) = receiver.recv_from(&mut buffer).await.unwrap();
        let decoded = codec.decode(&buffer[..len]).unwrap();
        assert_eq!(decoded.kind, WgKind::HandshakeResponse);
        assert_eq!(decoded.wireguard, packet.as_slice());
    }

    #[test]
    fn invalid_magic_is_rejected_before_wireguard() {
        let params = rt_proto::ObfsParams::generate();
        let codec = ObfsCodec::new(&params).unwrap();
        let packet = build_wireguard_packet(WgKind::TransportData, 32);
        assert!(codec.decode(&packet).is_err());
    }
}
