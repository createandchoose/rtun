use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use http::Request;
use rand::RngCore;
use rt_proto::{decode_batch, encode_batch, EndpointConfig, TransportKind, MAX_WS_DATAGRAMS};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::client_async_with_config;
use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};

use crate::error::{Result, TransportError};
use crate::resolve::EndpointResolver;
use crate::Transport;

pub const WS_SUBPROTOCOL: &str = "rtun.v1";
const READ_CHANNEL: usize = 256;
const WRITE_CHANNEL: usize = 256;

#[derive(Debug, Clone)]
pub struct WsConfig {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub server_name: String,
    pub alpn: Vec<String>,
    pub connect_timeout: Duration,
    pub ping_interval: Duration,
    pub mtu: u16,
}

impl WsConfig {
    pub fn from_endpoint(endpoint: &EndpointConfig, mtu: u16) -> Self {
        Self {
            host: endpoint.host.clone(),
            port: endpoint.port,
            path: endpoint.ws_path.clone(),
            server_name: endpoint.tls_server_name().to_string(),
            alpn: vec![endpoint.alpn.clone()],
            connect_timeout: Duration::from_secs(5),
            ping_interval: Duration::from_secs(20),
            mtu,
        }
    }
}

pub fn tls_client_config(alpns: &[&str]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpns.iter().map(|alpn| alpn.as_bytes().to_vec()).collect();
    Arc::new(config)
}

pub struct WsTlsTransport {
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    writer: Mutex<Option<JoinHandle<()>>>,
    reader: Mutex<Option<JoinHandle<()>>>,
    peer: Option<SocketAddr>,
    mtu: u16,
}

impl WsTlsTransport {
    pub async fn connect(config: WsConfig, resolver: &EndpointResolver) -> Result<Self> {
        if config.alpn.iter().any(|alpn| alpn == "h2") {
            return Err(TransportError::Config(
                "ws-tls transport requires ALPN http/1.1".into(),
            ));
        }
        let addresses = resolver.resolve(&config.host, config.port).await?;
        let stream = connect_tcp(&addresses, config.connect_timeout).await?;
        let peer = stream.peer_addr().ok();
        let server_name = match config.server_name.parse::<std::net::IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(config.server_name.clone()).map_err(|error| {
                TransportError::Config(format!("invalid TLS server name: {error}"))
            })?,
        };
        let alpn_refs = config.alpn.iter().map(String::as_str).collect::<Vec<_>>();
        let tls = tls_client_config(&alpn_refs);
        let connector = TlsConnector::from(tls);
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|error| TransportError::Tls(format!("TLS handshake failed: {error}")))?;

        let authority = if config.port == 443 {
            config.host.clone()
        } else {
            format!("{}:{}", config.host, config.port)
        };
        let uri = format!("wss://{authority}{}", config.path);
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let websocket_key = STANDARD.encode(nonce);
        let request = Request::builder()
            .uri(&uri)
            .header("Host", &authority)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", websocket_key)
            .header("Sec-WebSocket-Protocol", WS_SUBPROTOCOL)
            .header("User-Agent", "Mozilla/5.0")
            .body(())
            .map_err(|error| TransportError::Config(format!("invalid websocket URI: {error}")))?;

        let ws_config = WebSocketConfig {
            max_message_size: Some(1024 * 1024),
            max_frame_size: Some(1024 * 1024),
            ..WebSocketConfig::default()
        };
        let (stream, response) = client_async_with_config(request, tls_stream, Some(ws_config))
            .await
            .map_err(|error| {
                TransportError::WebSocket(format!("websocket handshake failed: {error}"))
            })?;
        let selected = response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|value| value.to_str().ok());
        if selected != Some(WS_SUBPROTOCOL) {
            return Err(TransportError::WebSocket(
                "server did not negotiate rtun.v1 subprotocol".into(),
            ));
        }

        let (mut write, mut read) = stream.split();
        let (tx, mut outbound) = mpsc::channel::<Vec<u8>>(WRITE_CHANNEL);
        let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>(READ_CHANNEL);
        let ping_interval = config.ping_interval;

        let writer = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(ping_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    message = outbound.recv() => {
                        let Some(first) = message else {
                            let _ = write.send(Message::Close(None)).await;
                            break;
                        };
                        let mut batch = vec![first];
                        while batch.len() < MAX_WS_DATAGRAMS {
                            match outbound.try_recv() {
                                Ok(datagram) => batch.push(datagram),
                                Err(_) => break,
                            }
                        }
                        let frame = match encode_batch(batch.iter().map(Vec::as_slice)) {
                            Ok(frame) => frame,
                            Err(_) => break,
                        };
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

        let reader = tokio::spawn(async move {
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
                            if incoming_tx.send(datagram.to_vec()).await.is_err() {
                                return;
                            }
                        }
                    }
                    Message::Close(_) => break,
                    Message::Ping(_) | Message::Pong(_) | Message::Text(_) => {}
                    Message::Frame(_) => {}
                }
            }
        });

        Ok(Self {
            tx,
            rx: Mutex::new(incoming_rx),
            writer: Mutex::new(Some(writer)),
            reader: Mutex::new(Some(reader)),
            peer,
            mtu: config.mtu,
        })
    }
}

async fn connect_tcp(addresses: &[SocketAddr], timeout: Duration) -> Result<TcpStream> {
    let mut last_error = None;
    for (index, address) in addresses.iter().enumerate() {
        let attempt_timeout = if index + 1 == addresses.len() {
            timeout
        } else {
            Duration::from_millis(250).min(timeout)
        };
        match tokio::time::timeout(attempt_timeout, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(_) => last_error = Some("connect timeout".to_string()),
        }
    }
    Err(TransportError::Resolve(format!(
        "cannot connect to websocket endpoint: {}",
        last_error.unwrap_or_else(|| "no addresses".into())
    )))
}

#[async_trait]
impl Transport for WsTlsTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::WsTls
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    async fn send(&self, datagram: &[u8]) -> Result<()> {
        self.tx
            .send(datagram.to_vec())
            .await
            .map_err(|_| TransportError::Closed)
    }

    async fn recv(&self) -> Result<Vec<u8>> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(TransportError::Closed)
    }

    async fn close(&self) {
        if let Some(task) = self.writer.lock().await.take() {
            task.abort();
        }
        if let Some(task) = self.reader.lock().await.take() {
            task.abort();
        }
    }
}
