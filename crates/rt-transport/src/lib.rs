pub mod health;
pub mod resolve;
pub mod udp;
pub mod ws;

pub use health::{FailoverController, FailoverDecision, HealthConfig, NetworkKey};
pub use resolve::{resolve_endpoint, DohResolver, EndpointResolver};
pub use udp::ObfsUdpTransport;
pub use ws::{WsConfig, WsTlsTransport};

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use rt_proto::TransportKind;

pub use error::{Result, TransportError};

pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum TransportError {
        #[error("transport I/O error: {0}")]
        Io(#[from] std::io::Error),
        #[error("transport is closed")]
        Closed,
        #[error("transport timed out")]
        Timeout,
        #[error("obfuscation error: {0}")]
        Obfs(#[from] rt_proto::ObfsError),
        #[error("websocket frame error: {0}")]
        Frame(#[from] rt_proto::WsFrameError),
        #[error("TLS error: {0}")]
        Tls(String),
        #[error("websocket error: {0}")]
        WebSocket(String),
        #[error("endpoint resolution failed: {0}")]
        Resolve(String),
        #[error("invalid transport configuration: {0}")]
        Config(String),
    }

    pub type Result<T> = std::result::Result<T, TransportError>;
}

#[async_trait]
pub trait Transport: Send + Sync {
    fn kind(&self) -> TransportKind;
    fn mtu(&self) -> u16;
    fn peer(&self) -> Option<SocketAddr>;
    async fn send(&self, datagram: &[u8]) -> Result<()>;
    async fn recv(&self) -> Result<Vec<u8>>;
    async fn close(&self);
}

pub async fn recv_with_timeout(transport: &dyn Transport, timeout: Duration) -> Result<Vec<u8>> {
    match tokio::time::timeout(timeout, transport.recv()).await {
        Ok(result) => result,
        Err(_) => Err(TransportError::Timeout),
    }
}
