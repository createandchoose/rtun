use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("transport error: {0}")]
    Transport(#[from] rt_transport::TransportError),
    #[error("tunnel error: {0}")]
    Tunnel(#[from] rt_tunnel::TunnelError),
    #[error("routing error: {0}")]
    Routing(#[from] rt_routing::RoutingError),
    #[error("DNS error: {0}")]
    Dns(#[from] rt_dns::DnsError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("handshake failed on all transports")]
    HandshakeFailed,
    #[error("session is stopped")]
    Stopped,
}

pub type Result<T> = std::result::Result<T, ClientError>;
