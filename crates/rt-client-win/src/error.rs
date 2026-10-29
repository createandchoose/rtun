use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientWinError {
    #[error("configuration: {0}")]
    Config(String),
    #[error("transport: {0}")]
    Transport(#[from] rt_transport::TransportError),
    #[error("tunnel: {0}")]
    Tunnel(#[from] rt_tunnel::TunnelError),
    #[error("routing: {0}")]
    Routing(#[from] rt_routing::error::RoutingError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("handshake failed: {0}")]
    Handshake(String),
    #[error("no physical default route found; cannot route the tunnel")]
    NoPhysicalRoute,
}
