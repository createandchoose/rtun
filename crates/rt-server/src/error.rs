use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tunnel error: {0}")]
    Tunnel(#[from] rt_tunnel::TunnelError),
    #[error("routing error: {0}")]
    Routing(#[from] rt_routing::RoutingError),
    #[error("websocket error: {0}")]
    WebSocket(String),
}

pub type Result<T> = std::result::Result<T, ServerError>;
