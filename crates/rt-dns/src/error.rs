use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("DNS I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid DNS message: {0}")]
    Message(String),
    #[error("no upstream DNS server available")]
    NoUpstream,
    #[error("upstream DNS query timed out")]
    Timeout,
    #[error("invalid DNS configuration: {0}")]
    Config(String),
    #[error("systemd-resolved management failed: {0}")]
    Resolved(String),
    #[error("state serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("routing command failed: {0}")]
    Executor(#[from] rt_routing::RoutingError),
    #[error("command {program} failed: {stderr}")]
    Command { program: String, stderr: String },
}

pub type Result<T> = std::result::Result<T, DnsError>;
