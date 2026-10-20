use thiserror::Error;

#[derive(Debug, Error)]
pub enum RoutingError {
    #[error("command {program} failed: {stderr}")]
    Command {
        program: String,
        args: Vec<String>,
        stderr: String,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid routing configuration: {0}")]
    Config(String),
    #[error("GeoIP error: {0}")]
    GeoIp(String),
    #[error("state serialization error: {0}")]
    State(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, RoutingError>;
