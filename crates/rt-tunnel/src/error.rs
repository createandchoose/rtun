use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("invalid tunnel configuration: {0}")]
    Config(String),
    #[error("tunnel I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("wireguard error: {0}")]
    WireGuard(String),
}

pub fn classify(error: &boringtun::noise::errors::WireGuardError) -> String {
    match error {
        boringtun::noise::errors::WireGuardError::ConnectionExpired => {
            "connection-expired".to_string()
        }
        boringtun::noise::errors::WireGuardError::InvalidPacket => "invalid-packet".to_string(),
        other => format!("{other:?}"),
    }
}
