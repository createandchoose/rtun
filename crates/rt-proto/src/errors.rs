use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid configuration: {0}")]
    Invalid(String),
    #[error("failed to parse configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("failed to serialize configuration: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("invalid key: {0}")]
    Key(#[from] KeyError),
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("key is not valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("key must decode to 32 bytes, got {0}")]
    Length(usize),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ObfsError {
    #[error("datagram is too short")]
    TooShort,
    #[error("unknown obfuscation magic")]
    UnknownMagic,
    #[error("invalid padding length")]
    BadPadding,
    #[error("payload is not a WireGuard message")]
    BadWireGuard,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WsFrameError {
    #[error("batch contains too many datagrams")]
    TooManyDatagrams,
    #[error("datagram is empty or too large")]
    BadLength,
    #[error("truncated frame")]
    Truncated,
    #[error("trailing bytes after frame")]
    TrailingBytes,
}
