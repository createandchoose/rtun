use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rt_proto::TransportKind;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientState {
    Disconnected,
    Resolving,
    Handshaking,
    Connected,
    Degraded,
    Reconnecting,
}

impl ClientState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Resolving => "resolving",
            Self::Handshaking => "handshaking",
            Self::Connected => "connected",
            Self::Degraded => "degraded",
            Self::Reconnecting => "reconnecting",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub state: ClientState,
    pub transport: Option<TransportKind>,
    pub endpoint: Option<String>,
    pub rtt_ms: Option<f64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_error: Option<String>,
    pub kill_switch: bool,
    pub dns_degraded: bool,
    pub dns_active: bool,
    pub network: Option<String>,
    pub connected_at: Option<u64>,
    pub updated_at: u64,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            state: ClientState::Disconnected,
            transport: None,
            endpoint: None,
            rtt_ms: None,
            tx_bytes: 0,
            rx_bytes: 0,
            last_error: None,
            kill_switch: true,
            dns_degraded: false,
            dns_active: false,
            network: None,
            connected_at: None,
            updated_at: now_secs(),
        }
    }
}

impl Status {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }
}

pub type SharedStatus = Arc<RwLock<Status>>;

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub async fn set_state(status: &SharedStatus, state: ClientState) {
    let mut status = status.write().await;
    if state == ClientState::Connected && status.connected_at.is_none() {
        status.connected_at = Some(now_secs());
    }
    if state != ClientState::Connected && state != ClientState::Reconnecting {
        status.connected_at = None;
    }
    status.state = state;
    status.updated_at = now_secs();
}

pub async fn set_error(status: &SharedStatus, error: impl Into<String>) {
    let mut status = status.write().await;
    status.last_error = Some(error.into());
    status.updated_at = now_secs();
}

pub async fn set_transport(
    status: &SharedStatus,
    transport: Option<TransportKind>,
    endpoint: Option<String>,
) {
    let mut status = status.write().await;
    status.transport = transport;
    status.endpoint = endpoint;
    status.updated_at = now_secs();
}

pub async fn update_metrics(
    status: &SharedStatus,
    tx_bytes: usize,
    rx_bytes: usize,
    rtt_ms: Option<f64>,
) {
    let mut status = status.write().await;
    status.tx_bytes = tx_bytes as u64;
    status.rx_bytes = rx_bytes as u64;
    status.rtt_ms = rtt_ms;
    status.updated_at = now_secs();
}

pub async fn set_dns(status: &SharedStatus, active: bool, degraded: bool) {
    let mut status = status.write().await;
    status.dns_active = active;
    status.dns_degraded = degraded;
    status.updated_at = now_secs();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_serializes_kebab_case() {
        let status = Status::default();
        let json = status.to_json();
        assert!(json.contains("\"state\": \"disconnected\""));
        assert!(json.contains("\"kill_switch\": true"));
    }

    #[tokio::test]
    async fn connected_sets_timestamp() {
        let status = Arc::new(RwLock::new(Status::default()));
        set_state(&status, ClientState::Connected).await;
        assert!(status.read().await.connected_at.is_some());
        set_state(&status, ClientState::Disconnected).await;
        assert!(status.read().await.connected_at.is_none());
    }
}
