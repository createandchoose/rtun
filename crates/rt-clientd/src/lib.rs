pub mod dbus;
pub mod engine;
pub mod error;
pub mod status;

pub use engine::{SessionHandle, SessionPaths};
pub use error::{ClientError, Result};
pub use status::{ClientState, SharedStatus, Status};

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

pub fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

pub async fn run_foreground(
    config: rt_proto::ClientConfig,
    paths: SessionPaths,
    status: SharedStatus,
) -> Result<()> {
    let handle = SessionHandle::spawn(config, paths, status);
    wait_for_signal().await?;
    handle.stop().await;
    Ok(())
}

pub async fn wait_for_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

pub fn load_status_file(path: &Path) -> Option<Status> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

pub async fn write_status_file(path: &Path, status: &SharedStatus) -> std::io::Result<()> {
    let snapshot = status.read().await.to_json();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, snapshot)
}

pub fn status_writer(
    path: std::path::PathBuf,
    status: SharedStatus,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(error) = write_status_file(&path, &status).await {
                tracing::debug!(%error, "cannot write status file");
            }
            tokio::time::sleep(interval).await;
        }
    })
}

pub fn new_status() -> SharedStatus {
    Arc::new(RwLock::new(Status::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn status_writer_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/status.json");
        let status = new_status();
        let handle = status_writer(path.clone(), status, Duration::from_millis(10));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(path.exists(), "status file was not created");
        handle.abort();
    }
}
