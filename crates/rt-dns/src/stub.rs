use std::path::{Path, PathBuf};
use std::sync::Arc;

use rt_routing::{CommandExecutor, CommandOutput};
use serde::{Deserialize, Serialize};

use crate::error::{DnsError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakeoverMode {
    StubOff,
    Degraded5533,
}

impl TakeoverMode {
    pub fn port(self) -> u16 {
        match self {
            Self::StubOff => 53,
            Self::Degraded5533 => 5533,
        }
    }

    pub fn dropin(self) -> &'static str {
        match self {
            Self::StubOff => "[Resolve]\nDNSStubListener=no\nDNS=127.0.0.1\nDomains=~.\n",
            Self::Degraded5533 => {
                "[Resolve]\nDNSStubListener=yes\nDNS=127.0.0.1:5533\nDomains=~.\n"
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StubMarker {
    existed: bool,
    backup: Option<String>,
}

pub struct ResolvedManager {
    executor: Arc<dyn CommandExecutor>,
    dropin: PathBuf,
    marker: PathBuf,
}

impl ResolvedManager {
    pub fn new(
        executor: Arc<dyn CommandExecutor>,
        dropin: impl Into<PathBuf>,
        marker: impl Into<PathBuf>,
    ) -> Self {
        Self {
            executor,
            dropin: dropin.into(),
            marker: marker.into(),
        }
    }

    pub fn system() -> Self {
        Self::new(
            Arc::new(rt_routing::ProcessExecutor),
            "/etc/systemd/resolved.conf.d/rtun.conf",
            "/run/rtun/resolved-marker.json",
        )
    }

    pub async fn is_resolved_active(&self) -> bool {
        match self
            .executor
            .run(
                "systemctl",
                &["is-active".into(), "systemd-resolved".into()],
            )
            .await
        {
            Ok(output) => {
                output.status == 0 && String::from_utf8_lossy(&output.stdout).trim() == "active"
            }
            Err(_) => false,
        }
    }

    pub async fn recover_stale(&self) -> Result<()> {
        if self.marker.exists() {
            self.restore_inner().await?;
        }
        Ok(())
    }

    pub async fn take_over(&self, mode: TakeoverMode) -> Result<()> {
        if self.marker.exists() {
            self.restore_inner().await?;
        }
        let existed = self.dropin.exists();
        let backup_path = self.dropin.with_extension("rtun-backup");
        let backup = if existed {
            let content = std::fs::read(&self.dropin)?;
            write_private(&backup_path, &content)?;
            Some(backup_path.to_string_lossy().to_string())
        } else {
            None
        };
        if let Some(parent) = self.marker.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let marker = StubMarker { existed, backup };
        std::fs::write(&self.marker, serde_json::to_vec_pretty(&marker)?)?;
        if let Some(parent) = self.dropin.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.dropin, mode.dropin())?;
        if let Err(error) = self.restart_resolved().await {
            let _ = self.restore_files(&marker);
            let _ = std::fs::remove_file(&self.marker);
            return Err(error);
        }
        Ok(())
    }

    pub async fn restore(&self) -> Result<()> {
        self.restore_inner().await
    }

    async fn restore_inner(&self) -> Result<()> {
        let Ok(text) = std::fs::read(&self.marker) else {
            return Ok(());
        };
        let marker: StubMarker = serde_json::from_slice(&text)
            .map_err(|error| DnsError::Resolved(format!("invalid resolved marker: {error}")))?;
        self.restore_files(&marker)?;
        let _ = std::fs::remove_file(&self.marker);
        self.restart_resolved().await
    }

    fn restore_files(&self, marker: &StubMarker) -> Result<()> {
        if marker.existed {
            if let Some(backup) = &marker.backup {
                let content = std::fs::read(backup)?;
                std::fs::write(&self.dropin, content)?;
            }
        } else {
            let _ = std::fs::remove_file(&self.dropin);
        }
        if let Some(backup) = &marker.backup {
            let _ = std::fs::remove_file(backup);
        }
        Ok(())
    }

    async fn restart_resolved(&self) -> Result<()> {
        let output = self
            .executor
            .run("systemctl", &["restart".into(), "systemd-resolved".into()])
            .await?;
        if output.status != 0 {
            return Err(DnsError::Command {
                program: "systemctl restart systemd-resolved".into(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        Ok(())
    }
}

fn write_private(path: &Path, content: &[u8]) -> Result<()> {
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn active_output() -> CommandOutput {
    CommandOutput {
        status: 0,
        stdout: b"active\n".to_vec(),
        stderr: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Mock {
        calls: Mutex<Vec<String>>,
        active: bool,
    }

    #[async_trait]
    impl CommandExecutor for Mock {
        async fn run(&self, program: &str, args: &[String]) -> rt_routing::Result<CommandOutput> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            Ok(CommandOutput {
                status: 0,
                stdout: if self.active && args.first().map(String::as_str) == Some("is-active") {
                    b"active\n".to_vec()
                } else {
                    Vec::new()
                },
                stderr: Vec::new(),
            })
        }
    }

    #[tokio::test]
    async fn takeover_restores_existing_dropin() {
        let dir = tempfile::tempdir().unwrap();
        let dropin = dir.path().join("resolved.conf.d/rtun.conf");
        std::fs::create_dir_all(dropin.parent().unwrap()).unwrap();
        std::fs::write(&dropin, "[Resolve]\nDNS=192.168.1.1\n").unwrap();
        let mock = Arc::new(Mock::default());
        let manager =
            ResolvedManager::new(mock.clone(), dropin.clone(), dir.path().join("marker.json"));
        manager.take_over(TakeoverMode::StubOff).await.unwrap();
        let content = std::fs::read_to_string(&dropin).unwrap();
        assert!(content.contains("DNSStubListener=no"));
        assert!(content.contains("DNS=127.0.0.1"));
        assert!(content.contains("Domains=~."));
        manager.restore().await.unwrap();
        assert_eq!(
            std::fs::read_to_string(&dropin).unwrap(),
            "[Resolve]\nDNS=192.168.1.1\n"
        );
        assert!(!dir.path().join("marker.json").exists());
        assert!(mock
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.contains("restart systemd-resolved")));
    }

    #[tokio::test]
    async fn takeover_removes_new_dropin_on_restore() {
        let dir = tempfile::tempdir().unwrap();
        let dropin = dir.path().join("resolved.conf.d/rtun.conf");
        let mock = Arc::new(Mock::default());
        let manager = ResolvedManager::new(mock, dropin.clone(), dir.path().join("marker.json"));
        manager.take_over(TakeoverMode::Degraded5533).await.unwrap();
        assert!(dropin.exists());
        manager.restore().await.unwrap();
        assert!(!dropin.exists());
    }

    #[tokio::test]
    async fn stale_takeover_is_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let dropin = dir.path().join("resolved.conf.d/rtun.conf");
        std::fs::create_dir_all(dropin.parent().unwrap()).unwrap();
        std::fs::write(&dropin, "[Resolve]\nDNS=1.1.1.1\n").unwrap();
        let mock = Arc::new(Mock::default());
        let manager =
            ResolvedManager::new(mock.clone(), dropin.clone(), dir.path().join("marker.json"));
        manager.take_over(TakeoverMode::StubOff).await.unwrap();
        manager.recover_stale().await.unwrap();
        assert!(std::fs::read_to_string(&dropin)
            .unwrap()
            .contains("DNS=1.1.1.1"));
    }
}
