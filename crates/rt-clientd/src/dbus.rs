use std::path::PathBuf;
use std::sync::Arc;

use rt_proto::{ClientConfig, TransportKind};
use tokio::sync::Mutex;
use zbus::fdo;
use zbus::message::Header;
use zbus::names::BusName;
use zbus::Connection;

use crate::engine::{SessionHandle, SessionPaths};
use crate::status::{SharedStatus, Status};

#[derive(Clone)]
pub struct ClientService {
    status: SharedStatus,
    config: Arc<Mutex<ClientConfig>>,
    config_path: PathBuf,
    paths: SessionPaths,
    session: Arc<Mutex<Option<SessionHandle>>>,
}

impl ClientService {
    pub fn new(
        status: SharedStatus,
        config: ClientConfig,
        config_path: PathBuf,
        paths: SessionPaths,
    ) -> Self {
        Self {
            status,
            config: Arc::new(Mutex::new(config)),
            config_path,
            paths,
            session: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn start(&self) -> fdo::Result<()> {
        let config = self.config.lock().await.clone();
        config
            .validate()
            .map_err(|error| fdo::Error::Failed(error.to_string()))?;
        let mut session = self.session.lock().await;
        if let Some(previous) = session.take() {
            previous.stop().await;
        }
        *session = Some(SessionHandle::spawn(
            config,
            self.paths.clone(),
            self.status.clone(),
        ));
        Ok(())
    }

    pub async fn stop(&self) -> fdo::Result<()> {
        if let Some(session) = self.session.lock().await.take() {
            session.stop().await;
        }
        let mut status = self.status.write().await;
        status.state = crate::status::ClientState::Disconnected;
        Ok(())
    }

    async fn restart(&self) -> fdo::Result<()> {
        self.start().await
    }
}

async fn authorize(connection: &Connection, header: &Header<'_>) -> fdo::Result<()> {
    let sender = header
        .sender()
        .ok_or_else(|| fdo::Error::AccessDenied("missing sender".into()))?;
    let proxy = fdo::DBusProxy::new(connection).await?;
    let uid = proxy
        .get_connection_unix_user(
            BusName::try_from(sender.as_str()).map_err(|error| {
                fdo::Error::AccessDenied(format!("invalid sender name: {error}"))
            })?,
        )
        .await
        .map_err(|error| fdo::Error::AccessDenied(format!("cannot read caller uid: {error}")))?;
    if uid == 0 {
        return Ok(());
    }
    let pid = proxy
        .get_connection_unix_process_id(
            BusName::try_from(sender.as_str()).map_err(|error| {
                fdo::Error::AccessDenied(format!("invalid sender name: {error}"))
            })?,
        )
        .await
        .map_err(|error| fdo::Error::AccessDenied(format!("cannot read caller pid: {error}")))?;
    let status = tokio::process::Command::new("pkcheck")
        .args([
            "--action-id",
            "org.rtun.client.control",
            "--process",
            &pid.to_string(),
            "--allow-user-interaction",
        ])
        .status()
        .await
        .map_err(|error| fdo::Error::AccessDenied(format!("polkit unavailable: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(fdo::Error::AccessDenied(
            "polkit did not authorize the request".into(),
        ))
    }
}

#[zbus::interface(name = "org.rtun.Client1")]
impl ClientService {
    #[zbus(name = "Connect")]
    async fn connect(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<()> {
        authorize(connection, &header).await?;
        self.start().await
    }

    #[zbus(name = "Disconnect")]
    async fn disconnect(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<()> {
        authorize(connection, &header).await?;
        self.stop().await
    }

    #[zbus(name = "Status")]
    async fn status(&self) -> String {
        self.status.read().await.to_json()
    }

    #[zbus(name = "GetDiagnostics")]
    async fn get_diagnostics(&self) -> String {
        let status = self.status.read().await.clone();
        let config = self.config.lock().await;
        let diagnostics = serde_json::json!({
            "status": status,
            "endpoint": config.endpoint.host,
            "port": config.endpoint.port,
            "priority": config.transports.priority,
            "obfs_mtu": config.device.mtu_obfs,
            "ws_mtu": config.device.mtu_ws,
            "direct_suffixes": config.routing.direct_suffixes,
            "kill_switch": config.kill_switch,
            "dns_mode": if config.dns.degraded { "degraded" } else { "split" },
        });
        diagnostics.to_string()
    }

    #[zbus(name = "SetTransport")]
    async fn set_transport(
        &self,
        kind: String,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<()> {
        authorize(connection, &header).await?;
        let kind = match kind.as_str() {
            "obfs-udp" => TransportKind::ObfsUdp,
            "ws-tls" => TransportKind::WsTls,
            other => {
                return Err(fdo::Error::InvalidArgs(format!(
                    "unknown transport {other}"
                )))
            }
        };
        {
            let mut config = self.config.lock().await;
            config.transports.priority.retain(|value| *value != kind);
            config.transports.priority.insert(0, kind);
        }
        self.restart().await
    }

    #[zbus(name = "SetKillSwitch")]
    async fn set_kill_switch(
        &self,
        enabled: bool,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<()> {
        authorize(connection, &header).await?;
        {
            let mut config = self.config.lock().await;
            config.kill_switch = enabled;
        }
        if self.session.lock().await.is_some() {
            self.restart().await?;
        }
        Ok(())
    }

    #[zbus(name = "ImportConfig")]
    async fn import_config(
        &self,
        toml: String,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<String> {
        authorize(connection, &header).await?;
        let config = ClientConfig::from_toml(&toml)
            .map_err(|error| fdo::Error::InvalidArgs(error.to_string()))?;
        rt_proto::config::write_secure(&self.config_path, config.to_toml().unwrap().as_bytes())
            .map_err(|error| fdo::Error::Failed(error.to_string()))?;
        *self.config.lock().await = config;
        Ok("imported".into())
    }
}

pub async fn serve(
    status: SharedStatus,
    config: ClientConfig,
    config_path: PathBuf,
    paths: SessionPaths,
    auto_connect: bool,
) -> zbus::Result<(Connection, ClientService)> {
    let connection = Connection::system().await?;
    let service = ClientService::new(status, config, config_path, paths);
    connection
        .object_server()
        .at("/org/rtun/Client1", service.clone())
        .await?;
    connection.request_name("org.rtun.Client1").await?;
    if auto_connect {
        if let Err(error) = service.start().await {
            tracing::warn!(%error, "automatic connect failed");
        }
    }
    Ok((connection, service))
}

pub fn status_snapshot(status: &Status) -> String {
    status.to_json()
}
