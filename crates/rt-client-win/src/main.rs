//! CLI клиента RTUN для Windows.
//!
//! `plan` ничего не меняет в системе и не требует прав администратора.
//! `up` требует запуска от администратора (wintun, netsh).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use rt_client_win::plan::{build_plan, dns_args, load_config, metric_args};
use rt_client_win::{run, ClientWinError};
use rt_proto::ClientConfig;
use rt_routing::geoip::GeoIpData;
use rt_routing::manager::{CommandExecutor, ProcessExecutor};
use rt_routing::win;
use rt_transport::EndpointResolver;
use tokio::sync::watch;
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(name = "rtun-win", version, about = "RTUN client for Windows")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Подключиться и держать туннель, пока не нажат Ctrl+C. Нужны права администратора.
    Up {
        #[arg(long)]
        config: PathBuf,
        /// Остановиться через столько секунд (для проверки). Откат выполняется штатно.
        #[arg(long)]
        r#for: Option<u64>,
    },
    /// Показать маршруты и команды netsh без изменения системы.
    Plan {
        #[arg(long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Up { config, r#for } => up(&config, r#for).await,
        Command::Plan { config } => plan(&config).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn up(path: &Path, duration: Option<u64>) -> Result<(), ClientWinError> {
    let config = load_config(path)?;
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(async move {
        match duration {
            Some(seconds) => {
                tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
                info!("duration reached");
            }
            None => {
                if tokio::signal::ctrl_c().await.is_err() {
                    return;
                }
                info!("stop requested");
            }
        }
        let _ = stop_tx.send(true);
    });
    let executor: Arc<dyn CommandExecutor> = Arc::new(ProcessExecutor);
    let (status_tx, mut status_rx) = tokio::sync::watch::channel(rt_client_win::TunnelState::Idle);
    tokio::spawn(async move {
        while status_rx.changed().await.is_ok() {
            info!(state = ?*status_rx.borrow(), "tunnel state");
        }
    });
    run(config, executor, stop_rx, status_tx).await?;
    info!("stopped; routes removed");
    Ok(())
}

/// Печатает план без изменений в системе. Адреса эндпоинта резолвятся,
/// физический маршрут читается через PowerShell.
async fn plan(path: &Path) -> Result<(), ClientWinError> {
    let config: ClientConfig = load_config(path)?;
    let executor = ProcessExecutor;
    let endpoints: Vec<SocketAddr> = EndpointResolver::new(true)
        .resolve(&config.endpoint.host, config.endpoint.port)
        .await?;
    let Some(physical) = win::detect_physical(&executor).await else {
        warn!("no physical default route found");
        return Err(ClientWinError::NoPhysicalRoute);
    };
    let plan = build_plan(&config, &endpoints, &GeoIpData::default())?;
    println!(
        "physical: interface {} gateway {:?}",
        physical.index, physical.gateway
    );
    println!("endpoints: {endpoints:?}");
    for route in win::route_plan(&plan, &physical) {
        println!("netsh {}", win::route_args("add", &route).join(" "));
    }
    println!("netsh {}", dns_args(config.dns.server_v4.into()).join(" "));
    println!("netsh {}", dns_args(config.dns.server_v6.into()).join(" "));
    println!("netsh {}", metric_args().join(" "));
    Ok(())
}
