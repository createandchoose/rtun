use std::path::PathBuf;

use clap::Parser;
use rt_proto::ServerConfig;
use rt_server::{run, ServerPaths};
use tokio::sync::{mpsc, watch};

#[derive(Debug, Parser)]
#[command(name = "rtund", version, about = "RTUN server daemon")]
struct Args {
    #[arg(long, default_value = "/etc/rtun/server.toml")]
    config: PathBuf,
    #[arg(long)]
    check_config: bool,
    #[arg(long, default_value = "/run/rtun")]
    run_dir: PathBuf,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let config = match ServerConfig::load(&args.config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("cannot load {}: {error}", args.config.display());
            return std::process::ExitCode::FAILURE;
        }
    };
    init_tracing(&config.log_level);
    if args.check_config {
        println!("configuration is valid");
        println!("tun: {}", config.tun_name);
        println!("udp: {:?}", config.obfs_listen);
        println!("ws backend: {}", config.ws_listen);
        return std::process::ExitCode::SUCCESS;
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (_reload_tx, reload_rx) = mpsc::channel(4);
    let paths = ServerPaths {
        state_file: args.run_dir.join("server-state.json"),
        run_dir: args.run_dir,
    };
    let mut handle = tokio::spawn(async move { run(config, paths, shutdown_rx, reload_rx).await });

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
        let mut hup = signal(SignalKind::hangup()).expect("SIGHUP handler");
        loop {
            tokio::select! {
                result = &mut handle => return task_exit(result),
                _ = term.recv() => break,
                _ = int.recv() => break,
                _ = hup.recv() => {
                    let _ = _reload_tx.send(()).await;
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            result = &mut handle => return task_exit(result),
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    let _ = shutdown_tx.send(true);
    task_exit(handle.await)
}

fn task_exit(
    result: Result<rt_server::Result<()>, tokio::task::JoinError>,
) -> std::process::ExitCode {
    match result {
        Ok(Ok(())) => std::process::ExitCode::SUCCESS,
        Ok(Err(error)) => {
            eprintln!("rtund failed: {error}");
            std::process::ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("rtund task failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
