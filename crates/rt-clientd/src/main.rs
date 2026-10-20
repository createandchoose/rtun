use std::path::PathBuf;

use clap::Parser;
use rt_clientd::engine::SessionPaths;
use rt_clientd::{dbus, init_tracing, new_status, run_foreground, status_writer};
use rt_proto::ClientConfig;

#[derive(Debug, Parser)]
#[command(name = "rt-clientd", version, about = "RTUN privileged client daemon")]
struct Args {
    #[arg(long, default_value = "/etc/rtun/client.toml")]
    config: PathBuf,
    #[arg(long)]
    headless: bool,
    #[arg(long)]
    check_config: bool,
    #[arg(long, default_value = "/run/rtun/status.json")]
    status_file: PathBuf,
    #[arg(long, default_value = "/run/rtun")]
    run_dir: PathBuf,
    #[arg(long)]
    auto_connect: bool,
    #[arg(long)]
    no_dns: bool,
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn paths(run_dir: PathBuf) -> SessionPaths {
    SessionPaths {
        state_file: run_dir.join("client-state.json"),
        run_dir,
        geoip_dir: PathBuf::from("/var/lib/rtun"),
        resolved_dropin: PathBuf::from("/etc/systemd/resolved.conf.d/rtun.conf"),
        resolved_marker: PathBuf::from("/run/rtun/resolved-marker.json"),
        enable_dns: true,
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let config = match ClientConfig::load(&args.config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("cannot load {}: {error}", args.config.display());
            return std::process::ExitCode::FAILURE;
        }
    };
    let level = if args.log_level == "info" {
        config.log_level.clone()
    } else {
        args.log_level.clone()
    };
    init_tracing(&level);
    if args.check_config {
        println!("configuration is valid");
        println!(
            "endpoint: {}:{}",
            config.endpoint.host, config.endpoint.port
        );
        println!("priority: {:?}", config.transports.priority);
        return std::process::ExitCode::SUCCESS;
    }

    let status = new_status();
    let _writer = status_writer(
        args.status_file.clone(),
        status.clone(),
        std::time::Duration::from_secs(1),
    );

    let mut session_paths = paths(args.run_dir);
    session_paths.enable_dns = !args.no_dns;

    if args.headless {
        if let Err(error) = run_foreground(config, session_paths, status).await {
            eprintln!("rt-clientd failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
        return std::process::ExitCode::SUCCESS;
    }

    let connection = match dbus::serve(
        status,
        config,
        args.config.clone(),
        session_paths,
        args.auto_connect,
    )
    .await
    {
        Ok((connection, service)) => {
            let result = wait_for_shutdown().await;
            service.stop().await.ok();
            let _ = connection;
            result
        }
        Err(error) => {
            eprintln!("cannot register D-Bus service: {error}");
            eprintln!("run with --headless if the system bus is unavailable");
            return std::process::ExitCode::FAILURE;
        }
    };
    if let Err(error) = connection {
        eprintln!("signal handling failed: {error}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

async fn wait_for_shutdown() -> std::io::Result<()> {
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
