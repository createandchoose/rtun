//! Менеджер RTUN: профили VPS, деплой, экспорт/импорт WG-подобных конфигов.
//! Контракт: docs/deploy-design.md.

mod profiles;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rt_deploy::pipeline::{validate_plan, DeployPlan};
use rt_proto::wgconf::WgConf;
use rt_proto::ClientConfig;

use profiles::{profiles_path, valid_host, valid_name, Profiles, Vps};

#[derive(Debug, Parser)]
#[command(name = "rtun-manager", version, about = "Менеджер RTUN")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Профили VPS.
    Vps {
        #[command(subcommand)]
        action: VpsAction,
    },
    /// Установка сервера на VPS по профилю (SSH-транспорт пока не реализован).
    Deploy {
        name: String,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        email: String,
        #[arg(long, default_value = "laptop")]
        peer: String,
        #[arg(long, default_value_t = 2)]
        index: u8,
        /// Корень репозитория с target/release и packaging/.
        #[arg(long, default_value = ".")]
        repo_root: PathBuf,
    },
    /// Конвертация конфигов между client.toml и WireGuard-подобным .conf.
    Conf {
        #[command(subcommand)]
        action: ConfAction,
    },
}

#[derive(Debug, Subcommand)]
enum VpsAction {
    Add {
        name: String,
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "root")]
        user: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// Путь к приватному ключу SSH. Пароль не сохраняется.
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        email: Option<String>,
    },
    List,
    Remove {
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum ConfAction {
    /// client.toml -> .conf
    ToWg {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// .conf -> client.toml
    FromWg {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Vps { action } => vps(action),
        Command::Deploy {
            name,
            domain,
            email,
            peer,
            index,
            repo_root,
        } => deploy(&name, domain, email, peer, index, repo_root),
        Command::Conf { action } => conf(action),
    }
}

fn vps(action: VpsAction) -> Result<(), String> {
    let path = profiles_path()?;
    let mut profiles = Profiles::load(&path)?;
    match action {
        VpsAction::Add {
            name,
            host,
            user,
            port,
            key,
            domain,
            email,
        } => {
            if !valid_name(&name) {
                return Err(format!("invalid profile name: {name}"));
            }
            if !valid_host(&host) {
                return Err(format!("invalid host: {host}"));
            }
            profiles.add(Vps {
                name: name.clone(),
                host,
                port,
                user,
                key_path: key,
                domain,
                email,
            })?;
            profiles.save(&path)?;
            println!("profile {name} saved to {}", path.display());
        }
        VpsAction::List => {
            if profiles.vps.is_empty() {
                println!("no profiles");
            }
            for vps in &profiles.vps {
                println!("{}\t{}@{}:{}", vps.name, vps.user, vps.host, vps.port);
            }
        }
        VpsAction::Remove { name } => {
            profiles.remove(&name)?;
            profiles.save(&path)?;
            println!("profile {name} removed");
        }
    }
    Ok(())
}

fn deploy(
    name: &str,
    domain: String,
    email: String,
    peer: String,
    index: u8,
    repo_root: PathBuf,
) -> Result<(), String> {
    let profiles = Profiles::load(&profiles_path()?)?;
    let vps = profiles
        .find(name)
        .ok_or_else(|| format!("no profile named {name}"))?;
    let plan = DeployPlan {
        repo_root,
        domain,
        email,
        peer_name: peer,
        peer_index: index,
    };
    validate_plan(&plan).map_err(|error| error.to_string())?;
    Err(format!(
        "deploy to {}@{} is not available yet: the SSH transport is not built. \
         Input is valid; see docs/deploy-design.md",
        vps.user, vps.host
    ))
}

fn conf(action: ConfAction) -> Result<(), String> {
    match action {
        ConfAction::ToWg { input, output } => {
            let client = ClientConfig::load(&input).map_err(|error| error.to_string())?;
            WgConf::from_client(&client)
                .save(&output)
                .map_err(|error| error.to_string())?;
            println!("written {}", output.display());
        }
        ConfAction::FromWg { input, output } => {
            let client = WgConf::load(&input)
                .map_err(|error| error.to_string())?
                .into_client()
                .map_err(|error| error.to_string())?;
            client.save(&output).map_err(|error| error.to_string())?;
            println!("written {}", output.display());
        }
    }
    Ok(())
}
