//! Менеджер RTUN: профили VPS, деплой, экспорт/импорт WG-подобных конфигов.
//! Контракт: docs/deploy-design.md.

mod profiles;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rt_deploy::pipeline::{self, validate_plan, DeployPlan};
use rt_deploy::{RusshRemote, SshAuth, VpsTarget};
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
    /// Установка сервера на VPS по SSH-профилю и выдача клиентского конфига.
    Deploy {
        name: String,
        #[arg(long)]
        domain: String,
        /// Email для Let's Encrypt. Необязателен: без него сертификат
        /// выпускается без адреса, уведомления о продлении не придут.
        #[arg(long)]
        email: Option<String>,
        #[arg(long, default_value = "laptop")]
        peer: String,
        #[arg(long, default_value_t = 2)]
        index: u8,
        /// Корень репозитория с target/release и packaging/.
        #[arg(long, default_value = ".")]
        repo_root: PathBuf,
        /// Куда записать клиентский .conf. По умолчанию rtun-<peer>.conf.
        #[arg(long)]
        out: Option<PathBuf>,
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

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Vps { action } => vps(action),
        Command::Deploy {
            name,
            domain,
            email,
            peer,
            index,
            repo_root,
            out,
        } => {
            deploy(DeployArgs {
                name: &name,
                domain,
                email,
                peer,
                index,
                repo_root,
                out,
            })
            .await
        }
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

struct DeployArgs<'a> {
    name: &'a str,
    domain: String,
    email: Option<String>,
    peer: String,
    index: u8,
    repo_root: PathBuf,
    out: Option<PathBuf>,
}

async fn deploy(args: DeployArgs<'_>) -> Result<(), String> {
    let profiles = Profiles::load(&profiles_path()?)?;
    let vps = profiles
        .find(args.name)
        .ok_or_else(|| format!("no profile named {}", args.name))?;
    let key_path = vps.key_path.clone().ok_or_else(|| {
        format!(
            "profile {} has no SSH key; add one with `vps add --key <path>`",
            vps.name
        )
    })?;
    let target = VpsTarget {
        host: vps.host.clone(),
        port: vps.port,
        user: vps.user.clone(),
    };

    let plan = DeployPlan {
        repo_root: args.repo_root,
        domain: args.domain,
        email: args.email.unwrap_or_default(),
        peer_name: args.peer.clone(),
        peer_index: args.index,
    };
    validate_plan(&plan).map_err(|error| error.to_string())?;

    let auth = SshAuth::KeyFile(key_path);
    let mut remote = RusshRemote::connect(&target, &auth)
        .await
        .map_err(|error| error.to_string())?;
    let mut progress = |step: pipeline::Step| println!("==> {}", step.label());
    let result = pipeline::deploy(&plan, &mut remote, &mut progress).await;
    // Закрываем соединение в любом случае, ошибку закрытия не показываем.
    let _ = remote.close().await;
    let result = result.map_err(|error| error.to_string())?;

    let out = args
        .out
        .unwrap_or_else(|| PathBuf::from(format!("rtun-{}.conf", args.peer)));
    result
        .client_conf
        .save(&out)
        .map_err(|error| error.to_string())?;
    println!(
        "client config for {} written to {}",
        result.peer_name,
        out.display()
    );
    Ok(())
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
