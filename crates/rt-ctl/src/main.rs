use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;

use clap::{Parser, Subcommand};
use rt_proto::config::write_secure;
use rt_proto::routing::IpRules;
use rt_proto::{ClientConfig, DeviceConfig, EndpointConfig, ObfsParams, PeerConfig, ServerConfig};
use rt_routing::geoip;
use serde_json::json;

#[derive(Debug, Parser)]
#[command(name = "rt-ctl", version, about = "RTUN control utility")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Keygen,
    ServerPublicKey {
        #[arg(long, default_value = "/etc/rtun/server.toml")]
        config: PathBuf,
    },
    GenServer {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "vpn.example.com")]
        endpoint: String,
        #[arg(long, default_value = "/etc/rtun/peers")]
        peers_dir: PathBuf,
    },
    GenClient {
        #[arg(long, default_value = "/etc/rtun/client.toml")]
        out: PathBuf,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        server_public_key: String,
        #[arg(long, default_value = "/etc/rtun/server.toml")]
        server_config: PathBuf,
        #[arg(long, default_value_t = 2)]
        index: u8,
        #[arg(long)]
        psk: Option<String>,
        #[arg(long)]
        private_key: Option<String>,
    },
    AddPeer {
        #[arg(long, default_value = "/etc/rtun/peers")]
        peers_dir: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, default_value_t = 2)]
        index: u8,
        #[arg(long)]
        psk: bool,
        #[arg(long)]
        server_config: Option<PathBuf>,
    },
    Route {
        target: String,
        #[arg(long, default_value = "/etc/rtun/client.toml")]
        config: PathBuf,
        #[arg(long, default_value = "/var/lib/rtun")]
        geoip_dir: PathBuf,
    },
    GeoipUpdate {
        #[arg(long, default_value = "/etc/rtun/client.toml")]
        config: PathBuf,
        #[arg(long, default_value = "/var/lib/rtun")]
        data_dir: PathBuf,
    },
    Status {
        #[arg(long, default_value = "/run/rtun/status.json")]
        file: PathBuf,
    },
    DecoyCheck {
        #[arg(long)]
        url: String,
    },
    UnboundConfig {
        #[arg(long, default_value = "10.66.0.1")]
        v4: String,
        #[arg(long, default_value = "fd66:1::1")]
        v6: String,
    },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = Args::parse();
    match run(args).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rt-ctl: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), String> {
    match args.command {
        Commands::Keygen => {
            let private = rt_proto::keys::generate_private_key();
            let public =
                rt_proto::keys::public_key_from_private(&private).map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "private_key": private,
                    "public_key": public,
                }))
                .expect("json")
            );
        }
        Commands::ServerPublicKey { config } => {
            let server = ServerConfig::load(&config).map_err(|error| error.to_string())?;
            let public = rt_proto::keys::public_key_from_private(&server.private_key)
                .map_err(|error| error.to_string())?;
            println!("{public}");
        }
        Commands::GenServer {
            out,
            endpoint,
            peers_dir,
        } => {
            let private = rt_proto::keys::generate_private_key();
            let public =
                rt_proto::keys::public_key_from_private(&private).map_err(|e| e.to_string())?;
            let config = ServerConfig {
                private_key: private,
                peers_dir: peers_dir.to_string_lossy().to_string(),
                obfs: ObfsParams::generate(),
                ..ServerConfig::default()
            };
            std::fs::create_dir_all(&peers_dir).map_err(|error| error.to_string())?;
            config.save(&out).map_err(|error| error.to_string())?;
            println!("server config written to {}", out.display());
            println!("server public key: {public}");
            println!("endpoint: {endpoint}");
            println!("obfs parameters are stored in {}", out.display());
        }
        Commands::GenClient {
            out,
            endpoint,
            server_public_key,
            server_config,
            index,
            psk,
            private_key,
        } => {
            let server = ServerConfig::load(&server_config).map_err(|error| error.to_string())?;
            let private = private_key.unwrap_or_else(rt_proto::keys::generate_private_key);
            let config = ClientConfig {
                endpoint: EndpointConfig {
                    host: endpoint,
                    ..EndpointConfig::default()
                },
                device: DeviceConfig {
                    private_key: private,
                    peer_public_key: server_public_key,
                    preshared_key: psk,
                    address_v4: format!("10.66.0.{index}").parse().expect("valid address"),
                    address_v6: format!("fd66:1::{index}").parse().expect("valid address"),
                    ..DeviceConfig::default()
                },
                obfs: server.obfs.clone(),
                ..ClientConfig::default()
            };
            config.validate().map_err(|error| error.to_string())?;
            config.save(&out).map_err(|error| error.to_string())?;
            println!("client config written to {}", out.display());
            println!("device IPv4: {}", config.device.address_v4);
            println!("device IPv6: {}", config.device.address_v6);
        }
        Commands::AddPeer {
            peers_dir,
            name,
            index,
            psk,
            server_config,
        } => {
            let private = rt_proto::keys::generate_private_key();
            let public =
                rt_proto::keys::public_key_from_private(&private).map_err(|e| e.to_string())?;
            let psk_value = if psk {
                Some(rt_proto::config::random_psk())
            } else {
                None
            };
            let peer = PeerConfig {
                name: name.clone(),
                public_key: public.clone(),
                preshared_key: psk_value.clone(),
                address_v4: format!("10.66.0.{index}").parse().expect("valid address"),
                address_v6: format!("fd66:1::{index}").parse().expect("valid address"),
                enabled: true,
            };
            peer.validate().map_err(|error| error.to_string())?;
            std::fs::create_dir_all(&peers_dir).map_err(|error| error.to_string())?;
            let path = peers_dir.join(format!("{name}.toml"));
            peer.to_toml()
                .map_err(|error| error.to_string())
                .and_then(|text| {
                    write_secure(&path, text.as_bytes()).map_err(|error| error.to_string())
                })?;
            println!("peer {name} written to {}", path.display());
            println!("client private key: {private}");
            println!(
                "server public key: {}",
                match server_config {
                    Some(path) => {
                        let config = ServerConfig::load(path).map_err(|error| error.to_string())?;
                        rt_proto::keys::public_key_from_private(&config.private_key)
                            .map_err(|error| error.to_string())?
                    }
                    None => "<read from /etc/rtun/server.toml>".to_string(),
                }
            );
            if let Some(psk) = psk_value {
                println!("preshared key: {psk}");
            }
        }
        Commands::Route {
            target,
            config,
            geoip_dir,
        } => {
            let config = ClientConfig::load(&config).map_err(|error| error.to_string())?;
            let suffixes = config
                .routing
                .suffix_set()
                .map_err(|error| error.to_string())?;
            let geo = geoip::load(&geoip_dir).unwrap_or_default();
            let mut endpoints = Vec::new();
            if let Ok(addresses) =
                tokio::net::lookup_host((config.endpoint.host.as_str(), config.endpoint.port)).await
            {
                endpoints.extend(addresses.map(|address| address.ip()));
            }
            let rules = IpRules::new(
                suffixes,
                config
                    .routing
                    .direct_nets()
                    .map_err(|error| error.to_string())?,
                config
                    .routing
                    .override_nets()
                    .map_err(|error| error.to_string())?,
                geo.all().collect(),
                endpoints,
            );
            if let Ok(ip) = target.parse::<IpAddr>() {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rules.route_ip(ip)).expect("json")
                );
            } else {
                let decision = rules.route_domain(&target, config.routing.smart_routing);
                println!("{}", serde_json::to_string_pretty(&decision).expect("json"));
                if let Ok(addresses) = tokio::net::lookup_host((target.as_str(), 443)).await {
                    for address in addresses {
                        let decision = rules.route_ip(address.ip());
                        println!(
                            "{} -> {} ({})",
                            address.ip(),
                            decision.action,
                            decision.reason
                        );
                    }
                }
            }
        }
        Commands::GeoipUpdate { config, data_dir } => {
            let config = ClientConfig::load(&config).map_err(|error| error.to_string())?;
            let v4 = fetch_url(&config.routing.geoip.v4_url)?;
            let v6 = fetch_url(&config.routing.geoip.v6_url)?;
            let mut v4_nets = geoip::parse_zone(&v4).map_err(|error| error.to_string())?;
            let mut v6_nets = geoip::parse_zone(&v6).map_err(|error| error.to_string())?;
            v4_nets.retain(|net| net.addr().is_ipv4());
            v6_nets.retain(|net| net.addr().is_ipv6());
            if v4_nets.len() < 100 || v6_nets.len() < 10 {
                return Err(format!(
                    "GeoIP data looks incomplete: {} IPv4, {} IPv6 prefixes",
                    v4_nets.len(),
                    v6_nets.len()
                ));
            }
            let data = geoip::GeoIpData {
                v4: v4_nets,
                v6: v6_nets,
            };
            geoip::save(&data_dir, &data).map_err(|error| error.to_string())?;
            println!(
                "GeoIP updated: {} IPv4 and {} IPv6 prefixes in {}",
                data.v4.len(),
                data.v6.len(),
                data_dir.display()
            );
        }
        Commands::Status { file } => {
            let text = std::fs::read_to_string(&file)
                .map_err(|error| format!("cannot read {}: {error}", file.display()))?;
            println!("{text}");
        }
        Commands::DecoyCheck { url } => {
            let output = Command::new("curl")
                .args([
                    "-sS",
                    "--max-time",
                    "10",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code} %{time_total}s %{ssl_verify_result}",
                    &url,
                ])
                .output()
                .map_err(|error| format!("cannot run curl: {error}"))?;
            if !output.status.success() {
                return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
            }
            println!("{}", String::from_utf8_lossy(&output.stdout));
        }
        Commands::UnboundConfig { v4, v6 } => {
            print!("{}", rt_server::unbound_config(&v4, &v6));
        }
    }
    Ok(())
}

fn fetch_url(url: &str) -> Result<String, String> {
    let output = Command::new("curl")
        .args(["-fsSL", "--max-time", "60", url])
        .output()
        .map_err(|error| format!("cannot run curl: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "download failed for {url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| format!("invalid UTF-8 from {url}: {error}"))
}
