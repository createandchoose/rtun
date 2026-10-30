//! Windows split routing: learn host routes before returning DNS answers.
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::{op::Message, rr::RData};
use ipnet::IpNet;
use rt_dns::proxy::ResponseHandler;
use rt_dns::{DnsEvent, DnsProxyHandle, DnsSettings};
use rt_proto::ClientConfig;
use rt_routing::{
    geoip::{self, GeoIpData},
    manager::CommandExecutor,
    win::{PhysicalRoute, WinRoute},
};
use tokio::sync::mpsc;
use tracing::warn;

use crate::{error::ClientWinError, setup::Setup};

fn cache_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("rtun")
        .join("geoip")
}

async fn download(url: &str) -> Result<String, ClientWinError> {
    let mut command = tokio::process::Command::new(if cfg!(windows) { "curl.exe" } else { "curl" });
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let output = command
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "15",
            url,
        ])
        .kill_on_drop(true)
        .output()
        .await?;
    if !output.status.success() {
        return Err(ClientWinError::Config(
            "Не удалось обновить базу российских IP".into(),
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| ClientWinError::Config(e.to_string()))
}

pub async fn load_geoip(config: &ClientConfig) -> Result<GeoIpData, ClientWinError> {
    let dir = cache_dir();
    let cached = geoip::load(&dir).unwrap_or_default();
    let fresh = ["geoip-v4.nets", "geoip-v6.nets"].iter().all(|file| {
        std::fs::metadata(dir.join(file))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| {
                age < Duration::from_secs(config.routing.geoip.update_hours.saturating_mul(3600))
            })
    });
    if fresh && !cached.v4.is_empty() && !cached.v6.is_empty() {
        return Ok(cached);
    }
    let (v4, v6) = tokio::join!(
        download(&config.routing.geoip.v4_url),
        download(&config.routing.geoip.v6_url)
    );
    let updated = (|| {
        let v4 = geoip::parse_zone(&v4?)?;
        let v6 = geoip::parse_zone(&v6?)?;
        if v4.len() < 100
            || v6.len() < 10
            || v4.iter().any(|net| net.addr().is_ipv6())
            || v6.iter().any(|net| net.addr().is_ipv4())
        {
            return Err(ClientWinError::Config("База российских IP неполная".into()));
        }
        Ok(GeoIpData { v4, v6 })
    })();
    match updated {
        Ok(data) => {
            if let Err(error) = geoip::save(&dir, &data) {
                warn!(%error, "cannot cache GeoIP data");
            }
            Ok(data)
        }
        Err(error) if !cached.v4.is_empty() && !cached.v6.is_empty() => {
            warn!(%error, "using cached Russian IP ranges");
            Ok(cached)
        }
        Err(error) => Err(error),
    }
}

pub struct SplitDns {
    settings: DnsSettings,
    config: ClientConfig,
    physical: PhysicalRoute,
    geo: GeoIpData,
}

impl SplitDns {
    pub async fn prepare(
        config: &ClientConfig,
        physical: &PhysicalRoute,
        executor: &dyn CommandExecutor,
    ) -> Result<Self, ClientWinError> {
        let mut settings = DnsSettings::from_config(config, false)
            .map_err(|e| ClientWinError::Config(e.to_string()))?
            .with_listen(vec![
                "127.0.0.1:53".parse().unwrap(),
                "[::1]:53".parse().unwrap(),
            ]);
        settings.direct_upstreams = config
            .dns
            .direct_upstreams
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(|ip| SocketAddr::new(*ip, 53))
            .collect();
        if settings.direct_upstreams.is_empty() && config.dns.use_system_direct_upstreams {
            let script = format!("Get-DnsClientServerAddress -InterfaceIndex {} -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses", physical.index);
            let output = executor
                .run(
                    "powershell",
                    &[
                        "-NoProfile".into(),
                        "-NonInteractive".into(),
                        "-Command".into(),
                        script,
                    ],
                )
                .await?;
            if output.status == 0 {
                settings.direct_upstreams = String::from_utf8_lossy(&output.stdout)
                    .split_whitespace()
                    .filter_map(|s| s.parse::<IpAddr>().ok())
                    .filter(|ip| {
                        ip.is_ipv4() && !ip.is_loopback() && *ip != IpAddr::V4(config.dns.server_v4)
                    })
                    .map(|ip| SocketAddr::new(ip, 53))
                    .collect();
            }
        }
        if settings.direct_upstreams.is_empty() {
            return Err(ClientWinError::Config(
                "Не найден DNS обычного подключения для российских сайтов".into(),
            ));
        }
        // Windows netsh starts a process per route: learn only the addresses
        // actually used instead of installing thousands of country prefixes.
        let geo = load_geoip(config).await?;
        Ok(Self {
            settings,
            config: config.clone(),
            physical: physical.clone(),
            geo,
        })
    }

    pub async fn start(self, setup: Arc<Setup>) -> Result<DnsProxyHandle, ClientWinError> {
        for upstream in &self.settings.direct_upstreams {
            if let Some(route) = direct_route(upstream.ip(), &self.physical) {
                setup.add_route(route).await?;
            }
        }
        let handler = Arc::new(Routes {
            setup,
            config: self.config,
            physical: self.physical,
            geo: self.geo,
        });
        let (tx, _rx) = mpsc::channel(1);
        rt_dns::proxy::spawn_with_handler(self.settings, tx, Some(handler))
            .await
            .map_err(|e| ClientWinError::Config(e.to_string()))
    }
}

pub fn direct_route(ip: IpAddr, physical: &PhysicalRoute) -> Option<WinRoute> {
    let gateway = match ip {
        IpAddr::V4(_) => IpAddr::V4(physical.gateway?),
        IpAddr::V6(_) => IpAddr::V6(physical.gateway_v6?),
    };
    Some(WinRoute {
        net: IpNet::from(ip),
        nexthop: gateway,
        interface: physical.index.to_string(),
    })
}

struct Routes {
    setup: Arc<Setup>,
    config: ClientConfig,
    physical: PhysicalRoute,
    geo: GeoIpData,
}

impl Routes {
    fn is_direct(&self, ip: IpAddr, direct_domain: bool) -> bool {
        if ip == IpAddr::V4(self.config.dns.server_v4)
            || ip == IpAddr::V6(self.config.dns.server_v6)
            || self
                .config
                .routing
                .override_nets()
                .unwrap_or_default()
                .iter()
                .any(|net| net.contains(&ip))
        {
            return false;
        }
        direct_domain || self.geo.all().any(|net| net.contains(&ip))
    }
}

#[async_trait::async_trait]
impl ResponseHandler for Routes {
    async fn prepare(&self, event: &DnsEvent, response: &mut Vec<u8>) -> rt_dns::Result<()> {
        for ip in &event.addresses {
            if self.is_direct(*ip, event.direct_domain) {
                if let Some(route) = direct_route(*ip, &self.physical) {
                    self.setup
                        .add_route(route)
                        .await
                        .map_err(|e| rt_dns::DnsError::Config(e.to_string()))?;
                }
            }
        }
        // With no native IPv6 gateway, Russian sites must use direct IPv4
        // rather than falling back to the VPN's IPv6 route.
        if self.physical.gateway_v6.is_none() {
            let mut message = Message::from_vec(response)
                .map_err(|e| rt_dns::DnsError::Message(e.to_string()))?;
            message.answers.retain(|record| match &record.data {
                RData::AAAA(ip) => !self.is_direct(IpAddr::V6(ip.0), event.direct_domain),
                _ => true,
            });
            *response = message
                .to_vec()
                .map_err(|e| rt_dns::DnsError::Message(e.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{MessageType, OpCode},
        rr::{
            rdata::{A, AAAA},
            Name, Record,
        },
    };
    use rt_routing::{CommandOutput, RoutingError};
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        commands: Mutex<Vec<Vec<String>>>,
    }
    #[async_trait::async_trait]
    impl CommandExecutor for Recorder {
        async fn run(&self, _: &str, args: &[String]) -> Result<CommandOutput, RoutingError> {
            self.commands.lock().await.push(args.to_vec());
            Ok(CommandOutput {
                status: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
    }
    fn handler(executor: Arc<Recorder>) -> Routes {
        Routes {
            setup: Arc::new(Setup::new(executor)),
            config: ClientConfig::default(),
            physical: PhysicalRoute {
                index: 7,
                gateway: Some("192.168.1.1".parse().unwrap()),
                gateway_v6: None,
            },
            geo: GeoIpData {
                v4: vec!["77.88.0.0/18".parse().unwrap()],
                v6: vec!["2a02:6b8::/32".parse().unwrap()],
            },
        }
    }
    fn answer(ip: IpAddr) -> Vec<u8> {
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.add_answer(Record::from_rdata(
            Name::from_ascii("example.ru").unwrap(),
            60,
            match ip {
                IpAddr::V4(ip) => RData::A(A(ip)),
                IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
            },
        ));
        message.to_vec().unwrap()
    }
    fn event(ip: IpAddr, direct: bool) -> DnsEvent {
        DnsEvent {
            name: "example.ru".into(),
            addresses: vec![ip],
            direct_domain: direct,
            ttl: 60,
        }
    }

    #[tokio::test]
    #[ignore = "downloads current Russian IP ranges and primes the local cache"]
    async fn refreshes_live_geoip() {
        let data = load_geoip(&ClientConfig::default()).await.unwrap();
        assert!(data.v4.len() > 100 && data.v6.len() > 10);
        assert!(data
            .v4
            .iter()
            .any(|net| net.contains(&"77.88.8.8".parse::<IpAddr>().unwrap())));
        assert!(!data
            .all()
            .any(|net| net.contains(&"8.8.8.8".parse::<IpAddr>().unwrap())));
        assert_eq!(data, load_geoip(&ClientConfig::default()).await.unwrap());
    }
    #[tokio::test]
    async fn russian_domains_and_country_ips_get_physical_routes_and_cleanup() {
        let recorder = Arc::new(Recorder::default());
        let routes = handler(recorder.clone());
        // Russian suffix on foreign hosting, then Russian hosting on any suffix.
        for (value, direct) in [("203.0.113.9", true), ("77.88.8.8", false)] {
            let ip = value.parse().unwrap();
            routes
                .prepare(&event(ip, direct), &mut answer(ip))
                .await
                .unwrap();
        }
        let commands = recorder.commands.lock().await;
        assert_eq!(
            commands
                .iter()
                .filter(|args| args.contains(&"add".into()))
                .count(),
            2
        );
        assert!(commands
            .iter()
            .all(|args| args.contains(&"interface=7".into())
                && args.contains(&"nexthop=192.168.1.1".into())));
        drop(commands);
        routes.setup.teardown().await;
        let ip = "203.0.113.10".parse().unwrap();
        assert!(routes
            .prepare(&event(ip, true), &mut answer(ip))
            .await
            .is_err());
        assert_eq!(
            recorder
                .commands
                .lock()
                .await
                .iter()
                .filter(|args| args.contains(&"delete".into()))
                .count(),
            4
        );
    }
    #[tokio::test]
    async fn foreign_addresses_and_tunnel_overrides_do_not_bypass() {
        let recorder = Arc::new(Recorder::default());
        let mut routes = handler(recorder.clone());
        routes.config.routing.tunnel_override_cidrs = vec!["203.0.113.0/24".into()];
        for (value, direct) in [
            ("8.8.8.8", false),
            ("203.0.113.9", true),
            ("10.66.0.1", true),
        ] {
            let ip = value.parse().unwrap();
            routes
                .prepare(&event(ip, direct), &mut answer(ip))
                .await
                .unwrap();
        }
        assert!(recorder.commands.lock().await.is_empty());
    }
    #[tokio::test]
    async fn russian_ipv6_uses_native_gateway_or_falls_back_to_ipv4() {
        let recorder = Arc::new(Recorder::default());
        let mut routes = handler(recorder.clone());
        let ip = "2a02:6b8::1".parse().unwrap();
        let mut response = answer(ip);
        routes
            .prepare(&event(ip, true), &mut response)
            .await
            .unwrap();
        assert!(Message::from_vec(&response).unwrap().answers.is_empty());
        assert!(recorder.commands.lock().await.is_empty());
        routes.physical.gateway_v6 = Some("fe80::1".parse().unwrap());
        let mut response = answer(ip);
        routes
            .prepare(&event(ip, true), &mut response)
            .await
            .unwrap();
        assert_eq!(Message::from_vec(&response).unwrap().answers.len(), 1);
        assert!(recorder
            .commands
            .lock()
            .await
            .iter()
            .any(|args| args.contains(&"add".into()) && args.contains(&"nexthop=fe80::1".into())));
    }
}
