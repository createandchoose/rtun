//! Process-aware TUN routing through a verified sing-box build. WireGuard
//! datagrams stay on loopback and are carried to the VPS by RTUN transports.
use crate::{
    preferences::{RuleKind, SmartPreferences, TransportChoice},
    setup::Setup,
    ClientWinError, TunnelState,
};
use rt_proto::{ClientConfig, TransportKind};
use rt_routing::{
    manager::{CommandExecutor, ProcessExecutor},
    win,
};
use rt_transport::EndpointResolver;
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::watch};

pub fn engine_path() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("rtun/engine/1.14.4/sing-box.exe")
}

async fn network_settings(index: u32) -> Result<Value, ClientWinError> {
    let script=format!("$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); $p=(Get-NetIPInterface -InterfaceIndex {index} -AddressFamily IPv4).InterfaceAlias; $l=(Get-NetIPInterface -InterfaceIndex 1 -AddressFamily IPv4).InterfaceAlias; $d=@(Get-DnsClientServerAddress -InterfaceIndex {index} -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses); @{{physical=$p;loopback=$l;dns=$d}} | ConvertTo-Json -Compress");
    let mut command = tokio::process::Command::new("powershell");
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let output = command
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .await?;
    if !output.status.success() {
        return Err(ClientWinError::NoPhysicalRoute);
    }
    serde_json::from_slice(&output.stdout).map_err(|e| ClientWinError::Config(e.to_string()))
}

async fn ensure_engine() -> Result<PathBuf, ClientWinError> {
    let path = engine_path();
    if !path.is_file() {
        let mut command = tokio::process::Command::new("powershell");
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        let output = command
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                include_str!("../../../packaging/windows/install-smart-engine.ps1"),
            ])
            .kill_on_drop(true)
            .output()
            .await?;
        if !output.status.success() || !path.is_file() {
            return Err(ClientWinError::Config(
                "Не удалось загрузить движок умной фильтрации с GitHub".into(),
            ));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let dll = exe.parent().unwrap().join("wintun.dll");
        if dll.is_file() {
            std::fs::copy(dll, path.parent().unwrap().join("wintun.dll"))?;
        }
    }
    Ok(path)
}

pub fn engine_config(
    config: &ClientConfig,
    prefs: &SmartPreferences,
    relay: SocketAddr,
    country: &[String],
    endpoints: &[SocketAddr],
) -> Value {
    let mut rules = vec![
        json!({"action":"sniff"}),
        json!({"protocol":"dns", "action":"hijack-dns"}),
    ];
    let mut dns_rules = Vec::new();
    // Applications take precedence over site/automatic rules.
    for kind in [RuleKind::Application, RuleKind::Site] {
        for rule in prefs.rules.iter().filter(|rule| rule.kind == kind) {
            let matcher = if kind == RuleKind::Application {
                "process_path"
            } else {
                "domain_suffix"
            };
            let mut route = json!({"action":"route", "outbound":rule.mode.tag()});
            route[matcher] = json!([rule.target]);
            rules.push(route);
            let mut dns = json!({"action":"route", "server": if rule.mode.tag() == "direct" { "local-dns" } else { "vpn-dns" }});
            dns[matcher] = json!([rule.target]);
            dns_rules.push(dns);
        }
    }
    if !config.routing.tunnel_override_cidrs.is_empty() {
        rules.push(json!({"ip_cidr":config.routing.tunnel_override_cidrs,"action":"route","outbound":"vpn"}));
    }
    if !config.routing.direct_cidrs.is_empty() {
        rules.push(
            json!({"ip_cidr":config.routing.direct_cidrs,"action":"route","outbound":"direct"}),
        );
    }
    rules.push(json!({"ip_is_private":true,"action":"route","outbound":"direct"}));
    if prefs.bypass_russia {
        rules.push(json!({"domain_suffix":config.routing.direct_suffixes,"action":"route","outbound":"direct"}));
        if !country.is_empty() {
            rules.push(json!({"ip_cidr":country,"action":"route","outbound":"direct"}));
        }
        dns_rules.push(json!({"domain_suffix":config.routing.direct_suffixes,"action":"route","server":"local-dns"}));
    }
    let mut peer = json!({"address":relay.ip().to_string(),"port":relay.port(),"public_key":config.device.peer_public_key,
        "allowed_ips":["0.0.0.0/0","::/0"],"persistent_keepalive_interval":25});
    if let Some(psk) = &config.device.preshared_key {
        peer["pre_shared_key"] = json!(psk);
    }
    json!({
        "log":{"level":"error","timestamp":false},
        "dns":{"servers":[{"type":"local","tag":"local-dns","detour":"direct"},
            {"type":"udp","tag":"vpn-dns","server":config.dns.server_v4.to_string(),"detour":"vpn"}],
            "rules":dns_rules,"final":"vpn-dns","reverse_mapping":true},
        "inbounds":[{"type":"tun","tag":"smart-tun","interface_name":"rtun-smart",
            "address":["172.29.255.1/30","fdfe:dcba:9876::1/126"],"mtu":1280,
            "auto_route":true,"strict_route":true,"dns_mode":"hijack","stack":"mixed",
            "route_exclude_address":endpoints.iter().map(|e| format!("{}/{}",e.ip(),if e.is_ipv4(){32}else{128})).collect::<Vec<_>>() }],
        "endpoints":[{"type":"wireguard","tag":"vpn","system":false,"mtu":1280,"bind_interface":"Loopback Pseudo-Interface 1",
            "address":[format!("{}/32",config.device.address_v4),format!("{}/128",config.device.address_v6)],
            "private_key":config.device.private_key,"peers":[peer]}],
        "outbounds":[{"type":"direct","tag":"direct"}],
        "route":{"auto_detect_interface":true,"default_domain_resolver":"vpn-dns","rules":rules,"final":"vpn"}
    })
}

struct PrivateConfig(PathBuf);
async fn open_transport(
    config: &ClientConfig,
    addresses: &[SocketAddr],
) -> Result<Arc<dyn rt_transport::Transport>, ClientWinError> {
    let mut error = String::new();
    for kind in &config.transports.priority {
        match kind {
            TransportKind::ObfsUdp => {
                for address in addresses {
                    match rt_transport::ObfsUdpTransport::connect(*address, &config.obfs, 1280)
                        .await
                    {
                        Ok(transport) => return Ok(Arc::new(transport)),
                        Err(e) => error = e.to_string(),
                    }
                }
            }
            TransportKind::WsTls => match tokio::time::timeout(
                Duration::from_secs(8),
                rt_transport::WsTlsTransport::connect(
                    rt_transport::WsConfig::from_endpoint(&config.endpoint, 1280),
                    &EndpointResolver::new(true),
                ),
            )
            .await
            {
                Ok(Ok(transport)) => return Ok(Arc::new(transport)),
                Ok(Err(e)) => error = e.to_string(),
                Err(_) => error = "HTTPS connection timed out".into(),
            },
        }
    }
    Err(ClientWinError::Handshake(error))
}
impl Drop for PrivateConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub async fn run(
    config: ClientConfig,
    prefs: SmartPreferences,
    mut shutdown: watch::Receiver<bool>,
    status: watch::Sender<TunnelState>,
) -> Result<(), ClientWinError> {
    if *shutdown.borrow() {
        return Ok(());
    }
    config
        .validate()
        .map_err(|e| ClientWinError::Config(e.to_string()))?;
    status.send_replace(TunnelState::Connecting);
    let engine =
        tokio::select! { result=ensure_engine()=>result?, _=shutdown.changed()=>return Ok(()) };
    let country = if prefs.bypass_russia {
        tokio::select! { result=crate::split::load_geoip(&config)=>result?, _=shutdown.changed()=>return Ok(()) }
            .all()
            .map(|net| net.to_string())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let executor: Arc<dyn CommandExecutor> = Arc::new(ProcessExecutor);
    let mut retry = 0;
    while !*shutdown.borrow() {
        let physical = win::detect_physical(executor.as_ref())
            .await
            .ok_or(ClientWinError::NoPhysicalRoute)?;
        let addresses = EndpointResolver::new(true)
            .resolve(&config.endpoint.host, config.endpoint.port)
            .await?;
        let setup = Setup::new(executor.clone());
        if let Err(error) = setup.bypass_endpoints(&addresses, &physical).await {
            setup.teardown().await;
            return Err(error);
        }
        let network = match network_settings(physical.index).await {
            Ok(value) => value,
            Err(error) => {
                setup.teardown().await;
                return Err(error);
            }
        };
        let mut active_config = config.clone();
        active_config.transports.priority = match prefs.transport {
            TransportChoice::Udp => vec![TransportKind::ObfsUdp],
            TransportChoice::Https => vec![TransportKind::WsTls],
            TransportChoice::Auto if retry % 2 == 0 => {
                vec![TransportKind::ObfsUdp, TransportKind::WsTls]
            }
            TransportChoice::Auto => vec![TransportKind::WsTls, TransportKind::ObfsUdp],
        };
        let result = session(
            &engine,
            &active_config,
            &prefs,
            &country,
            &addresses,
            &network,
            &mut shutdown,
            &status,
        )
        .await;
        setup.teardown().await;
        if *shutdown.borrow() {
            break;
        }
        retry += 1;
        status.send_replace(TunnelState::Reconnecting {
            reason: result
                .err()
                .map(|e| crate::explain(&e))
                .unwrap_or_else(|| "Связь с сервером потеряна".into()),
            retry_in_secs: 2,
        });
        tokio::select! { _ = shutdown.changed() => break, _ = tokio::time::sleep(Duration::from_secs(2)) => {} }
    }
    status.send_replace(TunnelState::Idle);
    Ok(())
}

async fn session(
    engine: &std::path::Path,
    config: &ClientConfig,
    prefs: &SmartPreferences,
    country: &[String],
    addresses: &[SocketAddr],
    network: &Value,
    shutdown: &mut watch::Receiver<bool>,
    status: &watch::Sender<TunnelState>,
) -> Result<(), ClientWinError> {
    status.send_replace(TunnelState::Handshaking {
        endpoint: config.endpoint.host.clone(),
    });
    // Exactly one WireGuard owner: a separate probe can advance replay timestamps.
    let transport = open_transport(config, addresses).await?;
    let relay = UdpSocket::bind("127.0.0.1:0").await?;
    let mut document = engine_config(config, prefs, relay.local_addr()?, country, addresses);
    document["endpoints"][0]["bind_interface"] = network["loopback"].clone();
    document["outbounds"][0]["bind_interface"] = network["physical"].clone();
    let direct_dns = config
        .dns
        .direct_upstreams
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(ToString::to_string)
        .or_else(|| {
            network["dns"]
                .as_array()?
                .iter()
                .filter_map(Value::as_str)
                .find(|s| {
                    s.parse::<std::net::Ipv4Addr>()
                        .is_ok_and(|ip| !ip.is_loopback())
                })
                .map(str::to_owned)
        })
        .ok_or_else(|| ClientWinError::Config("Не найден DNS обычного подключения".into()))?;
    // Capture upstream DNS before the new TUN becomes the system resolver.
    document["dns"]["servers"][0] =
        json!({"type":"udp","tag":"local-dns","server":direct_dns,"detour":"direct"});
    let dir = engine.parent().unwrap();
    let guard = PrivateConfig(dir.join(format!("session-{}.json", std::process::id())));
    rt_proto::config::write_secure(&guard.0, &serde_json::to_vec(&document).unwrap())
        .map_err(|e| ClientWinError::Config(e.to_string()))?;
    let mut command = tokio::process::Command::new(engine);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let mut child = command
        .args(["run", "-c"])
        .arg(&guard.0)
        .current_dir(dir)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let mut sender = None;
    let mut buffer = vec![0u8; 65535];
    let mut received = Instant::now();
    let mut ready = false;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let result = async { loop {
        tokio::select! {
            _ = shutdown.changed() => break Ok(()),
            result = child.wait() => break Err(ClientWinError::Config(format!("Движок фильтрации завершился: {:?}",result.map(|s| s.code())))),
            result = relay.recv_from(&mut buffer) => {
                let (len,peer) = result?;
                if sender.is_some_and(|known| known != peer) { continue; }
                if len < 32 { continue; }
                sender = Some(peer);
                if let Err(error) = transport.send(&buffer[..len]).await { break Err(error.into()); }
            }
            result = transport.recv() => {
                match result {
                    Ok(packet) => {
                        received = Instant::now();
                        if let Some(peer) = sender { relay.send_to(&packet,peer).await?; }
                        if !ready && packet.starts_with(&[2,0,0,0]) {
                            ready=true;
                            status.send_replace(TunnelState::Connected { endpoint:format!("{} · {}",config.endpoint.host,match transport.kind(){ TransportKind::ObfsUdp=>"UDP",TransportKind::WsTls=>"HTTPS" }),tunnel_ip:config.device.address_v4.to_string(),since:Instant::now() });
                        }
                    }
                    Err(error) => break Err(error.into()),
                }
            }
            _ = tick.tick() => {
                if received.elapsed() > Duration::from_secs(if ready { 60 } else { 15 }) { break Err(ClientWinError::Handshake("Нет ответа через выбранный транспорт".into())); }
            }
        }
    }}.await;
    let _ = child.start_kill();
    let _ = child.wait().await;
    transport.close().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preferences::{FilterRule, RuleMode};
    fn fixture() -> ClientConfig {
        let mut config = ClientConfig::default();
        config.device.private_key = rt_proto::generate_private_key();
        config.device.peer_public_key =
            rt_proto::public_key_from_private(&rt_proto::generate_private_key()).unwrap();
        config
    }
    #[tokio::test]
    async fn cancelled_session_does_not_start_engine() {
        let (_stop, shutdown) = watch::channel(true);
        let (status, _) = watch::channel(TunnelState::Idle);
        run(fixture(), SmartPreferences::default(), shutdown, status)
            .await
            .unwrap();
    }
    #[test]
    fn manual_rules_precede_automatic_country_rules() {
        let mut prefs = SmartPreferences::default();
        prefs.rules.push(FilterRule {
            kind: RuleKind::Site,
            target: "example.ru".into(),
            name: "example".into(),
            mode: RuleMode::Vpn,
            icon: None,
        });
        prefs.rules.push(FilterRule {
            kind: RuleKind::Application,
            target: r"C:\Program Files\Browser\browser.exe".into(),
            name: "Browser".into(),
            mode: RuleMode::Direct,
            icon: None,
        });
        let value = engine_config(
            &fixture(),
            &prefs,
            "127.0.0.1:12345".parse().unwrap(),
            &["77.88.0.0/18".into()],
            &[],
        );
        let rules = value["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[2]["outbound"], "direct");
        assert!(rules[2].get("process_path").is_some());
        assert_eq!(rules[3]["outbound"], "vpn");
        prefs.bypass_russia = false;
        let value = engine_config(
            &fixture(),
            &prefs,
            "127.0.0.1:12345".parse().unwrap(),
            &["77.88.0.0/18".into()],
            &[],
        );
        assert!(!value["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.get("ip_cidr") == Some(&json!(["77.88.0.0/18"]))));
        assert_eq!(value["route"]["rules"][3]["outbound"], "vpn");
    }
    #[test]
    #[ignore = "requires installed verified sing-box engine"]
    fn real_engine_accepts_generated_configuration() {
        let path =
            std::env::temp_dir().join(format!("rtun-engine-check-{}.json", std::process::id()));
        let _guard = PrivateConfig(path.clone());
        let mut prefs = SmartPreferences::default();
        prefs.rules.push(FilterRule {
            kind: RuleKind::Application,
            target: r"C:\Windows\System32\notepad.exe".into(),
            name: "Notepad".into(),
            mode: RuleMode::Vpn,
            icon: None,
        });
        prefs.rules.push(FilterRule {
            kind: RuleKind::Site,
            target: "example.ru".into(),
            name: "Example".into(),
            mode: RuleMode::Direct,
            icon: None,
        });
        let doc = engine_config(
            &fixture(),
            &prefs,
            "127.0.0.1:12345".parse().unwrap(),
            &["77.88.0.0/18".into()],
            &[],
        );
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        let result = std::process::Command::new(engine_path())
            .args(["check", "-c"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[tokio::test]
    #[ignore = "requires RTUN_LIVE_CONFIG and installed engine; uses loopback SOCKS only, no system routes"]
    async fn live_engine_relays_udp_and_https_to_vps() {
        let mut config = crate::plan::load_config(std::path::Path::new(
            &std::env::var("RTUN_LIVE_CONFIG").unwrap(),
        ))
        .unwrap();
        for kind in [TransportKind::ObfsUdp, TransportKind::WsTls] {
            config.transports.priority = vec![kind];
            let addresses = EndpointResolver::new(true)
                .resolve(&config.endpoint.host, config.endpoint.port)
                .await
                .unwrap();
            let transport = open_transport(&config, &addresses).await.unwrap();
            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let socks_port = reserved.local_addr().unwrap().port();
            drop(reserved);
            let mut doc = engine_config(
                &config,
                &SmartPreferences {
                    bypass_russia: false,
                    ..Default::default()
                },
                relay.local_addr().unwrap(),
                &[],
                &addresses,
            );
            doc["inbounds"] = json!([{"type":"mixed","tag":"test-socks","listen":"127.0.0.1","listen_port":socks_port}]);
            let guard = PrivateConfig(
                std::env::temp_dir().join(format!("rtun-live-engine-{}.json", std::process::id())),
            );
            std::fs::write(&guard.0, serde_json::to_vec(&doc).unwrap()).unwrap();
            let mut child = tokio::process::Command::new(engine_path())
                .args(["run", "-c"])
                .arg(&guard.0)
                .kill_on_drop(true)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let bridge_transport = transport.clone();
            let bridge = tokio::spawn(async move {
                let mut sender = None;
                let mut buffer = vec![0u8; 65535];
                loop {
                    tokio::select! {
                    result=relay.recv_from(&mut buffer)=>{let(len,peer)=result.unwrap();sender=Some(peer);bridge_transport.send(&buffer[..len]).await.unwrap();},
                    result=bridge_transport.recv()=>{let packet=result.unwrap();if let Some(peer)=sender{relay.send_to(&packet,peer).await.unwrap();}}
                    }
                }
            });
            tokio::time::sleep(Duration::from_millis(500)).await;
            let result = tokio::process::Command::new("curl.exe")
                .args([
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "20",
                    "--socks5-hostname",
                ])
                .arg(format!("127.0.0.1:{socks_port}"))
                .arg("https://api.ipify.org")
                .output()
                .await
                .unwrap();
            let _ = child.start_kill();
            let output = child.wait_with_output().await.unwrap();
            bridge.abort();
            transport.close().await;
            assert!(
                result.status.success(),
                "{kind:?}: curl={} engine={}",
                String::from_utf8_lossy(&result.stderr),
                String::from_utf8_lossy(&output.stderr)
            );
            let ip = String::from_utf8_lossy(&result.stdout)
                .trim()
                .parse::<std::net::IpAddr>()
                .unwrap();
            assert!(
                addresses.iter().any(|endpoint| endpoint.ip() == ip),
                "unexpected VPS egress for {kind:?}: {ip}"
            );
        }
    }
}
