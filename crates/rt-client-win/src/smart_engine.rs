//! Process-aware TUN routing through a verified sing-box build. WireGuard
//! datagrams stay on loopback and are carried to the VPS by RTUN transports.
use crate::{
    preferences::{RuleKind, SmartPreferences},
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
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::watch,
};

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
    if prefs.bypass_russia {
        rules.push(json!({"domain_suffix":config.routing.direct_suffixes,"action":"route","outbound":"direct"}));
    }
    // Resolve domain destinations before evaluating CIDR/country rules.
    rules.push(json!({"action":"resolve","strategy":"ipv4_only"}));
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
            "rules":dns_rules,"final":"vpn-dns","reverse_mapping":true,"strategy":"ipv4_only"},
        "inbounds":[{"type":"tun","tag":"smart-tun","interface_name":"rtun-smart",
            "address":["172.29.255.1/30","fdfe:dcba:9876::1/126"],"mtu":1280,
            "auto_route":true,"strict_route":false,"dns_mode":"native","stack":"gvisor",
            "route_exclude_address":endpoints.iter().map(|e| format!("{}/{}",e.ip(),if e.is_ipv4(){32}else{128})).collect::<Vec<_>>() }],
        "endpoints":[{"type":"wireguard","tag":"vpn","system":false,"mtu":1280,"bind_interface":"Loopback Pseudo-Interface 1",
            "address":[format!("{}/32",config.device.address_v4),format!("{}/128",config.device.address_v6)],
            "private_key":config.device.private_key,"peers":[peer]}],
        "outbounds":[{"type":"direct","tag":"direct","domain_resolver":{"server":"local-dns","strategy":"ipv4_only"}}],
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

fn transport_label(kind: TransportKind) -> &'static str {
    match kind {
        TransportKind::ObfsUdp => "obfs-udp",
        TransportKind::WsTls => "ws-tls",
    }
}

fn recoverable_adapter_error(message: &str) -> bool {
    message.contains("create adapter:") && message.contains("open existing adapter:")
}

fn next_transport(current: TransportKind, error: &ClientWinError) -> TransportKind {
    if matches!(
        error,
        ClientWinError::Transport(_) | ClientWinError::Handshake(_)
    ) {
        match current {
            TransportKind::ObfsUdp => TransportKind::WsTls,
            TransportKind::WsTls => TransportKind::ObfsUdp,
        }
    } else {
        current
    }
}

async fn wait_for_health_proxy(proxy: SocketAddr) -> Result<TcpStream, ClientWinError> {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            match TcpStream::connect(proxy).await {
                Ok(stream) => return Ok(stream),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .map_err(|_| {
        ClientWinError::Config(format!(
            "Локальный прокси проверки {proxy} не запустился за 4 секунды"
        ))
    })?
    .map_err(|error| ClientWinError::Config(format!("Локальный прокси проверки {proxy}: {error}")))
}

async fn check_tunnel_dns(
    proxy: SocketAddr,
    server: std::net::Ipv4Addr,
) -> Result<(), ClientWinError> {
    let mut stream = wait_for_health_proxy(proxy).await?;
    tokio::time::timeout(Duration::from_secs(8), async {
        stream.write_all(&[5,1,0]).await?;
        let mut greeting=[0u8;2];stream.read_exact(&mut greeting).await?;
        if greeting!=[5,0]{return Err(std::io::Error::other("Local health proxy rejected authentication"));}
        let mut connect=vec![5,1,0,1];connect.extend_from_slice(&server.octets());connect.extend_from_slice(&53u16.to_be_bytes());
        stream.write_all(&connect).await?;
        let mut header=[0u8;4];stream.read_exact(&mut header).await?;
        if header[1]!=0{return Err(std::io::Error::other("Cannot reach tunnel DNS over TCP"));}
        let size=match header[3]{1=>4,4=>16,3=>stream.read_u8().await? as usize,_=>return Err(std::io::Error::other("Invalid proxy response"))};
        let mut address=vec![0;size+2];stream.read_exact(&mut address).await?;
        let query=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        stream.write_all(&(query.len() as u16).to_be_bytes()).await?;stream.write_all(query).await?;
        let length=stream.read_u16().await? as usize;
        if !(12..=65535).contains(&length){return Err(std::io::Error::other("Invalid DNS answer length"));}
        let mut response=vec![0;length];stream.read_exact(&mut response).await?;
        if response[..2]!=[0x12,0x34] || response[3]&15!=0 || response[6..8]==[0,0] {return Err(std::io::Error::other("Tunnel DNS returned no usable answer"));}
        Ok::<(),std::io::Error>(())
    }).await.map_err(|_|ClientWinError::Handshake("Туннель не передаёт DNS: проверка данных не прошла".into()))?
        .map_err(|error| ClientWinError::Handshake(format!("Проверка DNS через туннель: {error}")))?;
    Ok(())
}

async fn check_native_dns(server: SocketAddr) -> Result<(), ClientWinError> {
    let query =
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut answer = [0u8; 4096];
        let length = loop {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            socket.connect(server).await?;
            socket.send(query).await?;
            match tokio::time::timeout(Duration::from_millis(800), socket.recv(&mut answer)).await {
                Ok(Ok(length)) => break length,
                Ok(Err(error))
                    if !matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    return Err(error)
                }
                _ => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        };
        if length < 12
            || answer[..2] != [0x12, 0x34]
            || answer[3] & 15 != 0
            || answer[6..8] == [0, 0]
        {
            return Err(std::io::Error::other(
                "Windows tunnel DNS returned no answer",
            ));
        }
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|_| {
        ClientWinError::Config(
            "Не отвечает DNS адаптера Windows: возможен конфликт с другим VPN".into(),
        )
    })?
    .map_err(|error| ClientWinError::Config(format!("DNS адаптера Windows ({server}): {error}")))?;
    Ok(())
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
    let mut active_transport = TransportKind::ObfsUdp;
    let mut adapter_recovery_used = false;
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
        active_config.transports.priority = vec![active_transport];
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
        // Local engine/configuration failures cannot be repaired by changing transport.
        // Surface them once instead of repeatedly destroying/recreating the adapter.
        if let Err(ClientWinError::Config(message)) = &result {
            if !adapter_recovery_used && recoverable_adapter_error(message) {
                // Wintun's failed create/open unwinds the stale device. Retry once
                // after the child has exited; never remove unrelated adapters.
                adapter_recovery_used = true;
            } else {
                return result;
            }
        }
        let reason = match result {
            Err(error) => {
                let next = next_transport(active_transport, &error);
                let detail = match &error {
                    ClientWinError::Handshake(message) | ClientWinError::Config(message) => {
                        message.clone()
                    }
                    _ => crate::explain(&error),
                };
                let reason = format!("{}: {}", transport_label(active_transport), detail);
                active_transport = next;
                format!("{reason}. Повтор через {}", transport_label(next))
            }
            Ok(()) => "Связь с сервером потеряна".into(),
        };
        status.send_replace(TunnelState::Reconnecting {
            reason,
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
        endpoint: format!(
            "{} · {}",
            config.endpoint.host,
            transport_label(config.transports.priority[0])
        ),
    });
    // Exactly one WireGuard owner: a separate probe can advance replay timestamps.
    let transport = open_transport(config, addresses).await?;
    let relay = UdpSocket::bind("127.0.0.1:0").await?;
    let mut document = engine_config(config, prefs, relay.local_addr()?, country, addresses);
    document["log"]["level"] = json!("info");
    let reserved = std::net::TcpListener::bind("127.0.0.1:0")?;
    let health_address = reserved.local_addr()?;
    drop(reserved);
    document["inbounds"].as_array_mut().unwrap().push(json!({"type":"mixed","tag":"health-check","listen":"127.0.0.1","listen_port":health_address.port()}));
    document["route"]["rules"].as_array_mut().unwrap().insert(
        0,
        json!({"inbound":["health-check"],"action":"route","outbound":"vpn"}),
    );
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
    let wrapper = dir.join("run-smart-engine.ps1");
    rt_proto::config::write_secure(
        &wrapper,
        include_bytes!("../../../packaging/windows/run-smart-engine.ps1"),
    )
    .map_err(|e| ClientWinError::Config(e.to_string()))?;
    let mut command = tokio::process::Command::new("powershell");
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let mut child = command
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&wrapper)
        .arg("-Engine")
        .arg(engine)
        .arg("-Config")
        .arg(&guard.0)
        .current_dir(dir)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;
    // Child::wait closes its owned stdin on the first poll. Keep the stop pipe
    // outside Child so monitoring exit cannot accidentally stop the engine.
    let mut engine_input = child.stdin.take();
    let engine_errors = Arc::new(tokio::sync::Mutex::new(
        std::collections::VecDeque::<String>::new(),
    ));
    let errors = engine_errors.clone();
    let (engine_started_tx, mut engine_started_rx) = watch::channel(false);
    let secret = config.device.private_key.clone();
    let psk = config.device.preshared_key.clone();
    let stderr = child.stdout.take().unwrap();
    let reader = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let mut line = line.replace(&secret, "[redacted]");
            if let Some(psk) = &psk {
                line = line.replace(psk, "[redacted]");
            }
            #[cfg(test)]
            eprintln!("ENGINE: {line}");
            if line.contains("sing-box started (") {
                engine_started_tx.send_replace(true);
            }
            let mut errors = errors.lock().await;
            if errors.len() == 12 {
                errors.pop_front();
            }
            errors.push_back(line);
        }
    });
    let mut sender = None;
    let mut buffer = vec![0u8; 65535];
    let mut received = Instant::now();
    let mut ready = false;
    let mut checking = false;
    let started_at = Instant::now();
    let mut last_health_check = Instant::now();
    let (health_tx, mut health_rx) = tokio::sync::mpsc::channel(1);
    let mut health_task = None;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let result = async { loop {
        tokio::select! {
            _ = shutdown.changed() => break Ok(()),
            result = child.wait() => {
                let detail=engine_errors.lock().await.iter().cloned().collect::<Vec<_>>().join("\n");
                break Err(ClientWinError::Config(format!("Движок фильтрации завершился: {:?}. {detail}",result.map(|s| s.code()))));
            },
            result = engine_started_rx.changed(), if !checking => {
                if result.is_err() { continue; }
                if *engine_started_rx.borrow() {
                    checking = true;
                    received = Instant::now();
                    let tx = health_tx.clone();
                    let dns = config.dns.server_v4;
                    health_task = Some(tokio::spawn(async move {
                        let result = async {
                            check_tunnel_dns(health_address, dns).await?;
                            check_native_dns("172.29.255.2:53".parse().unwrap()).await
                        }.await;
                        let _ = tx.send(result).await;
                    }));
                }
            },
            Some(result)=health_rx.recv(), if checking => {
                result?;
                #[cfg(test)]
                eprintln!("NATIVE HEALTH: tunnel and adapter DNS passed");
                health_task = None;
                last_health_check = Instant::now();
                if !ready {
                    ready=true;
                    status.send_replace(TunnelState::Connected { endpoint:format!("{} · {}",config.endpoint.host,transport_label(transport.kind())),tunnel_ip:config.device.address_v4.to_string(),since:Instant::now() });
                }
            }
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
                    }
                    Err(rt_transport::TransportError::Timeout) => {},
                    Err(rt_transport::TransportError::Io(error)) if transport.kind()==TransportKind::ObfsUdp && matches!(error.kind(),std::io::ErrorKind::ConnectionReset|std::io::ErrorKind::ConnectionRefused|std::io::ErrorKind::Interrupted|std::io::ErrorKind::WouldBlock) => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Err(error) => break Err(error.into()),
                }
            }
            _ = tick.tick() => {
                if ready && health_task.is_none() && last_health_check.elapsed() > Duration::from_secs(30) {
                    let tx = health_tx.clone();
                    let dns = config.dns.server_v4;
                    health_task = Some(tokio::spawn(async move {
                        let result = async {
                            check_tunnel_dns(health_address, dns).await?;
                            check_native_dns("172.29.255.2:53".parse().unwrap()).await
                        }.await;
                        let _ = tx.send(result).await;
                    }));
                }
                if !checking && started_at.elapsed() > Duration::from_secs(45) {
                    let detail=engine_errors.lock().await.iter().cloned().collect::<Vec<_>>().join("\n");
                    break Err(ClientWinError::Config(format!("Windows-адаптер не запустился за 45 секунд. {detail}")));
                }
                if checking && received.elapsed() > Duration::from_secs(if ready { 60 } else { 20 }) { break Err(ClientWinError::Handshake("Нет ответа через выбранный транспорт".into())); }
            }
        }
    }}.await;
    if let Some(mut input) = engine_input.take() {
        let _ = input.write_all(b"stop\n").await;
    }
    if tokio::time::timeout(Duration::from_secs(12), child.wait())
        .await
        .is_err()
    {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    if let Some(task) = health_task {
        task.abort();
    }
    reader.abort();
    transport.close().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preferences::{FilterRule, RuleMode};

    #[tokio::test]
    #[ignore = "requires administrator, RTUN_LIVE_CONFIG; temporarily creates the real Windows TUN"]
    async fn live_windows_tun_session() {
        assert!(crate::is_elevated(), "administrator required");
        let mut config = crate::plan::load_config(std::path::Path::new(
            &std::env::var("RTUN_LIVE_CONFIG").unwrap(),
        ))
        .unwrap();
        let mut prefs = SmartPreferences::load().unwrap();
        let scenario = std::env::var("RTUN_NATIVE_SCENARIO").unwrap_or_default();
        if scenario == "fallback" {
            // Simulate UDP silently dropped without changing the VPS or firewall.
            config.obfs.h1 ^= 0x10203040;
        }
        if scenario == "direct" || scenario == "fallback" {
            prefs.rules.retain(|rule| {
                rule.kind != RuleKind::Application && rule.target != "api.ipify.org"
            });
            prefs.rules.push(FilterRule {
                kind: RuleKind::Site,
                target: "api.ipify.org".into(),
                name: "test direct".into(),
                mode: RuleMode::Direct,
                icon: None,
            });
        }
        if scenario == "fallback" {
            let curl = std::process::Command::new("where.exe")
                .arg("curl.exe")
                .output()
                .unwrap();
            let path = String::from_utf8(curl.stdout)
                .unwrap()
                .lines()
                .next()
                .unwrap()
                .to_owned();
            prefs.rules.push(FilterRule {
                kind: RuleKind::Application,
                target: path,
                name: "test app override".into(),
                mode: RuleMode::Vpn,
                icon: None,
            });
        }
        let (stop_tx, stop_rx) = watch::channel(false);
        let (status_tx, mut status_rx) = watch::channel(TunnelState::Idle);
        let task = tokio::spawn(run(config, prefs, stop_rx, status_tx));
        let outcome = tokio::time::timeout(Duration::from_secs(80), async {
            loop {
                if status_rx.changed().await.is_err() {
                    return None;
                }
                let state = status_rx.borrow().clone();
                eprintln!("NATIVE: {state:?}");
                if matches!(state, TunnelState::Connected { .. }) {
                    if scenario == "stability" {
                        tokio::time::sleep(Duration::from_secs(35)).await;
                    }
                    let state = status_rx.borrow().clone();
                    let output = tokio::process::Command::new("curl.exe")
                        .args([
                            "--noproxy",
                            "*",
                            "--fail",
                            "--silent",
                            "--show-error",
                            "--max-time",
                            "12",
                            "https://api.ipify.org",
                        ])
                        .output()
                        .await
                        .unwrap();
                    return Some((state, output));
                }
            }
        })
        .await;
        stop_tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(15), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let (state, output) = outcome
            .expect("native Windows session did not connect")
            .expect("session exited before connecting");
        assert!(matches!(state, TunnelState::Connected { .. }));
        if scenario == "fallback" {
            assert!(
                matches!(&state, TunnelState::Connected { endpoint, .. } if endpoint.ends_with("ws-tls"))
            );
        }
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let address = String::from_utf8_lossy(&output.stdout);
        eprintln!("NATIVE RESULT ({scenario}): {}", address.trim());
        if scenario == "direct" {
            assert!(address.trim().parse::<std::net::Ipv4Addr>().is_ok());
            assert_ne!(address.trim(), "193.34.77.251");
        } else {
            assert_eq!(address.trim(), "193.34.77.251");
        }
    }

    #[test]
    fn failover_switches_transports_only_for_tunnel_failures() {
        let failure = ClientWinError::Handshake("timeout".into());
        assert_eq!(
            next_transport(TransportKind::ObfsUdp, &failure),
            TransportKind::WsTls
        );
        assert_eq!(
            next_transport(TransportKind::WsTls, &failure),
            TransportKind::ObfsUdp
        );
        let local = ClientWinError::Config("local DNS unavailable".into());
        assert_eq!(
            next_transport(TransportKind::ObfsUdp, &local),
            TransportKind::ObfsUdp
        );
        assert_eq!(
            next_transport(TransportKind::WsTls, &local),
            TransportKind::WsTls
        );
        assert_eq!(transport_label(TransportKind::ObfsUdp), "obfs-udp");
        assert!(recoverable_adapter_error("configure tun interface: (create adapter: exists | open existing adapter: Element not found.)"));
        assert!(!recoverable_adapter_error(
            "set ipv4 dns: permission denied"
        ));
    }

    #[tokio::test]
    async fn health_proxy_waits_for_delayed_listener() {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let server = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let listener = tokio::net::TcpListener::bind(address).await.unwrap();
            listener.accept().await.unwrap();
        });
        wait_for_health_proxy(address).await.unwrap();
        server.await.unwrap();
    }
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
    #[tokio::test]
    async fn native_dns_probe_rejects_dns_failures() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut query = [0u8; 512];
            let (length, peer) = server.recv_from(&mut query).await.unwrap();
            query[2] = 0x81;
            query[3] = 0x82;
            server.send_to(&query[..length], peer).await.unwrap();
        });
        assert!(check_native_dns(address).await.is_err());
        task.await.unwrap();
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
        let resolve = rules
            .iter()
            .position(|rule| rule["action"] == "resolve")
            .unwrap();
        let country = rules
            .iter()
            .position(|rule| rule.get("ip_cidr") == Some(&json!(["77.88.0.0/18"])))
            .unwrap();
        assert!(
            resolve < country,
            "CIDR filtering requires resolved addresses"
        );
        assert_eq!(value["inbounds"][0]["strict_route"], false);
        assert_eq!(value["inbounds"][0]["stack"], "gvisor");
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
            doc["route"]["rules"].as_array_mut().unwrap().insert(
                0,
                json!({"inbound":["test-socks"],"action":"route","outbound":"vpn"}),
            );
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
            check_tunnel_dns(
                format!("127.0.0.1:{socks_port}").parse().unwrap(),
                config.dns.server_v4,
            )
            .await
            .unwrap();
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
