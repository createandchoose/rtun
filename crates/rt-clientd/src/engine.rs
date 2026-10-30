use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rt_dns::{DnsEvent, DnsProxyHandle, DnsSettings, ResolvedManager, TakeoverMode};
use rt_proto::{ClientConfig, TransportKind};
use rt_routing::{build_client_plan, geoip, ClientPlan, GeoIpData, RuleManager};
use rt_transport::{
    EndpointResolver, FailoverController, FailoverDecision, HealthConfig, NetworkKey,
    ObfsUdpTransport, Transport, WsConfig, WsTlsTransport,
};
use rt_tunnel::{open_tun, TunnelConfig, TunnelEvent, WgTunnel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::error::{ClientError, Result};
use crate::status::{
    set_dns, set_error, set_state, set_transport, update_metrics, ClientState, SharedStatus,
};

#[derive(Debug, Clone)]
pub struct SessionPaths {
    pub state_file: PathBuf,
    pub run_dir: PathBuf,
    pub geoip_dir: PathBuf,
    pub resolved_dropin: PathBuf,
    pub resolved_marker: PathBuf,
    pub enable_dns: bool,
}

impl Default for SessionPaths {
    fn default() -> Self {
        if cfg!(windows) {
            let base = windows_state_dir();
            return Self {
                state_file: base.join("run").join("client-state.json"),
                run_dir: base.join("run"),
                geoip_dir: base.join("geoip"),
                resolved_dropin: base.join("unused-resolved.conf"),
                resolved_marker: base.join("unused-resolved-marker.json"),
                enable_dns: false,
            };
        }
        Self {
            state_file: PathBuf::from("/run/rtun/client-state.json"),
            run_dir: PathBuf::from("/run/rtun"),
            geoip_dir: PathBuf::from("/var/lib/rtun"),
            resolved_dropin: PathBuf::from("/etc/systemd/resolved.conf.d/rtun.conf"),
            resolved_marker: PathBuf::from("/run/rtun/resolved-marker.json"),
            enable_dns: true,
        }
    }
}

pub struct SessionHandle {
    shutdown: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

impl SessionHandle {
    pub fn spawn(config: ClientConfig, paths: SessionPaths, status: SharedStatus) -> SessionHandle {
        let (shutdown, shutdown_rx) = watch::channel(false);
        let join = tokio::spawn(async move {
            if let Err(error) = run_session(config, paths, status.clone(), shutdown_rx).await {
                set_state(&status, ClientState::Degraded).await;
                set_error(&status, error.to_string()).await;
                warn!(%error, "client session stopped");
            } else {
                set_state(&status, ClientState::Disconnected).await;
            }
        });
        Self { shutdown, join }
    }

    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(8), self.join).await;
    }

    pub fn stop_signal(&self) {
        let _ = self.shutdown.send(true);
    }
}

struct Resources {
    manager: Arc<RuleManager>,
    plan: Option<ClientPlan>,
    dns: Option<DnsProxyHandle>,
    resolved: ResolvedManager,
    resolved_taken: bool,
    status: SharedStatus,
}

impl Resources {
    async fn cleanup(&mut self) {
        if let Some(dns) = self.dns.take() {
            dns.shutdown().await;
        }
        if self.resolved_taken {
            if let Err(error) = self.resolved.restore().await {
                warn!(%error, "failed to restore systemd-resolved");
            }
            self.resolved_taken = false;
        }
        if let Some(plan) = self.plan.take() {
            if let Err(error) = self.manager.cleanup_client(&plan).await {
                warn!(%error, "failed to remove routing rules");
            }
        }
        set_dns(&self.status, false, false).await;
    }
}

async fn run_session(
    config: ClientConfig,
    paths: SessionPaths,
    status: SharedStatus,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    config
        .validate()
        .map_err(|error| ClientError::Config(error.to_string()))?;
    set_state(&status, ClientState::Resolving).await;
    let manager = Arc::new(RuleManager::new(
        Arc::new(rt_routing::ProcessExecutor),
        paths.state_file.clone(),
        paths.run_dir.clone(),
    ));
    manager.recover().await?;

    let resolved = ResolvedManager::new(
        Arc::new(rt_routing::ProcessExecutor),
        paths.resolved_dropin.clone(),
        paths.resolved_marker.clone(),
    );
    let mut resources = Resources {
        manager: manager.clone(),
        plan: None,
        dns: None,
        resolved,
        resolved_taken: false,
        status: status.clone(),
    };

    let result = session_inner(&config, &paths, &status, &mut shutdown, &mut resources).await;
    resources.cleanup().await;
    result
}

async fn session_inner(
    config: &ClientConfig,
    paths: &SessionPaths,
    status: &SharedStatus,
    shutdown: &mut watch::Receiver<bool>,
    resources: &mut Resources,
) -> Result<()> {
    let resolver = EndpointResolver::new(true);
    let addresses = resolver
        .resolve(&config.endpoint.host, config.endpoint.port)
        .await?;
    if addresses.is_empty() {
        return Err(ClientError::Config("endpoint has no addresses".into()));
    }
    debug!(?addresses, "resolved endpoint");

    let (mut tunnel, mut transport, mut active_kind) =
        establish(config, &resolver, status, shutdown).await?;
    let mut peer_ip = transport.peer().map(|peer| peer.ip());
    set_transport(
        status,
        Some(active_kind),
        Some(format!("{}:{}", config.endpoint.host, config.endpoint.port)),
    )
    .await;

    let geo = geoip::load(&paths.geoip_dir).unwrap_or_default();
    if geo.is_empty() {
        warn!("GeoIP data is missing; IP routing falls back to direct lists only");
    }
    let plan = build_plan(config, &addresses, &geo)?;
    let mtu = config.device.mtu_for(active_kind);
    resources.manager.apply_kill_switch(&plan).await?;
    let device = open_tun("rtun0", mtu)?;
    let host_v4 = Ipv4Net::new(config.device.address_v4, 24)
        .map_err(|error| ClientError::Config(error.to_string()))?;
    let host_v6 = Ipv6Net::new(config.device.address_v6, 64)
        .map_err(|error| ClientError::Config(error.to_string()))?;
    resources
        .manager
        .configure_interface("rtun0", mtu, host_v4, host_v6)
        .await?;
    resources.manager.apply_client_routing(&plan).await?;
    let default_route = detect_default_route().await;
    if let Some((interface, gateway_v4, gateway_v6)) = &default_route {
        resources
            .manager
            .install_split_routes(&plan, interface, *gateway_v4, *gateway_v6)
            .await?;
    } else {
        warn!("no physical default route found; split routes are limited to LAN prefixes");
    }
    resources.plan = Some(plan.clone());

    if paths.enable_dns {
        let (dns_feedback_tx, dns_feedback_rx) = mpsc::channel::<DnsEvent>(256);
        let (dns_handle, taken, degraded) =
            start_dns(config, paths, resources, dns_feedback_tx, status).await;
        resources.dns = dns_handle;
        resources.resolved_taken = taken;
        set_dns(status, resources.dns.is_some(), degraded).await;
        spawn_dns_feedback(
            dns_feedback_rx,
            resources.manager.clone(),
            geo.clone(),
            default_route,
            plan.table_id,
        );
    } else {
        set_dns(status, false, false).await;
    }

    set_state(status, ClientState::Connected).await;
    info!(%active_kind, mtu, "tunnel established");

    let (mut tun_rx, mut tun_tx) = tokio::io::split(device);
    let health = HealthConfig::from(&config.transports);
    let mut failover =
        FailoverController::new(health, config.transports.priority.clone(), monotonic_ms());
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut network_ticker = tokio::time::interval(Duration::from_secs(30));
    network_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let health_interval = Duration::from_secs(config.transports.health_interval_secs.max(1));
    let handshake_timeout = Duration::from_millis(config.transports.handshake_timeout_ms);
    let mut last_rx = Instant::now();
    let mut handshake_started: Option<Instant> = None;
    let mut last_probe = Instant::now() - health_interval;
    let mut buffer = vec![0u8; 65_535];

    loop {
        let recv_transport = Arc::clone(&transport);
        tokio::select! {
            _ = shutdown.changed() => break,
            result = tun_rx.read(&mut buffer) => {
                let len = result?;
                if len == 0 {
                    continue;
                }
                if len > mtu as usize {
                    debug!(len, mtu, "dropping oversized TUN packet");
                    continue;
                }
                match tunnel.encrypt(&buffer[..len]) {
                    TunnelEvent::Network(packet) => {
                        if let Err(error) = transport.send(&packet).await {
                            warn!(%error, "transport send failed");
                            if let Some((new_transport, kind)) = switch_transport(
                                &mut failover,
                                config,
                                &resolver,
                                &resources.manager,
                                "rtun0",
                                status,
                            ).await {
                                transport = new_transport;
                                active_kind = kind;
                                peer_ip = transport.peer().map(|peer| peer.ip());
                                handshake_started = restart_handshake(&mut tunnel, &transport).await;
                            }
                        }
                    }
                    TunnelEvent::Ip(packet) => {
                        let _ = tun_tx.write_all(&packet).await;
                    }
                    TunnelEvent::Error(error) => debug!(%error, "tunnel encrypt error"),
                    TunnelEvent::None => {}
                }
            }
            result = recv_transport.recv() => {
                match result {
                    Ok(datagram) => {
                        last_rx = Instant::now();
                        handshake_started = None;
                        for event in tunnel.decrypt(peer_ip, &datagram) {
                            match event {
                                TunnelEvent::Network(packet) => {
                                    if let Err(error) = transport.send(&packet).await {
                                        debug!(%error, "transport reply failed");
                                    }
                                }
                                TunnelEvent::Ip(packet) => {
                                    let _ = tun_tx.write_all(&packet).await;
                                }
                                TunnelEvent::Error(error) => debug!(%error, "tunnel decrypt error"),
                                TunnelEvent::None => {}
                            }
                        }
                        if tunnel.stats().last_handshake.is_some() {
                            let state = status.read().await.state;
                            if state != ClientState::Connected {
                                set_state(status, ClientState::Connected).await;
                                failover.handshake_completed();
                            }
                        }
                        let stats = tunnel.stats();
                        update_metrics(
                            status,
                            stats.tx_bytes,
                            stats.rx_bytes,
                            stats.rtt.map(|rtt| rtt.as_secs_f64() * 1000.0),
                        ).await;
                        failover.record_success(
                            active_kind,
                            stats.rtt.map(|rtt| rtt.as_secs_f64() * 1000.0).unwrap_or(0.0),
                            monotonic_ms(),
                        );
                    }
                    Err(error) => {
                        debug!(%error, "transport receive failed");
                        if let Some((new_transport, kind)) = switch_transport(
                            &mut failover,
                            config,
                            &resolver,
                            &resources.manager,
                            "rtun0",
                            status,
                        ).await {
                            transport = new_transport;
                            active_kind = kind;
                            peer_ip = transport.peer().map(|peer| peer.ip());
                            handshake_started = restart_handshake(&mut tunnel, &transport).await;
                        }
                    }
                }
            }
            _ = network_ticker.tick() => {
                let key = detect_network().await;
                if key != *failover.network() {
                    failover.set_network(key, monotonic_ms());
                    let preferred = failover.active();
                    if preferred != active_kind {
                        if let Some((new_transport, new_kind)) = connect_kind(
                            preferred,
                            config,
                            &resolver,
                            &resources.manager,
                            "rtun0",
                            status,
                        ).await {
                            transport = new_transport;
                            active_kind = new_kind;
                            peer_ip = transport.peer().map(|peer| peer.ip());
                            handshake_started = restart_handshake(&mut tunnel, &transport).await;
                        }
                    }
                }
            }
            _ = ticker.tick() => {
                for event in tunnel.tick() {
                    if let TunnelEvent::Network(packet) = event {
                        let _ = transport.send(&packet).await;
                    }
                }
                let now = Instant::now();
                if now.duration_since(last_probe) >= health_interval {
                    last_probe = now;
                    if now.duration_since(last_rx) >= health_interval {
                        if let TunnelEvent::Network(packet) = tunnel.force_handshake() {
                            let _ = transport.send(&packet).await;
                            handshake_started = Some(now);
                        }
                    }
                }
                if let Some(started) = handshake_started {
                    if started.elapsed() >= handshake_timeout {
                        handshake_started = None;
                        match failover.record_miss(monotonic_ms()) {
                            FailoverDecision::Switch(kind) => {
                                if let Some((new_transport, new_kind)) = connect_kind(
                                    kind,
                                    config,
                                    &resolver,
                                    &resources.manager,
                                    "rtun0",
                                    status,
                                ).await {
                                    transport = new_transport;
                                    active_kind = new_kind;
                                    peer_ip = transport.peer().map(|peer| peer.ip());
                                    handshake_started = restart_handshake(&mut tunnel, &transport).await;
                                } else {
                                    set_state(status, ClientState::Degraded).await;
                                    set_error(status, format!("cannot switch to {kind}")).await;
                                }
                            }
                            FailoverDecision::GiveUp => {
                                set_state(status, ClientState::Degraded).await;
                            }
                            FailoverDecision::Stay => {}
                        }
                    }
                }
                if now.duration_since(last_rx) > health_interval * 3 {
                    set_state(status, ClientState::Degraded).await;
                }
                let stats = tunnel.stats();
                update_metrics(
                    status,
                    stats.tx_bytes,
                    stats.rx_bytes,
                    stats.rtt.map(|rtt| rtt.as_secs_f64() * 1000.0),
                ).await;
            }
        }
    }

    drop(tun_tx);
    drop(tun_rx);
    Ok(())
}

async fn restart_handshake(
    tunnel: &mut WgTunnel,
    transport: &Arc<dyn Transport>,
) -> Option<Instant> {
    if let TunnelEvent::Network(packet) = tunnel.force_handshake() {
        if transport.send(&packet).await.is_ok() {
            return Some(Instant::now());
        }
    }
    None
}

fn build_plan(
    config: &ClientConfig,
    addresses: &[std::net::SocketAddr],
    geo: &GeoIpData,
) -> Result<ClientPlan> {
    let mut direct = config
        .routing
        .direct_nets()
        .map_err(|error| ClientError::Config(error.to_string()))?;
    direct.extend(config.dns.direct_upstreams.iter().copied().map(IpNet::from));
    let overrides = config
        .routing
        .override_nets()
        .map_err(|error| ClientError::Config(error.to_string()))?;
    let endpoints = addresses
        .iter()
        .map(|address| address.ip())
        .collect::<Vec<_>>();
    let tun_v4 = Ipv4Net::new(config.device.address_v4, 24)
        .map_err(|error| ClientError::Config(error.to_string()))?
        .trunc();
    let tun_v6 = Ipv6Net::new(config.device.address_v6, 64)
        .map_err(|error| ClientError::Config(error.to_string()))?
        .trunc();
    let dns_servers = vec![
        IpAddr::V4(config.dns.server_v4),
        IpAddr::V6(config.dns.server_v6),
    ];
    build_client_plan(
        "rtun0",
        config.device.mtu_obfs,
        config.routing.mark,
        config.routing.table_id,
        direct,
        overrides,
        &endpoints,
        geo,
        tun_v4,
        tun_v6,
        &dns_servers,
        config.kill_switch,
    )
    .map_err(ClientError::Routing)
}

async fn establish(
    config: &ClientConfig,
    resolver: &EndpointResolver,
    status: &SharedStatus,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(WgTunnel, Arc<dyn Transport>, TransportKind)> {
    set_state(status, ClientState::Handshaking).await;
    let mut last_error = None;
    for kind in config.transports.priority.iter() {
        if *kind == TransportKind::WsTls {
            let delay = Duration::from_millis(config.transports.ws_start_delay_ms);
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = shutdown.changed() => return Err(ClientError::Stopped),
            }
        }
        let addresses = resolver
            .resolve(&config.endpoint.host, config.endpoint.port)
            .await?;
        let timeout = Duration::from_millis(config.transports.handshake_timeout_ms);
        if *kind == TransportKind::ObfsUdp {
            for address in addresses {
                let transport =
                    match ObfsUdpTransport::connect(address, &config.obfs, config.device.mtu_obfs)
                        .await
                    {
                        Ok(transport) => Arc::new(transport) as Arc<dyn Transport>,
                        Err(error) => {
                            last_error = Some(error.to_string());
                            continue;
                        }
                    };
                let mut tunnel = WgTunnel::new(tunnel_config(config)?);
                match handshake(&mut tunnel, &transport, timeout).await {
                    Ok(()) => {
                        info!(%kind, %address, "handshake succeeded");
                        return Ok((tunnel, transport, *kind));
                    }
                    Err(error) => {
                        last_error = Some(error.to_string());
                        transport.close().await;
                    }
                }
            }
        } else {
            let transport = match connect_ws(config, resolver).await {
                Ok(transport) => transport,
                Err(error) => {
                    last_error = Some(error.to_string());
                    continue;
                }
            };
            let mut tunnel = WgTunnel::new(tunnel_config(config)?);
            match handshake(&mut tunnel, &transport, timeout).await {
                Ok(()) => {
                    info!(%kind, "handshake succeeded");
                    return Ok((tunnel, transport, *kind));
                }
                Err(error) => {
                    last_error = Some(error.to_string());
                    transport.close().await;
                }
            }
        }
    }
    Err(ClientError::HandshakeFailed).map_err(|error| {
        if let Some(detail) = last_error {
            ClientError::Config(format!("{error}: {detail}"))
        } else {
            error
        }
    })
}

async fn connect_udp(
    config: &ClientConfig,
    addresses: &[std::net::SocketAddr],
) -> Result<Arc<dyn Transport>> {
    let mut last_error = None;
    for address in addresses {
        match ObfsUdpTransport::connect(*address, &config.obfs, config.device.mtu_obfs).await {
            Ok(transport) => return Ok(Arc::new(transport)),
            Err(error) => last_error = Some(error),
        }
    }
    Err(ClientError::Transport(last_error.unwrap_or_else(|| {
        rt_transport::TransportError::Config("no UDP endpoint address".into())
    })))
}

async fn connect_ws(
    config: &ClientConfig,
    resolver: &EndpointResolver,
) -> Result<Arc<dyn Transport>> {
    let ws = WsTlsTransport::connect(
        WsConfig::from_endpoint(&config.endpoint, config.device.mtu_ws),
        resolver,
    )
    .await?;
    Ok(Arc::new(ws))
}

async fn handshake(
    tunnel: &mut WgTunnel,
    transport: &Arc<dyn Transport>,
    timeout: Duration,
) -> Result<()> {
    let TunnelEvent::Network(init) = tunnel.force_handshake() else {
        return Err(ClientError::HandshakeFailed);
    };
    transport.send(&init).await?;
    let peer_ip = transport.peer().map(|peer| peer.ip());
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let received = tokio::time::timeout(remaining, transport.recv()).await;
        match received {
            Ok(Ok(datagram)) => {
                for event in tunnel.decrypt(peer_ip, &datagram) {
                    if let TunnelEvent::Network(packet) = event {
                        transport.send(&packet).await?;
                    }
                }
                if tunnel.stats().last_handshake.is_some() {
                    return Ok(());
                }
            }
            Ok(Err(error)) => return Err(ClientError::Transport(error)),
            Err(_) => break,
        }
    }
    Err(ClientError::HandshakeFailed)
}

async fn switch_transport(
    failover: &mut FailoverController,
    config: &ClientConfig,
    resolver: &EndpointResolver,
    manager: &Arc<RuleManager>,
    tun_name: &str,
    status: &SharedStatus,
) -> Option<(Arc<dyn Transport>, TransportKind)> {
    let decision = failover.record_miss(monotonic_ms());
    let kind = match decision {
        FailoverDecision::Switch(kind) => kind,
        FailoverDecision::GiveUp => {
            set_state(status, ClientState::Degraded).await;
            return None;
        }
        FailoverDecision::Stay => return None,
    };
    connect_kind(kind, config, resolver, manager, tun_name, status).await
}

async fn connect_kind(
    kind: TransportKind,
    config: &ClientConfig,
    resolver: &EndpointResolver,
    manager: &Arc<RuleManager>,
    tun_name: &str,
    status: &SharedStatus,
) -> Option<(Arc<dyn Transport>, TransportKind)> {
    set_state(status, ClientState::Reconnecting).await;
    let result = match kind {
        TransportKind::ObfsUdp => {
            let addresses = resolver
                .resolve(&config.endpoint.host, config.endpoint.port)
                .await
                .ok()?;
            connect_udp(config, &addresses).await
        }
        TransportKind::WsTls => connect_ws(config, resolver).await,
    };
    match result {
        Ok(transport) => {
            let mtu = config.device.mtu_for(kind);
            if let Err(error) = manager.set_link_mtu(tun_name, mtu).await {
                warn!(%error, "cannot update TUN MTU");
            }
            set_transport(
                status,
                Some(kind),
                Some(format!("{}:{}", config.endpoint.host, config.endpoint.port)),
            )
            .await;
            info!(%kind, mtu, "switched transport");
            Some((transport, kind))
        }
        Err(error) => {
            warn!(%kind, %error, "transport switch failed");
            set_error(status, format!("transport {kind} failed: {error}")).await;
            None
        }
    }
}

fn tunnel_config(config: &ClientConfig) -> Result<TunnelConfig> {
    let index = rand::random::<u32>() % 1_000_000 + 1;
    TunnelConfig::from_base64(
        &config.device.private_key,
        &config.device.peer_public_key,
        config.device.preshared_key.as_deref(),
        Some(config.device.persistent_keepalive),
        index,
    )
    .map_err(ClientError::Tunnel)
}

async fn start_dns(
    config: &ClientConfig,
    paths: &SessionPaths,
    resources: &mut Resources,
    feedback: mpsc::Sender<DnsEvent>,
    status: &SharedStatus,
) -> (Option<DnsProxyHandle>, bool, bool) {
    let resolved = ResolvedManager::new(
        Arc::new(rt_routing::ProcessExecutor),
        paths.resolved_dropin.clone(),
        paths.resolved_marker.clone(),
    );
    if let Err(error) = resolved.recover_stale().await {
        warn!(%error, "cannot recover previous resolved state");
    }
    let stub_active = resolved.is_resolved_active().await;
    let mut settings = match DnsSettings::from_config(config, false) {
        Ok(settings) => settings,
        Err(error) => {
            warn!(%error, "DNS configuration failed");
            return (None, false, true);
        }
    };
    let degraded_listen: Vec<std::net::SocketAddr> = vec![
        "127.0.0.1:5533".parse().expect("valid address"),
        "[::1]:5533".parse().expect("valid address"),
    ];

    if !stub_active {
        match rt_dns::spawn(settings.clone(), feedback.clone()).await {
            Ok(handle) => {
                resources.resolved = resolved;
                return (Some(handle), false, settings.degraded);
            }
            Err(error) => {
                warn!(%error, "cannot bind DNS listeners, trying degraded port");
                settings = settings.clone().with_listen(degraded_listen);
                settings.degraded = true;
                return match rt_dns::spawn(settings.clone(), feedback).await {
                    Ok(handle) => {
                        resources.resolved = resolved;
                        (Some(handle), false, true)
                    }
                    Err(error) => {
                        warn!(%error, "degraded DNS listener failed");
                        set_error(status, format!("DNS unavailable: {error}")).await;
                        (None, false, true)
                    }
                };
            }
        }
    }

    if let Err(error) = resolved.take_over(TakeoverMode::StubOff).await {
        warn!(%error, "cannot disable systemd-resolved stub");
    } else {
        match rt_dns::spawn(settings.clone(), feedback.clone()).await {
            Ok(handle) => {
                resources.resolved = resolved;
                return (Some(handle), true, settings.degraded);
            }
            Err(error) => {
                warn!(%error, "cannot bind DNS listeners after stub takeover");
                let _ = resolved.restore().await;
            }
        }
    }

    settings = settings.with_listen(degraded_listen);
    settings.degraded = true;
    match rt_dns::spawn(settings.clone(), feedback).await {
        Ok(handle) => {
            let taken = match resolved.take_over(TakeoverMode::Degraded5533).await {
                Ok(()) => true,
                Err(error) => {
                    warn!(%error, "cannot configure systemd-resolved fallback");
                    false
                }
            };
            resources.resolved = resolved;
            (Some(handle), taken, true)
        }
        Err(error) => {
            warn!(%error, "degraded DNS listener failed");
            set_error(status, format!("DNS unavailable: {error}")).await;
            (None, false, true)
        }
    }
}

fn spawn_dns_feedback(
    mut rx: mpsc::Receiver<DnsEvent>,
    manager: Arc<RuleManager>,
    geo: GeoIpData,
    default_route: Option<(
        String,
        Option<std::net::Ipv4Addr>,
        Option<std::net::Ipv6Addr>,
    )>,
    table_id: u32,
) {
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let timeout = Some(u64::from(event.ttl).clamp(30, 3600));
            let (mut v4, mut v6) = (Vec::new(), Vec::new());
            for address in &event.addresses {
                let net = match address {
                    IpAddr::V4(ip) => IpNet::V4(Ipv4Net::new(*ip, 32).expect("valid prefix")),
                    IpAddr::V6(ip) => IpNet::V6(Ipv6Net::new(*ip, 128).expect("valid prefix")),
                };
                match address {
                    IpAddr::V4(_) => v4.push(net),
                    IpAddr::V6(_) => v6.push(net),
                }
            }
            let result = if event.direct_domain {
                if let Err(error) = manager.add_direct(&v4, &v6, timeout).await {
                    debug!(%error, "failed to add direct DNS set entries");
                }
                if let Some((interface, gateway_v4, gateway_v6)) = &default_route {
                    let nets = v4.iter().chain(v6.iter()).copied().collect::<Vec<_>>();
                    manager
                        .add_dynamic_direct_routes(
                            &nets,
                            interface,
                            *gateway_v4,
                            *gateway_v6,
                            table_id,
                        )
                        .await
                } else {
                    Ok(())
                }
            } else {
                let mut override_v4 = Vec::new();
                let mut override_v6 = Vec::new();
                for net in v4.iter().chain(v6.iter()) {
                    let is_ru = match net.addr() {
                        IpAddr::V4(_) => geo.v4.iter().any(|geo_net| geo_net.contains(&net.addr())),
                        IpAddr::V6(_) => geo.v6.iter().any(|geo_net| geo_net.contains(&net.addr())),
                    };
                    if is_ru {
                        match net.addr() {
                            IpAddr::V4(_) => override_v4.push(*net),
                            IpAddr::V6(_) => override_v6.push(*net),
                        }
                    }
                }
                if let Err(error) = manager
                    .add_override(&override_v4, &override_v6, timeout)
                    .await
                {
                    debug!(%error, "failed to add override DNS set entries");
                }
                let nets = override_v4
                    .iter()
                    .chain(override_v6.iter())
                    .copied()
                    .collect::<Vec<_>>();
                if nets.is_empty() {
                    Ok(())
                } else {
                    manager
                        .add_dynamic_override_routes(&nets, "rtun0", table_id)
                        .await
                }
            };
            if let Err(error) = result {
                debug!(%error, "failed to update routing sets from DNS");
            }
        }
    });
}

/// Per-user state directory on Windows, `%APPDATA%\RTUN`.
pub fn windows_state_dir() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("RTUN")
}

async fn detect_default_route() -> Option<(
    String,
    Option<std::net::Ipv4Addr>,
    Option<std::net::Ipv6Addr>,
)> {
    if cfg!(windows) {
        // On Windows the adapter index travels in the interface slot.
        let physical = rt_routing::win::detect_physical(&rt_routing::ProcessExecutor).await?;
        return Some((physical.index.to_string(), physical.gateway, None));
    }
    let mut interface = None;
    let mut gateway_v4 = None;
    let mut gateway_v6 = None;
    for family in ["-4", "-6"] {
        let output = tokio::process::Command::new("ip")
            .args([family, "route", "show", "default"])
            .output()
            .await
            .ok()?;
        if !output.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let Some(line) = text.lines().next() else {
            continue;
        };
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        let dev = tokens
            .iter()
            .position(|token| *token == "dev")
            .and_then(|index| tokens.get(index + 1))
            .map(|value| value.to_string());
        let via = tokens
            .iter()
            .position(|token| *token == "via")
            .and_then(|index| tokens.get(index + 1));
        if interface.is_none() {
            interface = dev.clone();
        }
        if family == "-4" {
            gateway_v4 = via.and_then(|value| value.parse().ok());
        } else {
            gateway_v6 = via.and_then(|value| value.parse().ok());
        }
    }
    interface.map(|interface| (interface, gateway_v4, gateway_v6))
}

async fn detect_network() -> NetworkKey {
    let gateway = tokio::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .await
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            let text = String::from_utf8_lossy(&output.stdout).to_string();
            text.split_whitespace()
                .skip_while(|token| *token != "via")
                .nth(1)
                .map(str::to_string)
        });
    let ssid = tokio::process::Command::new("iwgetid")
        .arg("-r")
        .output()
        .await
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if value.is_empty() {
                None
            } else {
                Some(value)
            }
        });
    NetworkKey::new(ssid, gateway)
}

fn monotonic_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

pub fn default_paths() -> SessionPaths {
    SessionPaths::default()
}

pub fn default_geoip_dir() -> &'static Path {
    Path::new("/var/lib/rtun")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rt_proto::{ClientConfig, DeviceConfig, EndpointConfig, TransportPrefs};

    fn config() -> ClientConfig {
        let private = rt_proto::keys::generate_private_key();
        let public = rt_proto::keys::public_key_from_private(&private).unwrap();
        ClientConfig {
            endpoint: EndpointConfig {
                host: "vpn.example.com".into(),
                ..EndpointConfig::default()
            },
            device: DeviceConfig {
                private_key: private,
                peer_public_key: public,
                ..DeviceConfig::default()
            },
            transports: TransportPrefs::default(),
            ..ClientConfig::default()
        }
    }

    #[test]
    fn plan_contains_endpoint_and_tunnel_override() {
        let config = config();
        let addresses = vec!["8.8.8.8:443".parse().unwrap()];
        let plan = build_plan(&config, &addresses, &GeoIpData::default()).unwrap();
        assert!(plan.direct4.contains(&"8.8.8.8/32".parse().unwrap()));
        assert!(plan.override4.contains(&"10.66.0.0/24".parse().unwrap()));
        assert_eq!(plan.mark, 1);
        assert!(plan.kill_switch);
    }

    #[test]
    fn tunnel_config_rejects_empty_keys() {
        let mut config = config();
        config.device.private_key.clear();
        assert!(tunnel_config(&config).is_err());
    }
}
