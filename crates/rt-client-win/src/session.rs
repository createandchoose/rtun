//! Жизненный цикл туннеля: подключение с повторами, настройка системы,
//! цикл пересылки пакетов и откат. При обрыве туннель поднимается заново.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rt_proto::{ClientConfig, TransportKind};
use rt_routing::geoip::GeoIpData;
use rt_routing::manager::CommandExecutor;
use rt_routing::win::{self, PhysicalRoute};
use rt_transport::{EndpointResolver, ObfsUdpTransport, Transport};
use rt_tunnel::{open_tun, TunnelEvent, WgTunnel};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::error::ClientWinError;
use crate::plan::{build_plan, tunnel_config, TUN_NAME};
use crate::setup::Setup;
use crate::status::{explain, TunnelState};

const RECONNECT_MIN: Duration = Duration::from_secs(2);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// Без входящих пакетов дольше этого срока туннель считается мертвым.
const DEAD_AFTER: Duration = Duration::from_secs(25);
/// Повторный handshake, если тишина дольше этого срока.
const KEEPALIVE_PROBE: Duration = Duration::from_secs(5);

#[derive(Debug, PartialEq, Eq)]
enum SessionEnd {
    Shutdown,
    Lost,
}

/// Держит туннель до сигнала остановки. Ошибки подключения повторяются
/// с растущей паузой, обрыв уже работавшего туннеля — с минимальной.
/// Состояние публикуется в `status`.
pub async fn run(
    config: ClientConfig,
    executor: Arc<dyn CommandExecutor>,
    mut shutdown: watch::Receiver<bool>,
    status: watch::Sender<TunnelState>,
) -> Result<(), ClientWinError> {
    config
        .validate()
        .map_err(|error| ClientWinError::Config(error.to_string()))?;
    if !config.transports.priority.contains(&TransportKind::ObfsUdp) {
        return Err(ClientWinError::Config(
            "the Windows client needs obfs-udp in transports.priority".into(),
        ));
    }

    let resolver = EndpointResolver::new(true);
    let mut backoff = RECONNECT_MIN;
    loop {
        if *shutdown.borrow() {
            break;
        }
        status.send_replace(TunnelState::Connecting);
        match session(&config, &resolver, executor.clone(), &mut shutdown, &status).await {
            Ok(SessionEnd::Shutdown) => break,
            Ok(SessionEnd::Lost) => {
                warn!("tunnel lost, reconnecting");
                backoff = RECONNECT_MIN;
                status.send_replace(TunnelState::Reconnecting {
                    reason: "Связь с сервером потеряна.".into(),
                    retry_in_secs: backoff.as_secs(),
                });
            }
            Err(error) => {
                warn!(%error, retry_in = ?backoff, "session failed");
                status.send_replace(TunnelState::Reconnecting {
                    reason: explain(&error),
                    retry_in_secs: backoff.as_secs(),
                });
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown.changed() => break,
        }
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
    status.send_replace(TunnelState::Stopping);
    status.send_replace(TunnelState::Idle);
    Ok(())
}

async fn session(
    config: &ClientConfig,
    resolver: &EndpointResolver,
    executor: Arc<dyn CommandExecutor>,
    shutdown: &mut watch::Receiver<bool>,
    status: &watch::Sender<TunnelState>,
) -> Result<SessionEnd, ClientWinError> {
    let addresses = resolver
        .resolve(&config.endpoint.host, config.endpoint.port)
        .await?;
    if addresses.is_empty() {
        return Err(ClientWinError::Config("endpoint has no addresses".into()));
    }

    // Физический маршрут берем до того, как TUN станет маршрутом по умолчанию.
    let physical = win::detect_physical(executor.as_ref())
        .await
        .ok_or(ClientWinError::NoPhysicalRoute)?;

    // Маршрут до сервера должен быть закреплен за физическим адаптером ДО
    // рукопожатия: иначе пакеты уйдут через чужой VPN (например sing-tun).
    let mut setup = Setup::new(executor);
    let outcome = session_inner(config, &addresses, &physical, &mut setup, shutdown, status).await;
    setup.teardown().await;
    outcome
}

async fn session_inner(
    config: &ClientConfig,
    addresses: &[SocketAddr],
    physical: &PhysicalRoute,
    setup: &mut Setup,
    shutdown: &mut watch::Receiver<bool>,
    status: &watch::Sender<TunnelState>,
) -> Result<SessionEnd, ClientWinError> {
    setup.bypass_endpoints(addresses, physical).await?;

    let endpoint = format!("{}:{}", config.endpoint.host, config.endpoint.port);
    status.send_replace(TunnelState::Handshaking {
        endpoint: endpoint.clone(),
    });
    let (tunnel, transport, peer) = connect(config, addresses).await?;
    info!(%peer, "handshake succeeded");

    let plan = build_plan(config, addresses, &GeoIpData::default())?;
    let device = open_tun(TUN_NAME, config.device.mtu_obfs)?;
    setup.configure(config, &plan, physical).await?;
    info!(interface = TUN_NAME, "routes and DNS installed");
    status.send_replace(TunnelState::Connected {
        endpoint,
        tunnel_ip: config.device.address_v4.to_string(),
        since: Instant::now(),
    });
    pump(device, tunnel, transport, peer, config, shutdown).await
}

/// Пробует все адреса эндпоинта по очереди. Возвращает туннель с готовым
/// handshake и транспорт.
async fn connect(
    config: &ClientConfig,
    addresses: &[SocketAddr],
) -> Result<(WgTunnel, Arc<dyn Transport>, SocketAddr), ClientWinError> {
    let timeout = Duration::from_millis(config.transports.handshake_timeout_ms);
    let mut last_error = String::from("no address worked");
    for address in addresses {
        let transport =
            match ObfsUdpTransport::connect(*address, &config.obfs, config.device.mtu_obfs).await {
                Ok(transport) => Arc::new(transport) as Arc<dyn Transport>,
                Err(error) => {
                    last_error = format!("{address}: {error}");
                    continue;
                }
            };
        let mut tunnel = WgTunnel::new(tunnel_config(config)?);
        match handshake(&mut tunnel, &transport, timeout).await {
            Ok(()) => return Ok((tunnel, transport, *address)),
            Err(error) => {
                last_error = format!("{address}: {error}");
                transport.close().await;
            }
        }
    }
    Err(ClientWinError::Handshake(last_error))
}

async fn handshake(
    tunnel: &mut WgTunnel,
    transport: &Arc<dyn Transport>,
    timeout: Duration,
) -> Result<(), ClientWinError> {
    let TunnelEvent::Network(init) = tunnel.force_handshake() else {
        return Err(ClientWinError::Handshake("cannot start handshake".into()));
    };
    transport.send(&init).await?;
    let peer_ip = transport.peer().map(|peer| peer.ip());
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, transport.recv()).await {
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
            Ok(Err(error)) => return Err(ClientWinError::Transport(error)),
            Err(_) => break,
        }
    }
    Err(ClientWinError::Handshake("timed out".into()))
}

/// Перекачивает пакеты между TUN и транспортом, пока туннель жив.
async fn pump<D>(
    device: D,
    mut tunnel: WgTunnel,
    transport: Arc<dyn Transport>,
    peer: SocketAddr,
    config: &ClientConfig,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<SessionEnd, ClientWinError>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mtu = config.device.mtu_obfs as usize;
    let peer_ip = Some(peer.ip());
    let (mut tun_rx, mut tun_tx) = tokio::io::split(device);
    let mut buffer = vec![0u8; 65_535];
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_rx = Instant::now();
    let mut last_probe = Instant::now();

    loop {
        let recv_transport = Arc::clone(&transport);
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(SessionEnd::Shutdown);
                }
            }
            result = tun_rx.read(&mut buffer) => {
                let len = result?;
                if len == 0 || len > mtu {
                    continue;
                }
                match tunnel.encrypt(&buffer[..len]) {
                    TunnelEvent::Network(packet) => {
                        if let Err(error) = transport.send(&packet).await {
                            debug!(%error, "transport send failed");
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
                    }
                    // Ошибка приема на UDP (например, ICMP unreachable в Windows)
                    // не означает обрыв: решает DEAD_AFTER.
                    Err(error) => {
                        debug!(%error, "transport receive failed");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            }
            _ = ticker.tick() => {
                for event in tunnel.tick() {
                    if let TunnelEvent::Network(packet) = event {
                        let _ = transport.send(&packet).await;
                    }
                }
                let silent = last_rx.elapsed();
                if silent >= DEAD_AFTER {
                    return Ok(SessionEnd::Lost);
                }
                if silent >= KEEPALIVE_PROBE && last_probe.elapsed() >= KEEPALIVE_PROBE {
                    last_probe = Instant::now();
                    if let TunnelEvent::Network(packet) = tunnel.force_handshake() {
                        let _ = transport.send(&packet).await;
                    }
                }
            }
        }
    }
}
