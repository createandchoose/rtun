//! Настройка системы под туннель через netsh и откат при выходе.
//! Маршруты и DNS удаляются явно; адаптер wintun уничтожается вместе с
//! устройством, поэтому его отдельно не трогаем.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ipnet::{IpNet, Ipv4Net};
use rt_proto::ClientConfig;
use rt_routing::manager::CommandExecutor;
use rt_routing::nft::ClientPlan;
use rt_routing::win::{self, PhysicalRoute, WinRoute};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::error::ClientWinError;
use crate::plan::{dns_args, metric_args, tun_addresses, TUN_NAME};

pub struct Setup {
    executor: Arc<dyn CommandExecutor>,
    /// Маршруты, которые уже могли быть добавлены. Удаляются в обратном порядке.
    routes: Mutex<Vec<WinRoute>>,
    closed: std::sync::atomic::AtomicBool,
}

impl Setup {
    pub fn new(executor: Arc<dyn CommandExecutor>) -> Self {
        Self {
            executor,
            routes: Mutex::new(Vec::new()),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Закрепляет маршруты до адресов сервера за физическим адаптером. Нужно
    /// до рукопожатия, иначе туннель и сервер могут быть недоступны из-за
    /// других VPN с маршрутом по умолчанию.
    pub async fn bypass_endpoints(
        &self,
        addresses: &[SocketAddr],
        physical: &PhysicalRoute,
    ) -> Result<(), ClientWinError> {
        let Some(gateway) = physical.gateway else {
            return Err(ClientWinError::NoPhysicalRoute);
        };
        for address in addresses {
            // Физический шлюз получен только для IPv4, поэтому IPv6-эндпоинт
            // здесь пропускаем: его маршрут уйдет через общий план.
            let IpAddr::V4(ip) = address.ip() else {
                continue;
            };
            let net = IpNet::V4(Ipv4Net::new(ip, 32).expect("/32 is valid"));
            self.add_route(WinRoute {
                net,
                nexthop: IpAddr::V4(gateway),
                interface: physical.index.to_string(),
            })
            .await?;
        }
        Ok(())
    }

    /// Настраивает адаптер, DNS и маршруты. Вызывается после открытия TUN.
    pub async fn configure(
        &self,
        config: &ClientConfig,
        plan: &ClientPlan,
        physical: &PhysicalRoute,
    ) -> Result<(), ClientWinError> {
        let (v4, v6) = tun_addresses(config)?;
        let mtu = config.device.mtu_obfs;

        self.netsh(&win::mtu_args(TUN_NAME, mtu)).await?;
        self.netsh_retry(&win::ipv4_address_args(TUN_NAME, v4))
            .await?;
        self.netsh_retry(&win::ipv6_address_args(TUN_NAME, v6))
            .await?;

        let dns_v4 = if config.routing.smart_routing {
            "127.0.0.1".parse().unwrap()
        } else {
            config.dns.server_v4
        };
        let dns_v6 = if config.routing.smart_routing {
            "::1".parse().unwrap()
        } else {
            config.dns.server_v6
        };
        self.netsh(&dns_args(dns_v4.into())).await?;
        self.netsh(&dns_args(dns_v6.into())).await?;
        // Метрика не обязательна: без нее DNS может уходить и в обычную сеть.
        if let Err(error) = self.netsh(&metric_args()).await {
            warn!(%error, "cannot set tunnel interface metric; DNS may leak to the local network");
        }

        for route in win::route_plan(plan, physical) {
            self.add_route(route).await?;
        }
        Ok(())
    }

    /// Удаляет все маршруты, которые успели добавиться. Ошибки логируются:
    /// откат не должен падать из-за уже отсутствующего маршрута.
    pub async fn teardown(&self) {
        let mut routes = self.routes.lock().await;
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        while let Some(route) = routes.pop() {
            let args = win::route_args("delete", &route);
            if let Err(error) = win::run(self.executor.as_ref(), &args).await {
                debug!(%error, net = %route.net, "route removal failed");
            }
        }
    }

    pub async fn add_route(&self, route: WinRoute) -> Result<(), ClientWinError> {
        let mut routes = self.routes.lock().await;
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ClientWinError::Config("session is stopping".into()));
        }
        if routes.contains(&route) {
            return Ok(());
        }
        // Старый маршрут от прерванного запуска может остаться и заблокировать add.
        let _ = win::run(self.executor.as_ref(), &win::route_args("delete", &route)).await;
        self.netsh(&win::route_args("add", &route)).await?;
        routes.push(route);
        Ok(())
    }

    async fn netsh(&self, args: &[String]) -> Result<(), ClientWinError> {
        win::run(self.executor.as_ref(), args)
            .await
            .map_err(ClientWinError::Routing)
    }

    async fn netsh_retry(&self, args: &[String]) -> Result<(), ClientWinError> {
        win::run_with_retry(self.executor.as_ref(), args)
            .await
            .map_err(ClientWinError::Routing)
    }
}
