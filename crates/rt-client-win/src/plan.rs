//! Подготовка данных для туннеля: план маршрутов, параметры WireGuard,
//! DNS-аргументы netsh и загрузка конфига из .conf или client.toml.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rt_proto::wgconf::WgConf;
use rt_proto::ClientConfig;
use rt_routing::geoip::GeoIpData;
use rt_routing::nft::{build_client_plan, ClientPlan};
use rt_tunnel::TunnelConfig;

use crate::error::ClientWinError;

pub const TUN_NAME: &str = "rtun0";

/// Загружает клиентский конфиг. `.conf` читается как WireGuard-подобный
/// файл с секцией [Rtun], остальное — как client.toml.
pub fn load_config(path: &Path) -> Result<ClientConfig, ClientWinError> {
    let is_wg = path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("conf"));
    if is_wg {
        WgConf::load(path)
            .and_then(WgConf::into_client)
            .map_err(|error| ClientWinError::Config(error.to_string()))
    } else {
        ClientConfig::load(path).map_err(|error| ClientWinError::Config(error.to_string()))
    }
}

/// План маршрутов: прямые префиксы, эндпоинт сервера, туннельная подсеть.
/// GeoIP пока пустой: на Windows база RU-префиксов не загружается.
pub fn build_plan(
    config: &ClientConfig,
    endpoints: &[SocketAddr],
    geo: &GeoIpData,
) -> Result<ClientPlan, ClientWinError> {
    let mut direct = config
        .routing
        .direct_nets()
        .map_err(|error| ClientWinError::Config(error.to_string()))?;
    direct.extend(config.dns.direct_upstreams.iter().copied().map(IpNet::from));
    let overrides = config
        .routing
        .override_nets()
        .map_err(|error| ClientWinError::Config(error.to_string()))?;
    let endpoint_ips: Vec<IpAddr> = endpoints.iter().map(SocketAddr::ip).collect();
    let tun_v4 = Ipv4Net::new(config.device.address_v4, 24)
        .map_err(|error| ClientWinError::Config(error.to_string()))?
        .trunc();
    let tun_v6 = Ipv6Net::new(config.device.address_v6, 64)
        .map_err(|error| ClientWinError::Config(error.to_string()))?
        .trunc();
    let dns_servers = [
        IpAddr::V4(config.dns.server_v4),
        IpAddr::V6(config.dns.server_v6),
    ];
    build_client_plan(
        TUN_NAME,
        config.device.mtu_obfs,
        config.routing.mark,
        config.routing.table_id,
        direct,
        overrides,
        &endpoint_ips,
        geo,
        tun_v4,
        tun_v6,
        &dns_servers,
        config.kill_switch,
    )
    .map_err(ClientWinError::Routing)
}

/// Параметры WireGuard. Индекс случайный: он нужен только внутри процесса.
pub fn tunnel_config(config: &ClientConfig) -> Result<TunnelConfig, ClientWinError> {
    let index = rand::random::<u32>() % 1_000_000 + 1;
    TunnelConfig::from_base64(
        &config.device.private_key,
        &config.device.peer_public_key,
        config.device.preshared_key.as_deref(),
        Some(config.device.persistent_keepalive),
        index,
    )
    .map_err(ClientWinError::Tunnel)
}

/// Аргументы netsh, которые ставят DNS туннельного сервера на адаптер.
pub fn dns_args(server: IpAddr) -> Vec<String> {
    let family = match server {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    };
    vec![
        "interface".into(),
        family.into(),
        "set".into(),
        "dnsservers".into(),
        format!("name={TUN_NAME}"),
        "source=static".into(),
        format!("address={server}"),
        "register=none".into(),
        "validate=no".into(),
    ]
}

/// Аргументы netsh, которые ставят приоритет адаптера туннеля.
/// Низкая метрика заставляет Windows предпочитать DNS туннеля.
pub fn metric_args() -> Vec<String> {
    vec![
        "interface".into(),
        "ipv4".into(),
        "set".into(),
        "interface".into(),
        format!("interface={TUN_NAME}"),
        "metric=1".into(),
    ]
}

/// Адрес туннеля для адаптера: /24 для IPv4 и /64 для IPv6.
pub fn tun_addresses(config: &ClientConfig) -> Result<(Ipv4Net, Ipv6Net), ClientWinError> {
    let v4 = Ipv4Net::new(config.device.address_v4, 24)
        .map_err(|error| ClientWinError::Config(error.to_string()))?;
    let v6 = Ipv6Net::new(config.device.address_v6, 64)
        .map_err(|error| ClientWinError::Config(error.to_string()))?;
    Ok((v4, v6))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn dns_args_pick_family_and_target_adapter() {
        let v4 = dns_args(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1)));
        assert_eq!(v4[1], "ipv4");
        assert!(v4.contains(&"name=rtun0".to_string()));
        assert!(v4.contains(&"address=10.66.0.1".to_string()));

        let v6 = dns_args(IpAddr::V6("fd66:1::1".parse().unwrap()));
        assert_eq!(v6[1], "ipv6");
        assert!(v6.contains(&"address=fd66:1::1".to_string()));
    }

    #[test]
    fn default_config_builds_a_plan_with_endpoint_direct() {
        let mut config = ClientConfig::default();
        config.device.private_key = rt_proto::generate_private_key();
        config.device.peer_public_key =
            rt_proto::public_key_from_private(&rt_proto::generate_private_key()).unwrap();
        config.endpoint.host = "vpn.example.com".into();
        let endpoint: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let plan = build_plan(&config, &[endpoint], &GeoIpData::default()).unwrap();
        assert!(plan
            .direct4
            .iter()
            .any(|net| net.to_string() == "203.0.113.10/32"));
        assert_eq!(plan.tun_name, TUN_NAME);
    }
}
