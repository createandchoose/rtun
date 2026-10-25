//! Windows routing backend.
//!
//! Interfaces and routes are configured with `netsh`, which ships with every
//! supported Windows release, so the client needs nothing beyond the wintun
//! adapter that the TUN crate creates. The argument builders are pure and are
//! unit-tested on every platform; only `detect_physical` and `run` touch the
//! system.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::error::{Result, RoutingError};
use crate::manager::CommandExecutor;
use crate::nft::ClientPlan;

const TUNNEL_HALVES_V4: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];
const TUNNEL_HALVES_V6: [&str; 2] = ["::/1", "8000::/1"];

/// Default route of the physical network, captured before the tunnel starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalRoute {
    pub index: u32,
    pub gateway: Option<Ipv4Addr>,
}

/// One route installed through `netsh`. `interface` is either the TUN adapter
/// name or the numeric index of the physical adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinRoute {
    pub net: IpNet,
    pub nexthop: IpAddr,
    pub interface: String,
}

/// Routes for the tunnel: direct prefixes (including the endpoint) leave via
/// the physical gateway, the TUN subnet and everything else via the tunnel.
/// Order matters only for the endpoint: its host route must exist before the
/// `/1` halves capture the default route.
pub fn route_plan(plan: &ClientPlan, physical: &PhysicalRoute) -> Vec<WinRoute> {
    let mut routes = Vec::new();
    if let Some(gateway) = physical.gateway {
        for net in &plan.direct4 {
            if is_skipped(net) {
                continue;
            }
            routes.push(WinRoute {
                net: *net,
                nexthop: IpAddr::V4(gateway),
                interface: physical.index.to_string(),
            });
        }
    }
    // Link-local and multicast IPv6 must stay on the physical link; the
    // tunnel's `::/1` halves would otherwise capture them and the server drops them.
    for net in ["fe80::/10", "ff00::/8"] {
        routes.push(WinRoute {
            net: net.parse().expect("valid IPv6 prefix"),
            nexthop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            interface: physical.index.to_string(),
        });
    }
    for net in &plan.override4 {
        routes.push(WinRoute {
            net: *net,
            nexthop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            interface: plan.tun_name.clone(),
        });
    }
    for half in TUNNEL_HALVES_V4 {
        routes.push(WinRoute {
            net: half.parse().expect("valid IPv4 half"),
            nexthop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            interface: plan.tun_name.clone(),
        });
    }
    for half in TUNNEL_HALVES_V6 {
        routes.push(WinRoute {
            net: half.parse().expect("valid IPv6 half"),
            nexthop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            interface: plan.tun_name.clone(),
        });
    }
    routes
}

/// Routes that must stay with the OS: unspecified, loopback, link-local,
/// multicast and broadcast. Direct IPv6 prefixes are covered by the tunnel.
fn is_skipped(net: &IpNet) -> bool {
    match net.addr() {
        IpAddr::V4(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
        }
        IpAddr::V6(_) => true,
    }
}

/// True for the `/1` halves that capture the default route.
pub fn is_tunnel_half(route: &WinRoute) -> bool {
    route.net.prefix_len() == 1 && route.nexthop.is_unspecified()
}

pub fn route_args(action: &str, route: &WinRoute) -> Vec<String> {
    let family = match route.net {
        IpNet::V4(_) => "ipv4",
        IpNet::V6(_) => "ipv6",
    };
    let mut args = vec![
        "interface".to_string(),
        family.to_string(),
        action.to_string(),
        "route".to_string(),
        format!("prefix={}", route.net),
        format!("interface={}", route.interface),
        format!("nexthop={}", route.nexthop),
    ];
    if action == "add" {
        args.push("store=active".to_string());
    }
    args
}

pub fn ipv4_address_args(tun: &str, v4: Ipv4Net) -> Vec<String> {
    vec![
        "interface".into(),
        "ipv4".into(),
        "set".into(),
        "address".into(),
        format!("name={tun}"),
        "source=static".into(),
        format!("address={}", v4.addr()),
        format!("mask={}", v4.netmask()),
        "store=active".into(),
    ]
}

pub fn ipv6_address_args(tun: &str, v6: Ipv6Net) -> Vec<String> {
    vec![
        "interface".into(),
        "ipv6".into(),
        "add".into(),
        "address".into(),
        format!("interface={tun}"),
        format!("address={v6}"),
        "store=active".into(),
    ]
}

pub fn mtu_args(tun: &str, mtu: u16) -> Vec<String> {
    vec![
        "interface".into(),
        "ipv4".into(),
        "set".into(),
        "subinterface".into(),
        format!("interface={tun}"),
        format!("mtu={mtu}"),
        "store=active".into(),
    ]
}

/// Runs `netsh` and maps a non-zero exit to an error. netsh reports most
/// failures on stdout, so both streams are kept for the message.
pub async fn run(executor: &dyn CommandExecutor, args: &[String]) -> Result<()> {
    let output = executor.run("netsh", args).await?;
    if output.status == 0 {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Err(RoutingError::Command {
        program: "netsh".into(),
        args: args.to_vec(),
        stderr: if stderr.is_empty() { stdout } else { stderr },
    })
}

/// Same as [`run`], retried a few times. Used right after the adapter is
/// created, when Windows may not expose it to netsh yet.
pub async fn run_with_retry(executor: &dyn CommandExecutor, args: &[String]) -> Result<()> {
    let mut last = None;
    for attempt in 0..5 {
        match run(executor, args).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                last = Some(error);
                if attempt < 4 {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
        }
    }
    Err(last.expect("at least one attempt"))
}

/// Finds the best physical IPv4 default route. The TUN adapter has no default
/// route yet when this runs, so the result is the real network.
pub async fn detect_physical(executor: &dyn CommandExecutor) -> Option<PhysicalRoute> {
    const SCRIPT: &str = "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' \
        | Where-Object { $_.NextHop -ne '0.0.0.0' } \
        | Sort-Object { $_.RouteMetric + $_.InterfaceMetric } \
        | Select-Object -First 1 \
        | ForEach-Object { '{0} {1}' -f $_.InterfaceIndex, $_.NextHop }";
    let output = executor
        .run(
            "powershell",
            &[
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                SCRIPT.to_string(),
            ],
        )
        .await
        .ok()?;
    if output.status != 0 {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut tokens = text.split_whitespace();
    let index = tokens.next()?.parse().ok()?;
    let gateway = tokens.next().and_then(|value| value.parse().ok());
    Some(PhysicalRoute { index, gateway })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nft::build_client_plan;
    use crate::GeoIpData;

    fn plan() -> ClientPlan {
        build_client_plan(
            "rtun0",
            1360,
            0x1,
            51820,
            vec!["192.0.2.0/24".parse().unwrap()],
            Vec::new(),
            &["203.0.113.7".parse().unwrap()],
            &GeoIpData::default(),
            Ipv4Net::new(Ipv4Addr::new(10, 66, 0, 2), 24)
                .unwrap()
                .trunc(),
            Ipv6Net::new("fd66:1::2".parse().unwrap(), 64)
                .unwrap()
                .trunc(),
            &[],
            false,
        )
        .unwrap()
    }

    fn physical() -> PhysicalRoute {
        PhysicalRoute {
            index: 7,
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
        }
    }

    #[test]
    fn endpoint_is_routed_outside_the_tunnel() {
        let routes = route_plan(&plan(), &physical());
        let endpoint = routes
            .iter()
            .find(|route| route.net.to_string() == "203.0.113.7/32")
            .expect("endpoint route");
        assert_eq!(endpoint.interface, "7");
        assert_eq!(endpoint.nexthop, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn tunnel_halves_capture_default_route_after_direct_routes() {
        let routes = route_plan(&plan(), &physical());
        let first_half = routes.iter().position(is_tunnel_half).expect("half");
        let endpoint = routes
            .iter()
            .position(|route| route.net.to_string() == "203.0.113.7/32")
            .expect("endpoint");
        assert!(endpoint < first_half);
        let halves = routes
            .iter()
            .filter(|route| is_tunnel_half(route) && route.net.addr().is_ipv4())
            .count();
        assert_eq!(halves, 2);
    }

    #[test]
    fn without_gateway_only_tunnel_routes_are_installed() {
        let physical = PhysicalRoute {
            index: 7,
            gateway: None,
        };
        let routes = route_plan(&plan(), &physical);
        assert!(routes
            .iter()
            .filter(|route| route.net.addr().is_ipv4())
            .all(|route| route.interface == "rtun0"));
    }

    #[test]
    fn route_args_match_netsh_syntax() {
        let route = WinRoute {
            net: "0.0.0.0/1".parse().unwrap(),
            nexthop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            interface: "rtun0".into(),
        };
        assert_eq!(
            route_args("add", &route),
            vec![
                "interface",
                "ipv4",
                "add",
                "route",
                "prefix=0.0.0.0/1",
                "interface=rtun0",
                "nexthop=0.0.0.0",
                "store=active",
            ]
        );
        assert!(!route_args("delete", &route).contains(&"store=active".to_string()));
    }

    #[test]
    fn address_args_use_host_address_and_mask() {
        let args = ipv4_address_args(
            "rtun0",
            Ipv4Net::new(Ipv4Addr::new(10, 66, 0, 2), 24).unwrap(),
        );
        assert!(args.contains(&"address=10.66.0.2".to_string()));
        assert!(args.contains(&"mask=255.255.255.0".to_string()));
    }
}
