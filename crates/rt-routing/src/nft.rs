use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::error::{Result, RoutingError};
use crate::geoip::GeoIpData;

pub const TUN_V4: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 0);
pub const TUN_V4_PREFIX: u8 = 24;
pub const TUN_V6_PREFIX: u8 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPlan {
    pub tun_name: String,
    pub mtu: u16,
    pub mark: u32,
    pub table_id: u32,
    pub direct4: Vec<IpNet>,
    pub direct6: Vec<IpNet>,
    pub override4: Vec<IpNet>,
    pub override6: Vec<IpNet>,
    pub kill_switch: bool,
    pub tun_v4: Ipv4Net,
    pub tun_v6: Ipv6Net,
    pub dns_servers: Vec<IpAddr>,
}

impl ClientPlan {
    pub fn internal_v4(&self) -> IpNet {
        IpNet::V4(self.tun_v4)
    }

    pub fn internal_v6(&self) -> IpNet {
        IpNet::V6(self.tun_v6)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_client_plan(
    tun_name: &str,
    mtu: u16,
    mark: u32,
    table_id: u32,
    direct: Vec<IpNet>,
    endpoint_override: Vec<IpNet>,
    endpoints: &[IpAddr],
    geo: &GeoIpData,
    tun_v4: Ipv4Net,
    tun_v6: Ipv6Net,
    dns_servers: &[IpAddr],
    kill_switch: bool,
) -> Result<ClientPlan> {
    if tun_name.is_empty() || mark == 0 || table_id == 0 {
        return Err(RoutingError::Config(
            "tun name, mark and table id must be non-zero".into(),
        ));
    }
    let mut direct4 = BTreeSet::new();
    let mut direct6 = BTreeSet::new();
    let mut override4 = BTreeSet::new();
    let mut override6 = BTreeSet::new();

    for net in builtin_direct_nets() {
        insert_net(net, &mut direct4, &mut direct6);
    }
    for net in &direct {
        insert_net(*net, &mut direct4, &mut direct6);
    }
    for net in &geo.v4 {
        direct4.insert(*net);
    }
    for net in &geo.v6 {
        direct6.insert(*net);
    }
    for ip in endpoints {
        match ip {
            IpAddr::V4(ip) => {
                direct4.insert(IpNet::V4(Ipv4Net::new(*ip, 32).expect("valid prefix")));
            }
            IpAddr::V6(ip) => {
                direct6.insert(IpNet::V6(Ipv6Net::new(*ip, 128).expect("valid prefix")));
            }
        }
    }
    for net in &endpoint_override {
        insert_net(*net, &mut override4, &mut override6);
    }
    insert_net(IpNet::V4(tun_v4), &mut override4, &mut override6);
    insert_net(IpNet::V6(tun_v6), &mut override4, &mut override6);

    for net in override4.iter() {
        direct4.remove(net);
    }
    for net in override6.iter() {
        direct6.remove(net);
    }

    let direct4 = IpNet::aggregate(&direct4.into_iter().collect());
    let direct6 = IpNet::aggregate(&direct6.into_iter().collect());
    let override4 = IpNet::aggregate(&override4.into_iter().collect());
    let override6 = IpNet::aggregate(&override6.into_iter().collect());

    Ok(ClientPlan {
        tun_name: tun_name.to_string(),
        mtu,
        mark,
        table_id,
        direct4,
        direct6,
        override4,
        override6,
        kill_switch,
        tun_v4,
        tun_v6,
        dns_servers: dns_servers.to_vec(),
    })
}

fn insert_net(net: IpNet, v4: &mut BTreeSet<IpNet>, v6: &mut BTreeSet<IpNet>) {
    match net {
        IpNet::V4(_) => {
            v4.insert(net);
        }
        IpNet::V6(_) => {
            v6.insert(net);
        }
    }
}

pub fn builtin_direct_nets() -> Vec<IpNet> {
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ]
    .iter()
    .map(|value| value.parse().expect("builtin network is valid"))
    .collect()
}

fn format_elements(nets: &[IpNet]) -> String {
    if nets.is_empty() {
        return String::new();
    }
    let mut output = String::from("    elements = {\n");
    for (index, net) in nets.iter().enumerate() {
        output.push_str("        ");
        output.push_str(&net.to_string());
        if index + 1 != nets.len() {
            output.push(',');
        }
        output.push('\n');
    }
    output.push_str("    }\n");
    output
}

fn set_block(name: &str, address_type: &str, nets: &[IpNet], timeout: bool) -> String {
    let mut output =
        format!("    set {name} {{\n        type {address_type}\n        flags interval\n");
    if timeout {
        output.push_str("        timeout 1h\n");
    }
    output.push_str(&format_elements(nets));
    output.push_str("    }\n");
    output
}

pub fn client_nft(plan: &ClientPlan) -> String {
    let mut output = String::from("table inet rtun {\n");
    output.push_str(&set_block("direct4", "ipv4_addr", &plan.direct4, false));
    output.push_str(&set_block("direct6", "ipv6_addr", &plan.direct6, false));
    output.push_str(&set_block("override4", "ipv4_addr", &plan.override4, false));
    output.push_str(&set_block("override6", "ipv6_addr", &plan.override6, false));
    output.push_str(&set_block("dns_direct4", "ipv4_addr", &[], true));
    output.push_str(&set_block("dns_direct6", "ipv6_addr", &[], true));
    output.push_str(&set_block("dns_override4", "ipv4_addr", &[], true));
    output.push_str(&set_block("dns_override6", "ipv6_addr", &[], true));
    output.push_str(&format!(
        "    chain output {{\n        type route hook output priority mangle; policy accept;\n        ip daddr @override4 return\n        ip daddr @dns_override4 return\n        ip6 daddr @override6 return\n        ip6 daddr @dns_override6 return\n        ip daddr @direct4 counter meta mark set {:#x} accept\n        ip daddr @dns_direct4 counter meta mark set {:#x} accept\n        ip6 daddr @direct6 counter meta mark set {:#x} accept\n        ip6 daddr @dns_direct6 counter meta mark set {:#x} accept\n    }}\n",
        plan.mark, plan.mark, plan.mark, plan.mark
    ));
    let dns4 = plan
        .dns_servers
        .iter()
        .filter(|ip| ip.is_ipv4())
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let dns6 = plan
        .dns_servers
        .iter()
        .filter(|ip| ip.is_ipv6())
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    output.push_str("    chain dns_out {\n        type filter hook output priority -5; policy accept;\n        udp dport 53 ip daddr @direct4 accept\n        udp dport 53 ip daddr @dns_direct4 accept\n        udp dport 53 ip6 daddr @direct6 accept\n        udp dport 53 ip6 daddr @dns_direct6 accept\n");
    if !dns4.is_empty() {
        output.push_str(&format!(
            "        udp dport 53 ip daddr {{ {dns4} }} counter accept\n"
        ));
    }
    if !dns6.is_empty() {
        output.push_str(&format!(
            "        udp dport 53 ip6 daddr {{ {dns6} }} counter accept\n"
        ));
    }
    output.push_str("        udp dport 53 drop\n        tcp dport 53 drop\n    }\n}\n");
    output
}

pub fn kill_switch_nft(plan: &ClientPlan) -> String {
    let dns4 = plan
        .dns_servers
        .iter()
        .filter(|ip| ip.is_ipv4())
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let dns6 = plan
        .dns_servers
        .iter()
        .filter(|ip| ip.is_ipv6())
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut rules = String::new();
    rules.push_str("        udp dport 53 ip daddr { 127.0.0.1, 127.0.0.53 } counter accept\n        udp dport 53 ip6 daddr ::1 counter accept\n");
    if !dns4.is_empty() {
        rules.push_str(&format!(
            "        udp dport 53 ip daddr {{ {dns4} }} counter accept\n"
        ));
    }
    if !dns6.is_empty() {
        rules.push_str(&format!(
            "        udp dport 53 ip6 daddr {{ {dns6} }} counter accept\n"
        ));
    }
    format!(
        "table inet rtun_ks {{\n    chain output {{\n        type filter hook output priority 0; policy drop;\n        ct state established,related counter accept\n        oifname \"lo\" counter accept\n        oifname \"{tun}\" counter accept\n        meta mark {mark:#x} counter accept\n{rules}        udp sport 68 udp dport 67 counter accept\n        udp sport 546 udp dport 547 counter accept\n        icmpv6 type {{ nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} counter accept\n    }}\n}}\n",
        tun = plan.tun_name,
        mark = plan.mark
    )
}

pub fn server_nft(
    tun_name: &str,
    v4_prefix: &str,
    v6_prefix: &str,
    udp_port: u16,
    handshake_rate: u32,
) -> String {
    let burst = handshake_rate.saturating_mul(2).max(1);
    format!(
        "table inet rtun_srv {{\n    chain forward {{\n        type filter hook forward priority mangle; policy accept;\n        tcp flags syn tcp option maxseg size set rt mtu\n    }}\n    chain postrouting {{\n        type nat hook postrouting priority srcnat; policy accept;\n        ip saddr {v4_prefix} oifname != \"{tun_name}\" masquerade\n        ip6 saddr {v6_prefix} oifname != \"{tun_name}\" masquerade\n    }}\n    chain input {{\n        type filter hook input priority filter; policy accept;\n        udp dport {udp_port} ct state new limit rate {handshake_rate}/second burst {burst} packets accept\n        udp dport {udp_port} ct state new drop\n    }}\n}}\n"
    )
}

pub fn client_ip_commands(plan: &ClientPlan) -> Vec<Vec<String>> {
    let mark = format!("{:#x}", plan.mark);
    let table = plan.table_id.to_string();
    vec![
        vec![
            "rule".into(),
            "add".into(),
            "pref".into(),
            "100".into(),
            "fwmark".into(),
            mark.clone(),
            "lookup".into(),
            "main".into(),
        ],
        vec![
            "rule".into(),
            "add".into(),
            "pref".into(),
            "200".into(),
            "lookup".into(),
            table.clone(),
        ],
        vec![
            "route".into(),
            "replace".into(),
            "default".into(),
            "dev".into(),
            plan.tun_name.clone(),
            "table".into(),
            table.clone(),
        ],
    ]
}

pub fn client_ip6_commands(plan: &ClientPlan) -> Vec<Vec<String>> {
    let mark = format!("{:#x}", plan.mark);
    let table = plan.table_id.to_string();
    vec![
        vec![
            "rule".into(),
            "add".into(),
            "pref".into(),
            "100".into(),
            "fwmark".into(),
            mark,
            "lookup".into(),
            "main".into(),
        ],
        vec![
            "rule".into(),
            "add".into(),
            "pref".into(),
            "200".into(),
            "lookup".into(),
            table.clone(),
        ],
        vec![
            "route".into(),
            "replace".into(),
            "default".into(),
            "dev".into(),
            plan.tun_name.clone(),
            "table".into(),
            table,
        ],
    ]
}

pub fn cleanup_ip_commands(plan: &ClientPlan) -> Vec<Vec<String>> {
    let mark = format!("{:#x}", plan.mark);
    let table = plan.table_id.to_string();
    vec![
        vec![
            "rule".into(),
            "del".into(),
            "pref".into(),
            "100".into(),
            "fwmark".into(),
            mark.clone(),
            "lookup".into(),
            "main".into(),
        ],
        vec![
            "rule".into(),
            "del".into(),
            "pref".into(),
            "200".into(),
            "lookup".into(),
            table.clone(),
        ],
        vec!["route".into(), "flush".into(), "table".into(), table],
    ]
}

pub fn set_add_command(
    table: &str,
    set: &str,
    nets: &[IpNet],
    timeout_secs: Option<u64>,
) -> String {
    let elements = nets
        .iter()
        .map(|net| match timeout_secs {
            Some(timeout) => format!("{net} timeout {timeout}s"),
            None => net.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("add element inet {table} {set} {{ {elements} }}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectRoute {
    pub net: IpNet,
    pub via: Option<IpAddr>,
    pub dev: String,
}

pub fn plan_direct_routes(
    plan: &ClientPlan,
    dev: &str,
    gateway_v4: Option<std::net::Ipv4Addr>,
    gateway_v6: Option<std::net::Ipv6Addr>,
) -> Vec<DirectRoute> {
    let mut routes = Vec::new();
    for net in plan.direct4.iter().chain(plan.direct6.iter()) {
        let addr = net.addr();
        if addr.is_loopback() || addr.is_unspecified() {
            continue;
        }
        let link_local = match addr {
            IpAddr::V4(ip) => ip.is_link_local() || ip.is_multicast() || ip.is_broadcast(),
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                (octets[0] == 0xfe && octets[1] & 0xc0 == 0x80) || ip.is_multicast()
            }
        };
        let via = if link_local {
            None
        } else {
            match addr {
                IpAddr::V4(_) => gateway_v4.map(IpAddr::V4),
                IpAddr::V6(_) => gateway_v6.map(IpAddr::V6),
            }
        };
        if !link_local && via.is_none() {
            continue;
        }
        routes.push(DirectRoute {
            net: *net,
            via,
            dev: dev.to_string(),
        });
    }
    for net in plan.override4.iter().chain(plan.override6.iter()) {
        routes.push(DirectRoute {
            net: *net,
            via: None,
            dev: plan.tun_name.clone(),
        });
    }
    routes
}

pub fn route_batch_lines(routes: &[DirectRoute], table_id: u32) -> String {
    let mut output = String::new();
    for route in routes {
        output.push_str("route replace ");
        output.push_str(&route.net.to_string());
        if let Some(via) = route.via {
            output.push_str(" via ");
            output.push_str(&via.to_string());
        }
        output.push_str(" dev ");
        output.push_str(&route.dev);
        output.push_str(" table ");
        output.push_str(&table_id.to_string());
        output.push('\n');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ClientPlan {
        build_client_plan(
            "rtun0",
            1360,
            0x1,
            51820,
            vec!["203.0.113.0/24".parse().unwrap()],
            vec!["198.51.100.0/24".parse().unwrap()],
            &["8.8.8.8".parse().unwrap(), "2001:db8::8".parse().unwrap()],
            &GeoIpData {
                v4: vec!["5.0.0.0/8".parse().unwrap()],
                v6: vec!["2a00::/16".parse().unwrap()],
            },
            "10.66.0.0/24".parse().unwrap(),
            "fd66:1::/64".parse().unwrap(),
            &["10.66.0.1".parse().unwrap(), "fd66:1::1".parse().unwrap()],
            true,
        )
        .unwrap()
    }

    #[test]
    fn builtin_and_endpoint_nets_are_direct() {
        let plan = plan();
        assert!(plan.direct4.contains(&"10.0.0.0/8".parse().unwrap()));
        assert!(plan.direct4.contains(&"8.8.8.8/32".parse().unwrap()));
        assert!(plan.direct6.contains(&"2001:db8::8/128".parse().unwrap()));
        assert!(plan.direct4.contains(&"5.0.0.0/8".parse().unwrap()));
        assert!(plan.direct6.contains(&"2a00::/16".parse().unwrap()));
    }

    #[test]
    fn internal_tunnel_ranges_are_not_direct() {
        let plan = plan();
        assert!(plan.override4.contains(&"10.66.0.0/24".parse().unwrap()));
        assert!(plan.override6.contains(&"fd66:1::/64".parse().unwrap()));
        assert!(!plan.direct4.contains(&"10.66.0.0/24".parse().unwrap()));
        assert!(!plan.direct6.contains(&"fd66:1::/64".parse().unwrap()));
    }

    #[test]
    fn override_cidrs_are_excluded_from_direct() {
        let plan = plan();
        assert!(plan.override4.contains(&"198.51.100.0/24".parse().unwrap()));
        assert!(!plan.direct4.contains(&"198.51.100.0/24".parse().unwrap()));
    }

    #[test]
    fn client_nft_contains_required_rules() {
        let text = client_nft(&plan());
        assert!(text.contains("table inet rtun"));
        assert!(text.contains("set direct4"));
        assert!(text.contains("set override4"));
        assert!(text.contains("ip daddr @override4 return"));
        assert!(text.contains("ip daddr @direct4 counter meta mark set 0x1"));
        assert!(text.contains("set dns_direct4"));
        assert!(text.contains("timeout 1h"));
        let direct = text.find("set direct4").expect("direct set");
        let direct_block = &text[direct..direct + text[direct..].find('}').unwrap_or(0)];
        assert!(!direct_block.contains("timeout"));
        assert!(text.contains("type route hook output priority mangle"));
        assert!(text.contains("chain dns_out"));
        assert!(text.contains("udp dport 53 drop"));
    }

    #[test]
    fn kill_switch_defaults_to_drop_and_allows_tunnel() {
        let text = kill_switch_nft(&plan());
        assert!(text.contains("policy drop"));
        assert!(text.contains("oifname \"rtun0\" counter accept"));
        assert!(text.contains("meta mark 0x1 counter accept"));
        assert!(text.contains("udp dport 53 ip daddr { 127.0.0.1, 127.0.0.53 } counter accept"));
        assert!(text.contains("udp dport 53 ip daddr { 10.66.0.1 } counter accept"));
        assert!(text.contains("icmpv6 type"));
    }

    #[test]
    fn server_nft_has_nat44_nat66_and_clamp() {
        let text = server_nft("rtun0", "10.66.0.0/24", "fd66:1::/64", 443, 50);
        assert!(text.contains("ip saddr 10.66.0.0/24 oifname != \"rtun0\" masquerade"));
        assert!(text.contains("ip6 saddr fd66:1::/64 oifname != \"rtun0\" masquerade"));
        assert!(text.contains("tcp option maxseg size set rt mtu"));
        assert!(text.contains("limit rate 50/second burst 100 packets"));
    }

    #[test]
    fn split_routes_use_gateway_and_tunnel_override() {
        let plan = plan();
        let routes = plan_direct_routes(
            &plan,
            "eth0",
            Some("10.200.1.1".parse().unwrap()),
            Some("2001:db8:1::1".parse().unwrap()),
        );
        assert!(routes
            .iter()
            .any(|route| route.net == "8.8.8.8/32".parse().unwrap()
                && route.via == Some("10.200.1.1".parse().unwrap())
                && route.dev == "eth0"));
        assert!(routes
            .iter()
            .any(|route| route.net == "10.0.0.0/8".parse().unwrap()
                && route.via == Some("10.200.1.1".parse().unwrap())
                && route.dev == "eth0"));
        assert!(routes
            .iter()
            .any(|route| route.net == "10.66.0.0/24".parse().unwrap() && route.dev == "rtun0"));
        assert!(!routes.iter().any(|route| route.net.addr().is_loopback()));
    }

    #[test]
    fn split_route_batch_is_parseable() {
        let routes = vec![DirectRoute {
            net: "8.8.8.8/32".parse().unwrap(),
            via: Some("10.0.0.1".parse().unwrap()),
            dev: "eth0".into(),
        }];
        assert_eq!(
            route_batch_lines(&routes, 51820),
            "route replace 8.8.8.8/32 via 10.0.0.1 dev eth0 table 51820\n"
        );
    }

    #[test]
    fn set_update_includes_timeout() {
        let command = set_add_command(
            "rtun",
            "direct4",
            &["1.2.3.0/24".parse().unwrap()],
            Some(300),
        );
        assert_eq!(
            command,
            "add element inet rtun direct4 { 1.2.3.0/24 timeout 300s }"
        );
    }

    #[test]
    fn ip_commands_use_expected_table_and_mark() {
        let plan = plan();
        let v4 = client_ip_commands(&plan);
        assert_eq!(v4[0][0], "rule");
        assert!(v4[0].contains(&"0x1".to_string()));
        assert!(v4[2].contains(&"51820".to_string()));
        assert_eq!(client_ip6_commands(&plan).len(), 3);
        assert_eq!(cleanup_ip_commands(&plan).len(), 3);
    }
}
