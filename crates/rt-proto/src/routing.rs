use std::fmt;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::errors::ConfigError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuffixSet {
    suffixes: Vec<String>,
}

impl SuffixSet {
    pub fn new<I, S>(suffixes: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut normalized = Vec::new();
        for suffix in suffixes {
            let value = normalize_domain(suffix.as_ref()).map_err(|error| {
                ConfigError::Invalid(format!(
                    "invalid direct domain suffix {:?}: {error}",
                    suffix.as_ref()
                ))
            })?;
            if value.is_empty() || value.contains('.') && value.starts_with('.') {
                return Err(ConfigError::Invalid(format!(
                    "invalid direct domain suffix {:?}",
                    suffix.as_ref()
                )));
            }
            if !normalized.contains(&value) {
                normalized.push(value);
            }
        }
        if normalized.is_empty() {
            return Err(ConfigError::Invalid(
                "direct domain suffix list is empty".into(),
            ));
        }
        Ok(Self {
            suffixes: normalized,
        })
    }

    pub fn suffixes(&self) -> &[String] {
        &self.suffixes
    }

    pub fn matches(&self, domain: &str) -> bool {
        let Ok(domain) = normalize_domain(domain) else {
            return false;
        };
        self.match_normalized(&domain)
    }

    fn match_normalized(&self, domain: &str) -> bool {
        self.suffixes
            .iter()
            .any(|suffix| domain == suffix || domain.ends_with(&format!(".{suffix}")))
    }

    pub fn matched_suffix(&self, domain: &str) -> Option<&str> {
        let domain = normalize_domain(domain).ok()?;
        self.suffixes
            .iter()
            .find(|suffix| domain == **suffix || domain.ends_with(&format!(".{suffix}")))
            .map(String::as_str)
    }
}

pub fn normalize_domain(value: &str) -> Result<String, String> {
    let trimmed = value.trim().trim_end_matches('.').trim_start_matches('.');
    if trimmed.is_empty() {
        return Err("empty domain".into());
    }
    let ascii = idna::domain_to_ascii(trimmed).map_err(|error| error.to_string())?;
    Ok(ascii.to_ascii_lowercase())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteAction {
    Direct,
    Tunnel,
}

impl fmt::Display for RouteAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => f.write_str("direct"),
            Self::Tunnel => f.write_str("tunnel"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteReason {
    Loopback,
    Private,
    LinkLocal,
    Multicast,
    Broadcast,
    Endpoint,
    TunnelOverride,
    DirectCidr,
    GeoIp,
    DirectDomain,
    DegradedDns,
    DefaultTunnel,
}

impl fmt::Display for RouteReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::LinkLocal => "link-local",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Endpoint => "endpoint",
            Self::TunnelOverride => "tunnel-override",
            Self::DirectCidr => "direct-cidr",
            Self::GeoIp => "geo-ip",
            Self::DirectDomain => "direct-domain",
            Self::DegradedDns => "degraded-dns",
            Self::DefaultTunnel => "default-tunnel",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteDecision {
    pub action: RouteAction,
    pub reason: RouteReason,
    pub matched: Option<String>,
}

impl RouteDecision {
    fn new(action: RouteAction, reason: RouteReason) -> Self {
        Self {
            action,
            reason,
            matched: None,
        }
    }

    fn with_match(mut self, value: impl Into<String>) -> Self {
        self.matched = Some(value.into());
        self
    }
}

pub fn is_builtin_direct(ip: IpAddr) -> Option<RouteReason> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return Some(RouteReason::Loopback);
            }
            if v4.is_private() || v4.octets()[0] == 0 {
                return Some(RouteReason::Private);
            }
            if v4.is_link_local() {
                return Some(RouteReason::LinkLocal);
            }
            if v4.is_multicast() {
                return Some(RouteReason::Multicast);
            }
            if v4.is_broadcast() {
                return Some(RouteReason::Broadcast);
            }
            let octets = v4.octets();
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return Some(RouteReason::Private);
            }
            None
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_builtin_direct(IpAddr::V4(mapped));
            }
            if v6.is_loopback() || v6.is_unspecified() {
                return Some(RouteReason::Loopback);
            }
            let octets = v6.octets();
            if octets[0] & 0xfe == 0xfc {
                return Some(RouteReason::Private);
            }
            if octets[0] == 0xfe && octets[1] & 0xc0 == 0x80 {
                return Some(RouteReason::LinkLocal);
            }
            if v6.is_multicast() {
                return Some(RouteReason::Multicast);
            }
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRules {
    pub suffixes: SuffixSet,
    pub direct: Vec<IpNet>,
    pub tunnel_override: Vec<IpNet>,
    pub geo: Vec<IpNet>,
    pub endpoints: Vec<IpAddr>,
}

impl IpRules {
    pub fn new(
        suffixes: SuffixSet,
        direct: Vec<IpNet>,
        tunnel_override: Vec<IpNet>,
        geo: Vec<IpNet>,
        endpoints: Vec<IpAddr>,
    ) -> Self {
        Self {
            suffixes,
            direct,
            tunnel_override,
            geo,
            endpoints,
        }
    }

    pub fn replace_geo(&mut self, geo: Vec<IpNet>) {
        self.geo = geo;
    }

    pub fn route_ip(&self, ip: IpAddr) -> RouteDecision {
        let ip = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            other => other,
        };
        if let Some(reason) = is_builtin_direct(ip) {
            return RouteDecision::new(RouteAction::Direct, reason);
        }
        if self.endpoints.contains(&ip) {
            return RouteDecision::new(RouteAction::Direct, RouteReason::Endpoint);
        }
        if let Some(net) = self.tunnel_override.iter().find(|net| net.contains(&ip)) {
            return RouteDecision::new(RouteAction::Tunnel, RouteReason::TunnelOverride)
                .with_match(net.to_string());
        }
        if let Some(net) = self.direct.iter().find(|net| net.contains(&ip)) {
            return RouteDecision::new(RouteAction::Direct, RouteReason::DirectCidr)
                .with_match(net.to_string());
        }
        if let Some(net) = self.geo.iter().find(|net| net.contains(&ip)) {
            return RouteDecision::new(RouteAction::Direct, RouteReason::GeoIp)
                .with_match(net.to_string());
        }
        RouteDecision::new(RouteAction::Tunnel, RouteReason::DefaultTunnel)
    }

    pub fn route_domain(&self, domain: &str, smart_routing: bool) -> RouteDecision {
        if !smart_routing {
            return RouteDecision::new(RouteAction::Tunnel, RouteReason::DegradedDns);
        }
        match self.suffixes.matched_suffix(domain) {
            Some(suffix) => RouteDecision::new(RouteAction::Direct, RouteReason::DirectDomain)
                .with_match(suffix.to_string()),
            None => RouteDecision::new(RouteAction::Tunnel, RouteReason::DefaultTunnel),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn rules() -> IpRules {
        IpRules::new(
            SuffixSet::new(["ru", "рф", "su", "xn--p1ai"]).unwrap(),
            vec!["203.0.113.0/24".parse().unwrap()],
            vec!["198.51.100.0/24".parse().unwrap()],
            vec!["5.0.0.0/8".parse().unwrap()],
            vec![
                "203.0.113.10".parse().unwrap(),
                "2001:db8::10".parse().unwrap(),
            ],
        )
    }

    #[test]
    fn lan_and_private_are_direct() {
        let rules = rules();
        for ip in [
            "127.0.0.1",
            "192.168.1.1",
            "10.1.2.3",
            "172.20.0.1",
            "169.254.1.1",
            "100.100.1.1",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fd66::1",
        ] {
            let decision = rules.route_ip(ip.parse().unwrap());
            assert_eq!(decision.action, RouteAction::Direct, "{ip}");
        }
    }

    #[test]
    fn endpoint_is_always_direct() {
        let rules = rules();
        assert_eq!(
            rules.route_ip("203.0.113.10".parse().unwrap()).reason,
            RouteReason::Endpoint
        );
        assert_eq!(
            rules.route_ip("2001:db8::10".parse().unwrap()).reason,
            RouteReason::Endpoint
        );
    }

    #[test]
    fn tunnel_override_wins_over_direct_and_geo() {
        let mut rules = rules();
        rules.direct.push("198.51.100.0/24".parse().unwrap());
        rules.geo.push("198.51.100.0/24".parse().unwrap());
        let decision = rules.route_ip("198.51.100.7".parse().unwrap());
        assert_eq!(decision.action, RouteAction::Tunnel);
        assert_eq!(decision.reason, RouteReason::TunnelOverride);
    }

    #[test]
    fn geoip_is_direct_and_rest_is_tunnel() {
        let rules = rules();
        assert_eq!(
            rules.route_ip("5.10.0.1".parse().unwrap()).reason,
            RouteReason::GeoIp
        );
        let decision = rules.route_ip("8.8.8.8".parse().unwrap());
        assert_eq!(decision.action, RouteAction::Tunnel);
        assert_eq!(decision.reason, RouteReason::DefaultTunnel);
    }

    #[test]
    fn suffix_matches_label_boundary_only() {
        let rules = rules();
        assert_eq!(
            rules.route_domain("www.example.ru", true).reason,
            RouteReason::DirectDomain
        );
        assert_eq!(
            rules.route_domain("notru.example", true).action,
            RouteAction::Tunnel
        );
        assert_eq!(
            rules.route_domain("пример.рф", true).action,
            RouteAction::Direct
        );
        assert_eq!(
            rules.route_domain("example.xn--p1ai", true).action,
            RouteAction::Direct
        );
        assert_eq!(
            rules.route_domain("example.com", true).action,
            RouteAction::Tunnel
        );
    }

    #[test]
    fn degraded_mode_ignores_domain_rules() {
        let rules = rules();
        let decision = rules.route_domain("example.ru", false);
        assert_eq!(decision.action, RouteAction::Tunnel);
        assert_eq!(decision.reason, RouteReason::DegradedDns);
        assert_eq!(
            rules.route_ip("5.10.0.1".parse().unwrap()).action,
            RouteAction::Direct
        );
    }

    #[test]
    fn mapped_ipv6_uses_ipv4_rules() {
        let rules = rules();
        let mapped: IpAddr = Ipv4Addr::new(5, 10, 0, 1).to_ipv6_mapped().into();
        assert_eq!(rules.route_ip(mapped).reason, RouteReason::GeoIp);
    }

    #[test]
    fn suffix_set_deduplicates_unicode() {
        let set = SuffixSet::new(["ru", "рф", "xn--p1ai", ".RU."]).unwrap();
        assert!(set.matches("foo.ru"));
        assert_eq!(set.suffixes().len(), 2);
    }
}
