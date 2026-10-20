use std::net::IpAddr;
use std::path::Path;

use rt_proto::SuffixSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamClass {
    Direct,
    Tunnel,
}

#[derive(Debug, Clone)]
pub struct SplitPolicy {
    suffixes: SuffixSet,
    smart_routing: bool,
    degraded: bool,
}

impl SplitPolicy {
    pub fn new(suffixes: SuffixSet, smart_routing: bool, degraded: bool) -> Self {
        Self {
            suffixes,
            smart_routing,
            degraded,
        }
    }

    pub fn classify(&self, domain: &str) -> UpstreamClass {
        if self.degraded || !self.smart_routing {
            return UpstreamClass::Tunnel;
        }
        if self.suffixes.matches(domain) {
            UpstreamClass::Direct
        } else {
            UpstreamClass::Tunnel
        }
    }

    pub fn is_direct_domain(&self, domain: &str) -> bool {
        self.classify(domain) == UpstreamClass::Direct
    }

    pub fn degraded(&self) -> bool {
        self.degraded
    }
}

pub fn discover_direct_upstreams(paths: &[&Path]) -> Vec<IpAddr> {
    let mut upstreams = Vec::new();
    for path in paths {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("nameserver") else {
                continue;
            };
            let Some(value) = rest.split_whitespace().next() else {
                continue;
            };
            let Ok(ip) = value.parse::<IpAddr>() else {
                continue;
            };
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                continue;
            }
            if !upstreams.contains(&ip) {
                upstreams.push(ip);
            }
        }
    }
    upstreams
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(degraded: bool) -> SplitPolicy {
        SplitPolicy::new(SuffixSet::new(["ru", "рф", "su"]).unwrap(), true, degraded)
    }

    #[test]
    fn classifies_direct_and_tunnel_domains() {
        let policy = policy(false);
        assert_eq!(policy.classify("www.example.ru"), UpstreamClass::Direct);
        assert_eq!(policy.classify("example.com"), UpstreamClass::Tunnel);
        assert_eq!(policy.classify("пример.рф"), UpstreamClass::Direct);
    }

    #[test]
    fn degraded_mode_sends_everything_tunnel() {
        let policy = policy(true);
        assert_eq!(policy.classify("example.ru"), UpstreamClass::Tunnel);
        assert_eq!(policy.classify("example.com"), UpstreamClass::Tunnel);
    }

    #[test]
    fn discovers_non_loopback_nameservers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(
            &path,
            "nameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver 192.168.1.1\nnameserver 2001:db8::1\nnameserver invalid\n",
        )
        .unwrap();
        let upstreams = discover_direct_upstreams(&[&path]);
        assert_eq!(
            upstreams,
            vec![
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn missing_files_are_ignored() {
        assert!(discover_direct_upstreams(&[Path::new("/nonexistent/resolv.conf")]).is_empty());
    }
}
