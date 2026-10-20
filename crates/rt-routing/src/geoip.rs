use std::net::IpAddr;
use std::path::Path;

use ipnet::IpNet;

use crate::error::{Result, RoutingError};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeoIpData {
    pub v4: Vec<IpNet>,
    pub v6: Vec<IpNet>,
}

impl GeoIpData {
    pub fn all(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.v4.iter().chain(self.v6.iter()).copied()
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

pub fn parse_zone(text: &str) -> Result<Vec<IpNet>> {
    let mut nets = Vec::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.split_whitespace().count() != 1 {
            return Err(RoutingError::GeoIp(format!(
                "line {}: expected a single CIDR, got {line:?}",
                index + 1
            )));
        }
        let net = line.parse::<IpNet>().map_err(|error| {
            RoutingError::GeoIp(format!(
                "line {}: invalid CIDR {line:?}: {error}",
                index + 1
            ))
        })?;
        if net.prefix_len() == 0 {
            return Err(RoutingError::GeoIp(format!(
                "line {}: refusing default route in GeoIP data",
                index + 1
            )));
        }
        nets.push(net);
    }
    if nets.is_empty() {
        return Err(RoutingError::GeoIp("GeoIP zone is empty".into()));
    }
    nets.sort_by_key(|net| (net.network().is_ipv6(), net.addr(), net.prefix_len()));
    nets.dedup();
    Ok(nets)
}

pub fn split_families(nets: Vec<IpNet>) -> GeoIpData {
    let mut data = GeoIpData::default();
    for net in nets {
        match net.addr() {
            IpAddr::V4(_) => data.v4.push(net),
            IpAddr::V6(_) => data.v6.push(net),
        }
    }
    data
}

pub fn write_atomic(path: &Path, nets: &[IpNet]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("geoip"),
        std::process::id()
    ));
    let mut text = String::with_capacity(nets.len() * 20);
    for net in nets {
        text.push_str(&net.to_string());
        text.push('\n');
    }
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn read_file(path: &Path) -> Result<Vec<IpNet>> {
    let text = std::fs::read_to_string(path)?;
    parse_zone(&text)
}

pub fn load(data_dir: &Path) -> Result<GeoIpData> {
    let v4_path = data_dir.join("geoip-v4.nets");
    let v6_path = data_dir.join("geoip-v6.nets");
    let v4 = if v4_path.exists() {
        read_file(&v4_path)?
    } else {
        Vec::new()
    };
    let v6 = if v6_path.exists() {
        read_file(&v6_path)?
    } else {
        Vec::new()
    };
    Ok(GeoIpData { v4, v6 })
}

pub fn save(data_dir: &Path, data: &GeoIpData) -> Result<()> {
    write_atomic(&data_dir.join("geoip-v4.nets"), &data.v4)?;
    write_atomic(&data_dir.join("geoip-v6.nets"), &data.v6)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comments_and_blank_lines() {
        let text = "# comment\n\n5.0.0.0/8\n 77.88.0.0/18 # yandex\n";
        let nets = parse_zone(text).unwrap();
        assert_eq!(nets.len(), 2);
        assert_eq!(nets[0], "5.0.0.0/8".parse().unwrap());
    }

    #[test]
    fn rejects_garbage_and_default_route() {
        assert!(parse_zone("not-a-cidr\n").is_err());
        assert!(parse_zone("0.0.0.0/0\n").is_err());
        assert!(parse_zone("::/0\n").is_err());
        assert!(parse_zone("\n\n").is_err());
        assert!(parse_zone("5.0.0.0/8 6.0.0.0/8\n").is_err());
    }

    #[test]
    fn deduplicates_and_sorts() {
        let nets = parse_zone("5.0.0.0/8\n1.0.0.0/24\n5.0.0.0/8\n").unwrap();
        assert_eq!(nets.len(), 2);
        assert_eq!(nets[0], "1.0.0.0/24".parse().unwrap());
    }

    #[test]
    fn splits_families() {
        let nets = vec!["5.0.0.0/8".parse().unwrap(), "2a00::/16".parse().unwrap()];
        let data = split_families(nets);
        assert_eq!(data.v4.len(), 1);
        assert_eq!(data.v6.len(), 1);
    }

    #[test]
    fn atomic_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let data = GeoIpData {
            v4: vec!["5.0.0.0/8".parse().unwrap()],
            v6: vec!["2a00::/16".parse().unwrap()],
        };
        save(dir.path(), &data).unwrap();
        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded, data);
    }
}
