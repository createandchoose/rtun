//! WireGuard-подобный конфиг клиента: секции [Interface], [Peer] и [Rtun].
//! Формат описан в docs/deploy-design.md. Секция [Rtun] — расширение RTUN,
//! стандартные WireGuard-клиенты ее игнорируют.
//!
//! Покрыто все, что есть в `ClientConfig`, кроме `DnsConfig` (кроме адресов
//! туннельного DNS, см. ключ DNS) и `GeoIpConfig`. Эти поля при импорте
//! берутся по умолчанию, при экспорте теряются.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;

use crate::config::{write_secure, ClientConfig, ObfsParams, TransportKind};
use crate::errors::ConfigError;
use crate::keys::{parse_private_key, parse_public_key};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgConf {
    pub interface: Interface,
    pub peer: Peer,
    pub rtun: RtunSection,
}

impl Default for WgConf {
    fn default() -> Self {
        Self::from_client(&ClientConfig::default())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Interface {
    pub private_key: String,
    pub address_v4: Ipv4Addr,
    pub address_v6: Ipv6Addr,
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
}

impl fmt::Debug for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Interface")
            .field("private_key", &"<redacted>")
            .field("address_v4", &self.address_v4)
            .field("address_v6", &self.address_v6)
            .field("dns", &self.dns)
            .field("mtu", &self.mtu)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Peer {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub persistent_keepalive: u16,
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("public_key", &self.public_key)
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| "<redacted>"),
            )
            .field("endpoint_host", &self.endpoint_host)
            .field("endpoint_port", &self.endpoint_port)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtunSection {
    pub server_name: Option<String>,
    pub ws_path: String,
    pub alpn: String,
    pub mtu_ws: u16,
    pub transports: Vec<TransportKind>,
    pub ws_start_delay_ms: u64,
    pub health_interval_secs: u64,
    pub health_misses: u8,
    pub handshake_timeout_ms: u64,
    pub probe_interval_secs: u64,
    pub preferred_gain_pct: u8,
    pub min_switch_interval_secs: u64,
    pub obfs: ObfsParams,
    pub direct_suffixes: Vec<String>,
    pub direct_cidrs: Vec<String>,
    pub tunnel_override_cidrs: Vec<String>,
    pub smart_routing: bool,
    pub table_id: u32,
    pub mark: u32,
    pub kill_switch: bool,
    pub log_level: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Interface,
    Peer,
    Rtun,
}

struct Entry {
    section: Section,
    line: usize,
    key: String,
    value: String,
}

impl WgConf {
    pub fn from_client(cfg: &ClientConfig) -> Self {
        Self {
            interface: Interface {
                private_key: cfg.device.private_key.clone(),
                address_v4: cfg.device.address_v4,
                address_v6: cfg.device.address_v6,
                dns: vec![IpAddr::V4(cfg.dns.server_v4), IpAddr::V6(cfg.dns.server_v6)],
                mtu: cfg.device.mtu_obfs,
            },
            peer: Peer {
                public_key: cfg.device.peer_public_key.clone(),
                preshared_key: cfg.device.preshared_key.clone(),
                endpoint_host: cfg.endpoint.host.clone(),
                endpoint_port: cfg.endpoint.port,
                persistent_keepalive: cfg.device.persistent_keepalive,
            },
            rtun: RtunSection {
                server_name: cfg.endpoint.server_name.clone(),
                ws_path: cfg.endpoint.ws_path.clone(),
                alpn: cfg.endpoint.alpn.clone(),
                mtu_ws: cfg.device.mtu_ws,
                transports: cfg.transports.priority.clone(),
                ws_start_delay_ms: cfg.transports.ws_start_delay_ms,
                health_interval_secs: cfg.transports.health_interval_secs,
                health_misses: cfg.transports.health_misses,
                handshake_timeout_ms: cfg.transports.handshake_timeout_ms,
                probe_interval_secs: cfg.transports.probe_interval_secs,
                preferred_gain_pct: cfg.transports.preferred_gain_pct,
                min_switch_interval_secs: cfg.transports.min_switch_interval_secs,
                obfs: cfg.obfs.clone(),
                direct_suffixes: cfg.routing.direct_suffixes.clone(),
                direct_cidrs: cfg.routing.direct_cidrs.clone(),
                tunnel_override_cidrs: cfg.routing.tunnel_override_cidrs.clone(),
                smart_routing: cfg.routing.smart_routing,
                table_id: cfg.routing.table_id,
                mark: cfg.routing.mark,
                kill_switch: cfg.kill_switch,
                log_level: cfg.log_level.clone(),
            },
        }
    }

    pub fn into_client(self) -> Result<ClientConfig, ConfigError> {
        let mut cfg = ClientConfig::default();

        cfg.device.private_key = self.interface.private_key;
        cfg.device.address_v4 = self.interface.address_v4;
        cfg.device.address_v6 = self.interface.address_v6;
        cfg.device.mtu_obfs = self.interface.mtu;
        for ip in self.interface.dns {
            match ip {
                IpAddr::V4(addr) => cfg.dns.server_v4 = addr,
                IpAddr::V6(addr) => cfg.dns.server_v6 = addr,
            }
        }

        cfg.device.peer_public_key = self.peer.public_key;
        cfg.device.preshared_key = self.peer.preshared_key;
        cfg.device.persistent_keepalive = self.peer.persistent_keepalive;
        cfg.endpoint.host = self.peer.endpoint_host;
        cfg.endpoint.port = self.peer.endpoint_port;

        let rtun = self.rtun;
        cfg.endpoint.server_name = rtun.server_name;
        cfg.endpoint.ws_path = rtun.ws_path;
        cfg.endpoint.alpn = rtun.alpn;
        cfg.device.mtu_ws = rtun.mtu_ws;
        cfg.transports.priority = rtun.transports;
        cfg.transports.ws_start_delay_ms = rtun.ws_start_delay_ms;
        cfg.transports.health_interval_secs = rtun.health_interval_secs;
        cfg.transports.health_misses = rtun.health_misses;
        cfg.transports.handshake_timeout_ms = rtun.handshake_timeout_ms;
        cfg.transports.probe_interval_secs = rtun.probe_interval_secs;
        cfg.transports.preferred_gain_pct = rtun.preferred_gain_pct;
        cfg.transports.min_switch_interval_secs = rtun.min_switch_interval_secs;
        cfg.obfs = rtun.obfs;
        cfg.routing.direct_suffixes = rtun.direct_suffixes;
        cfg.routing.direct_cidrs = rtun.direct_cidrs;
        cfg.routing.tunnel_override_cidrs = rtun.tunnel_override_cidrs;
        cfg.routing.smart_routing = rtun.smart_routing;
        cfg.routing.table_id = rtun.table_id;
        cfg.routing.mark = rtun.mark;
        cfg.kill_switch = rtun.kill_switch;
        cfg.log_level = rtun.log_level;

        cfg.validate()?;
        Ok(cfg)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut current = None;
        let mut seen = Vec::new();
        let mut entries = Vec::new();

        for (index, raw) in text.lines().enumerate() {
            let line_no = index + 1;
            let line = raw.split(['#', ';']).next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some(name) = line
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            {
                let section = match name.trim().to_ascii_lowercase().as_str() {
                    "interface" => Section::Interface,
                    "peer" => Section::Peer,
                    "rtun" => Section::Rtun,
                    other => {
                        return Err(invalid(line_no, format!("unknown section [{other}]")));
                    }
                };
                if seen.contains(&section) {
                    return Err(invalid(line_no, format!("duplicate section [{name}]")));
                }
                seen.push(section);
                current = Some(section);
                continue;
            }
            let section = current
                .ok_or_else(|| invalid(line_no, "key is outside of any section".to_string()))?;
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| invalid(line_no, "expected Key = Value".to_string()))?;
            entries.push(Entry {
                section,
                line: line_no,
                key: key.trim().to_ascii_lowercase(),
                value: value.trim().to_string(),
            });
        }

        if !seen.contains(&Section::Interface) {
            return Err(ConfigError::Invalid("missing [Interface] section".into()));
        }
        if !seen.contains(&Section::Peer) {
            return Err(ConfigError::Invalid("missing [Peer] section".into()));
        }

        let mut conf = Self::default();
        let mut present: Vec<(Section, String)> = Vec::new();
        for entry in entries {
            match entry.section {
                Section::Interface => apply_interface(&mut conf.interface, &entry)?,
                Section::Peer => apply_peer(&mut conf.peer, &entry)?,
                Section::Rtun => apply_rtun(&mut conf.rtun, &entry)?,
            }
            present.push((entry.section, entry.key));
        }

        let has = |section: Section, key: &str| {
            present
                .iter()
                .any(|(s, k)| *s == section && k.as_str() == key)
        };
        if !has(Section::Interface, "privatekey") {
            return Err(ConfigError::Invalid(
                "missing PrivateKey in [Interface]".into(),
            ));
        }
        if !has(Section::Interface, "address") {
            return Err(ConfigError::Invalid(
                "missing Address in [Interface]".into(),
            ));
        }
        if !has(Section::Peer, "publickey") {
            return Err(ConfigError::Invalid("missing PublicKey in [Peer]".into()));
        }
        if !has(Section::Peer, "endpoint") {
            return Err(ConfigError::Invalid("missing Endpoint in [Peer]".into()));
        }

        parse_private_key(&conf.interface.private_key)?;
        parse_public_key(&conf.peer.public_key)?;
        if let Some(psk) = &conf.peer.preshared_key {
            parse_public_key(psk)?;
        }
        Ok(conf)
    }

    pub fn to_text(&self) -> String {
        let i = &self.interface;
        let p = &self.peer;
        let r = &self.rtun;
        let mut out = String::new();

        out.push_str("[Interface]\n");
        push(&mut out, "PrivateKey", &i.private_key);
        push(
            &mut out,
            "Address",
            &format!("{}/32, {}/128", i.address_v4, i.address_v6),
        );
        if !i.dns.is_empty() {
            push(&mut out, "DNS", &join(&i.dns));
        }
        push(&mut out, "MTU", &i.mtu.to_string());

        out.push_str("\n[Peer]\n");
        push(&mut out, "PublicKey", &p.public_key);
        if let Some(psk) = &p.preshared_key {
            push(&mut out, "PresharedKey", psk);
        }
        let endpoint = if p.endpoint_host.contains(':') {
            format!("[{}]:{}", p.endpoint_host, p.endpoint_port)
        } else {
            format!("{}:{}", p.endpoint_host, p.endpoint_port)
        };
        push(&mut out, "Endpoint", &endpoint);
        push(
            &mut out,
            "PersistentKeepalive",
            &p.persistent_keepalive.to_string(),
        );

        out.push_str("\n[Rtun]\n");
        if let Some(name) = &r.server_name {
            push(&mut out, "ServerName", name);
        }
        push(&mut out, "WsPath", &r.ws_path);
        push(&mut out, "Alpn", &r.alpn);
        push(&mut out, "MtuWs", &r.mtu_ws.to_string());
        push(&mut out, "Transports", &join(&r.transports));
        push(&mut out, "WsStartDelayMs", &r.ws_start_delay_ms.to_string());
        push(
            &mut out,
            "HealthIntervalSecs",
            &r.health_interval_secs.to_string(),
        );
        push(&mut out, "HealthMisses", &r.health_misses.to_string());
        push(
            &mut out,
            "HandshakeTimeoutMs",
            &r.handshake_timeout_ms.to_string(),
        );
        push(
            &mut out,
            "ProbeIntervalSecs",
            &r.probe_interval_secs.to_string(),
        );
        push(
            &mut out,
            "PreferredGainPct",
            &r.preferred_gain_pct.to_string(),
        );
        push(
            &mut out,
            "MinSwitchIntervalSecs",
            &r.min_switch_interval_secs.to_string(),
        );
        push(&mut out, "ObfsH1", &r.obfs.h1.to_string());
        push(&mut out, "ObfsH2", &r.obfs.h2.to_string());
        push(&mut out, "ObfsH3", &r.obfs.h3.to_string());
        push(&mut out, "ObfsH4", &r.obfs.h4.to_string());
        push(&mut out, "PaddingMax", &r.obfs.padding_max.to_string());
        push(&mut out, "JunkCount", &r.obfs.junk_count.to_string());
        push(&mut out, "JunkMin", &r.obfs.junk_min.to_string());
        push(&mut out, "JunkMax", &r.obfs.junk_max.to_string());
        push(
            &mut out,
            "JunkDelayMinMs",
            &r.obfs.junk_delay_min_ms.to_string(),
        );
        push(
            &mut out,
            "JunkDelayMaxMs",
            &r.obfs.junk_delay_max_ms.to_string(),
        );
        push(&mut out, "DirectSuffixes", &join(&r.direct_suffixes));
        push(&mut out, "DirectCidrs", &join(&r.direct_cidrs));
        push(
            &mut out,
            "TunnelOverrideCidrs",
            &join(&r.tunnel_override_cidrs),
        );
        push(&mut out, "SmartRouting", &r.smart_routing.to_string());
        push(&mut out, "TableId", &r.table_id.to_string());
        push(&mut out, "Mark", &r.mark.to_string());
        push(&mut out, "KillSwitch", &r.kill_switch.to_string());
        push(&mut out, "LogLevel", &r.log_level);
        out
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| ConfigError::Invalid(format!("cannot read config: {error}")))?;
        Self::parse(&text)
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        write_secure(path, self.to_text().as_bytes())
    }
}

fn invalid(line: usize, message: String) -> ConfigError {
    ConfigError::Invalid(format!("line {line}: {message}"))
}

fn unknown_key(entry: &Entry) -> ConfigError {
    invalid(entry.line, format!("unknown key {}", entry.key))
}

fn push(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(" = ");
    out.push_str(value);
    out.push('\n');
}

fn join<T: ToString>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

fn number<T: FromStr>(entry: &Entry) -> Result<T, ConfigError> {
    entry.value.parse::<T>().map_err(|_| {
        invalid(
            entry.line,
            format!("invalid value for {}: {}", entry.key, entry.value),
        )
    })
}

fn boolean(entry: &Entry) -> Result<bool, ConfigError> {
    match entry.value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" => Ok(true),
        "false" | "no" | "0" => Ok(false),
        _ => Err(invalid(
            entry.line,
            format!("invalid boolean for {}: {}", entry.key, entry.value),
        )),
    }
}

fn parse_ip(line: usize, text: &str) -> Result<IpAddr, ConfigError> {
    text.parse::<IpAddr>()
        .map_err(|_| invalid(line, format!("invalid IP address: {text}")))
}

fn parse_transport(line: usize, text: &str) -> Result<TransportKind, ConfigError> {
    match text {
        "obfs-udp" => Ok(TransportKind::ObfsUdp),
        "ws-tls" => Ok(TransportKind::WsTls),
        other => Err(invalid(line, format!("unknown transport: {other}"))),
    }
}

fn parse_endpoint(entry: &Entry) -> Result<(String, u16), ConfigError> {
    let (host, port) = entry
        .value
        .rsplit_once(':')
        .ok_or_else(|| invalid(entry.line, "Endpoint must be host:port".to_string()))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(invalid(entry.line, "Endpoint host is empty".to_string()));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| invalid(entry.line, format!("invalid Endpoint port: {port}")))?;
    Ok((host.to_string(), port))
}

fn apply_interface(interface: &mut Interface, entry: &Entry) -> Result<(), ConfigError> {
    match entry.key.as_str() {
        "privatekey" => interface.private_key = entry.value.clone(),
        "address" => {
            for item in list(&entry.value) {
                let text = item.split('/').next().unwrap_or("");
                match parse_ip(entry.line, text)? {
                    IpAddr::V4(addr) => interface.address_v4 = addr,
                    IpAddr::V6(addr) => interface.address_v6 = addr,
                }
            }
        }
        "dns" => {
            interface.dns = list(&entry.value)
                .iter()
                .map(|item| parse_ip(entry.line, item))
                .collect::<Result<_, _>>()?;
        }
        "mtu" => interface.mtu = number(entry)?,
        _ => return Err(unknown_key(entry)),
    }
    Ok(())
}

fn apply_peer(peer: &mut Peer, entry: &Entry) -> Result<(), ConfigError> {
    match entry.key.as_str() {
        "publickey" => peer.public_key = entry.value.clone(),
        "presharedkey" => peer.preshared_key = non_empty(&entry.value),
        "endpoint" => {
            let (host, port) = parse_endpoint(entry)?;
            peer.endpoint_host = host;
            peer.endpoint_port = port;
        }
        "persistentkeepalive" => peer.persistent_keepalive = number(entry)?,
        _ => return Err(unknown_key(entry)),
    }
    Ok(())
}

fn apply_rtun(rtun: &mut RtunSection, entry: &Entry) -> Result<(), ConfigError> {
    let value = entry.value.as_str();
    match entry.key.as_str() {
        "servername" => rtun.server_name = non_empty(value),
        "wspath" => rtun.ws_path = value.to_string(),
        "alpn" => rtun.alpn = value.to_string(),
        "mtuws" => rtun.mtu_ws = number(entry)?,
        "transports" => {
            rtun.transports = list(value)
                .iter()
                .map(|item| parse_transport(entry.line, item))
                .collect::<Result<_, _>>()?;
        }
        "wsstartdelayms" => rtun.ws_start_delay_ms = number(entry)?,
        "healthintervalsecs" => rtun.health_interval_secs = number(entry)?,
        "healthmisses" => rtun.health_misses = number(entry)?,
        "handshaketimeoutms" => rtun.handshake_timeout_ms = number(entry)?,
        "probeintervalsecs" => rtun.probe_interval_secs = number(entry)?,
        "preferredgainpct" => rtun.preferred_gain_pct = number(entry)?,
        "minswitchintervalsecs" => rtun.min_switch_interval_secs = number(entry)?,
        "obfsh1" => rtun.obfs.h1 = number(entry)?,
        "obfsh2" => rtun.obfs.h2 = number(entry)?,
        "obfsh3" => rtun.obfs.h3 = number(entry)?,
        "obfsh4" => rtun.obfs.h4 = number(entry)?,
        "paddingmax" => rtun.obfs.padding_max = number(entry)?,
        "junkcount" => rtun.obfs.junk_count = number(entry)?,
        "junkmin" => rtun.obfs.junk_min = number(entry)?,
        "junkmax" => rtun.obfs.junk_max = number(entry)?,
        "junkdelayminms" => rtun.obfs.junk_delay_min_ms = number(entry)?,
        "junkdelaymaxms" => rtun.obfs.junk_delay_max_ms = number(entry)?,
        "directsuffixes" => rtun.direct_suffixes = list(value),
        "directcidrs" => rtun.direct_cidrs = list(value),
        "tunneloverridecidrs" => rtun.tunnel_override_cidrs = list(value),
        "smartrouting" => rtun.smart_routing = boolean(entry)?,
        "tableid" => rtun.table_id = number(entry)?,
        "mark" => rtun.mark = number(entry)?,
        "killswitch" => rtun.kill_switch = boolean(entry)?,
        "loglevel" => rtun.log_level = value.to_string(),
        _ => return Err(unknown_key(entry)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{generate_private_key, public_key_from_private};

    fn sample_client() -> ClientConfig {
        let private = generate_private_key();
        let peer_private = generate_private_key();
        let mut cfg = ClientConfig::default();
        cfg.device.private_key = private;
        cfg.device.peer_public_key = public_key_from_private(&peer_private).unwrap();
        cfg.device.preshared_key = Some(generate_private_key());
        cfg.endpoint.host = "vpn.example.com".into();
        cfg.obfs = ObfsParams::generate();
        cfg
    }

    #[test]
    fn client_round_trip_is_lossless() {
        let cfg = sample_client();
        let wg = WgConf::from_client(&cfg);
        let text = wg.to_text();
        let parsed = WgConf::parse(&text).unwrap();
        assert_eq!(parsed, wg);
        assert_eq!(parsed.into_client().unwrap(), cfg);
    }

    #[test]
    fn ipv6_endpoint_is_bracketed() {
        let mut cfg = sample_client();
        cfg.endpoint.host = "2001:db8::1".into();
        let wg = WgConf::from_client(&cfg);
        let text = wg.to_text();
        assert!(text.contains("Endpoint = [2001:db8::1]:443"));
        assert_eq!(WgConf::parse(&text).unwrap().into_client().unwrap(), cfg);
    }

    #[test]
    fn comments_and_case_are_accepted() {
        let cfg = sample_client();
        let text = WgConf::from_client(&cfg).to_text();
        let noisy = format!(
            "# generated\n{}",
            text.replace("[Interface]", "[INTERFACE]")
                .replace("MTU = ", "mtu = ")
        );
        let parsed = WgConf::parse(&noisy).unwrap();
        assert_eq!(parsed.peer.endpoint_host, "vpn.example.com");
    }

    #[test]
    fn unknown_key_is_rejected() {
        let text = WgConf::from_client(&sample_client()).to_text();
        let bad = text.replace("MTU = ", "Mtuu = ");
        let error = WgConf::parse(&bad).unwrap_err().to_string();
        assert!(error.contains("unknown key mtuu"), "{error}");
    }

    #[test]
    fn invalid_key_is_rejected() {
        let text = WgConf::from_client(&sample_client()).to_text();
        let bad = text.replacen("PrivateKey = ", "PrivateKey = AAAA", 1);
        assert!(matches!(WgConf::parse(&bad), Err(ConfigError::Key(_))));
    }

    #[test]
    fn duplicate_section_is_rejected() {
        let text = WgConf::from_client(&sample_client()).to_text();
        let bad = format!("{text}\n[Peer]\nPublicKey = x\n");
        let error = WgConf::parse(&bad).unwrap_err().to_string();
        assert!(error.contains("duplicate section"), "{error}");
    }

    #[test]
    fn missing_peer_is_rejected() {
        let error = WgConf::parse("[Interface]\nPrivateKey = x\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing [Peer]"), "{error}");
    }

    #[test]
    fn key_outside_section_is_rejected() {
        let error = WgConf::parse("MTU = 1360\n").unwrap_err().to_string();
        assert!(error.contains("outside of any section"), "{error}");
    }

    #[test]
    fn interface_debug_redacts_private_key() {
        let wg = WgConf::from_client(&sample_client());
        let dump = format!("{:?}", wg.interface);
        assert!(!dump.contains(&wg.interface.private_key));
        assert!(dump.contains("<redacted>"));
    }

    #[test]
    fn save_and_load_round_trip() {
        let wg = WgConf::from_client(&sample_client());
        let dir = std::env::temp_dir().join(format!("rtun-wgconf-{}", std::process::id()));
        let path = dir.join("client.conf");
        wg.save(&path).unwrap();
        assert_eq!(WgConf::load(&path).unwrap(), wg);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
