use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use base64::Engine;
use ipnet::IpNet;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::errors::ConfigError;
use crate::keys::{parse_private_key, parse_public_key};
use crate::routing::SuffixSet;

pub const DEFAULT_OBFS_MTU: u16 = 1360;
pub const DEFAULT_WS_MTU: u16 = 1280;
pub const DEFAULT_TABLE_ID: u32 = 51820;
pub const DEFAULT_MARK: u32 = 0x1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportKind {
    #[serde(rename = "obfs-udp")]
    ObfsUdp,
    #[serde(rename = "ws-tls")]
    WsTls,
}

impl TransportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ObfsUdp => "obfs-udp",
            Self::WsTls => "ws-tls",
        }
    }

    pub fn mtu(self) -> u16 {
        match self {
            Self::ObfsUdp => DEFAULT_OBFS_MTU,
            Self::WsTls => DEFAULT_WS_MTU,
        }
    }
}

impl fmt::Display for TransportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointConfig {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_ws_path")]
    pub ws_path: String,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default = "default_alpn")]
    pub alpn: String,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: default_port(),
            ws_path: default_ws_path(),
            server_name: None,
            alpn: default_alpn(),
        }
    }
}

impl EndpointConfig {
    pub fn tls_server_name(&self) -> &str {
        self.server_name.as_deref().unwrap_or(&self.host)
    }
}

fn default_port() -> u16 {
    443
}

fn default_ws_path() -> String {
    "/ws".to_string()
}

fn default_alpn() -> String {
    "http/1.1".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub private_key: String,
    pub peer_public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    #[serde(default = "default_client_v4")]
    pub address_v4: Ipv4Addr,
    #[serde(default = "default_client_v6")]
    pub address_v6: Ipv6Addr,
    #[serde(default = "default_obfs_mtu")]
    pub mtu_obfs: u16,
    #[serde(default = "default_ws_mtu")]
    pub mtu_ws: u16,
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive: u16,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            peer_public_key: String::new(),
            preshared_key: None,
            address_v4: default_client_v4(),
            address_v6: default_client_v6(),
            mtu_obfs: default_obfs_mtu(),
            mtu_ws: default_ws_mtu(),
            persistent_keepalive: default_keepalive(),
        }
    }
}

impl DeviceConfig {
    pub fn mtu_for(&self, kind: TransportKind) -> u16 {
        match kind {
            TransportKind::ObfsUdp => self.mtu_obfs,
            TransportKind::WsTls => self.mtu_ws,
        }
    }
}

fn default_client_v4() -> Ipv4Addr {
    Ipv4Addr::new(10, 66, 0, 2)
}

fn default_client_v6() -> Ipv6Addr {
    Ipv6Addr::new(0xfd66, 1, 0, 0, 0, 0, 0, 2)
}

fn default_obfs_mtu() -> u16 {
    DEFAULT_OBFS_MTU
}

fn default_ws_mtu() -> u16 {
    DEFAULT_WS_MTU
}

fn default_keepalive() -> u16 {
    25
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObfsParams {
    #[serde(default = "default_h1")]
    pub h1: u32,
    #[serde(default = "default_h2")]
    pub h2: u32,
    #[serde(default = "default_h3")]
    pub h3: u32,
    #[serde(default = "default_h4")]
    pub h4: u32,
    #[serde(default = "default_padding_max")]
    pub padding_max: u8,
    #[serde(default = "default_junk_count")]
    pub junk_count: u16,
    #[serde(default = "default_junk_min")]
    pub junk_min: u16,
    #[serde(default = "default_junk_max")]
    pub junk_max: u16,
    #[serde(default = "default_junk_delay_min")]
    pub junk_delay_min_ms: u16,
    #[serde(default = "default_junk_delay_max")]
    pub junk_delay_max_ms: u16,
}

impl fmt::Debug for ObfsParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfsParams")
            .field("h1", &"<redacted>")
            .field("h2", &"<redacted>")
            .field("h3", &"<redacted>")
            .field("h4", &"<redacted>")
            .field("padding_max", &self.padding_max)
            .field("junk_count", &self.junk_count)
            .field("junk_min", &self.junk_min)
            .field("junk_max", &self.junk_max)
            .field("junk_delay_min_ms", &self.junk_delay_min_ms)
            .field("junk_delay_max_ms", &self.junk_delay_max_ms)
            .finish()
    }
}

impl Default for ObfsParams {
    fn default() -> Self {
        Self {
            h1: 0x5254_5501,
            h2: 0x5254_5502,
            h3: 0x5254_5503,
            h4: 0x5254_5504,
            padding_max: default_padding_max(),
            junk_count: default_junk_count(),
            junk_min: default_junk_min(),
            junk_max: default_junk_max(),
            junk_delay_min_ms: default_junk_delay_min(),
            junk_delay_max_ms: default_junk_delay_max(),
        }
    }
}

fn default_h1() -> u32 {
    0x5254_5501
}
fn default_h2() -> u32 {
    0x5254_5502
}
fn default_h3() -> u32 {
    0x5254_5503
}
fn default_h4() -> u32 {
    0x5254_5504
}
fn default_padding_max() -> u8 {
    8
}
fn default_junk_count() -> u16 {
    4
}
fn default_junk_min() -> u16 {
    80
}
fn default_junk_max() -> u16 {
    300
}
fn default_junk_delay_min() -> u16 {
    5
}
fn default_junk_delay_max() -> u16 {
    15
}

impl ObfsParams {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        loop {
            let mut values = [0u32; 4];
            for value in &mut values {
                let mut raw = [0u8; 4];
                rng.fill_bytes(&mut raw);
                *value = u32::from_le_bytes(raw) | 1;
            }
            if values[0] != values[1]
                && values[0] != values[2]
                && values[0] != values[3]
                && values[1] != values[2]
                && values[1] != values[3]
                && values[2] != values[3]
            {
                return Self {
                    h1: values[0],
                    h2: values[1],
                    h3: values[2],
                    h4: values[3],
                    ..Self::default()
                };
            }
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let magics = [self.h1, self.h2, self.h3, self.h4];
        for (index, magic) in magics.iter().enumerate() {
            if *magic == 0 {
                return Err(ConfigError::Invalid("obfs magic must not be zero".into()));
            }
            if magics[..index].contains(magic) {
                return Err(ConfigError::Invalid(
                    "obfs magic headers must be distinct".into(),
                ));
            }
        }
        if self.padding_max > 64 {
            return Err(ConfigError::Invalid(
                "obfs padding_max must be <= 64".into(),
            ));
        }
        if self.junk_count > 64 {
            return Err(ConfigError::Invalid("obfs junk_count must be <= 64".into()));
        }
        if self.junk_min > self.junk_max || self.junk_max > 1400 || self.junk_min < 32 {
            return Err(ConfigError::Invalid(
                "obfs junk size range must satisfy 32 <= min <= max <= 1400".into(),
            ));
        }
        if self.junk_delay_min_ms > self.junk_delay_max_ms {
            return Err(ConfigError::Invalid(
                "obfs junk delay range is inverted".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportPrefs {
    #[serde(default = "default_priority")]
    pub priority: Vec<TransportKind>,
    #[serde(default = "default_ws_delay")]
    pub ws_start_delay_ms: u64,
    #[serde(default = "default_health_interval")]
    pub health_interval_secs: u64,
    #[serde(default = "default_health_misses")]
    pub health_misses: u8,
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_ms: u64,
    #[serde(default = "default_probe_interval")]
    pub probe_interval_secs: u64,
    #[serde(default = "default_gain_pct")]
    pub preferred_gain_pct: u8,
    #[serde(default = "default_min_switch_interval")]
    pub min_switch_interval_secs: u64,
}

impl Default for TransportPrefs {
    fn default() -> Self {
        Self {
            priority: default_priority(),
            ws_start_delay_ms: default_ws_delay(),
            health_interval_secs: default_health_interval(),
            health_misses: default_health_misses(),
            handshake_timeout_ms: default_handshake_timeout(),
            probe_interval_secs: default_probe_interval(),
            preferred_gain_pct: default_gain_pct(),
            min_switch_interval_secs: default_min_switch_interval(),
        }
    }
}

fn default_priority() -> Vec<TransportKind> {
    vec![TransportKind::ObfsUdp, TransportKind::WsTls]
}
fn default_ws_delay() -> u64 {
    300
}
fn default_health_interval() -> u64 {
    5
}
fn default_health_misses() -> u8 {
    3
}
fn default_handshake_timeout() -> u64 {
    4000
}
fn default_probe_interval() -> u64 {
    300
}
fn default_gain_pct() -> u8 {
    30
}
fn default_min_switch_interval() -> u64 {
    300
}

impl TransportPrefs {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.priority.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one transport must be configured".into(),
            ));
        }
        for (index, kind) in self.priority.iter().enumerate() {
            if self.priority[..index].contains(kind) {
                return Err(ConfigError::Invalid(
                    "transport priority contains duplicates".into(),
                ));
            }
        }
        if self.health_interval_secs == 0 || self.health_misses == 0 {
            return Err(ConfigError::Invalid(
                "health check interval and miss count must be positive".into(),
            ));
        }
        if self.preferred_gain_pct > 100 {
            return Err(ConfigError::Invalid(
                "preferred_gain_pct must be <= 100".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoIpConfig {
    #[serde(default = "default_geoip_v4")]
    pub v4_url: String,
    #[serde(default = "default_geoip_v6")]
    pub v6_url: String,
    #[serde(default = "default_geoip_update_hours")]
    pub update_hours: u64,
    #[serde(default = "default_geoip_max_age_hours")]
    pub max_age_hours: u64,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            v4_url: default_geoip_v4(),
            v6_url: default_geoip_v6(),
            update_hours: default_geoip_update_hours(),
            max_age_hours: default_geoip_max_age_hours(),
        }
    }
}

fn default_geoip_v4() -> String {
    "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone".into()
}
fn default_geoip_v6() -> String {
    "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ru-aggregated.zone".into()
}
fn default_geoip_update_hours() -> u64 {
    168
}
fn default_geoip_max_age_hours() -> u64 {
    336
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingConfig {
    #[serde(default = "default_suffixes")]
    pub direct_suffixes: Vec<String>,
    #[serde(default)]
    pub direct_cidrs: Vec<String>,
    #[serde(default)]
    pub tunnel_override_cidrs: Vec<String>,
    #[serde(default)]
    pub geoip: GeoIpConfig,
    #[serde(default = "default_table_id")]
    pub table_id: u32,
    #[serde(default = "default_mark")]
    pub mark: u32,
    #[serde(default = "default_true")]
    pub smart_routing: bool,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            direct_suffixes: default_suffixes(),
            direct_cidrs: Vec::new(),
            tunnel_override_cidrs: Vec::new(),
            geoip: GeoIpConfig::default(),
            table_id: default_table_id(),
            mark: default_mark(),
            smart_routing: true,
        }
    }
}

fn default_suffixes() -> Vec<String> {
    vec![
        "ru".into(),
        "рф".into(),
        "xn--p1ai".into(),
        "su".into(),
        "moscow".into(),
        "москва".into(),
        "xn--80adxhks".into(),
    ]
}

fn default_table_id() -> u32 {
    DEFAULT_TABLE_ID
}

fn default_mark() -> u32 {
    DEFAULT_MARK
}

fn parse_cidrs(values: &[String], field: &str) -> Result<Vec<IpNet>, ConfigError> {
    values
        .iter()
        .map(|value| {
            value.parse::<IpNet>().map_err(|error| {
                ConfigError::Invalid(format!("invalid CIDR in {field}: {value}: {error}"))
            })
        })
        .collect()
}

impl RoutingConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        SuffixSet::new(self.direct_suffixes.iter().map(String::as_str))?;
        parse_cidrs(&self.direct_cidrs, "direct_cidrs")?;
        parse_cidrs(&self.tunnel_override_cidrs, "tunnel_override_cidrs")?;
        if self.mark == 0 {
            return Err(ConfigError::Invalid("routing mark must be non-zero".into()));
        }
        if self.table_id < 1 || self.table_id > 2_147_483_647 {
            return Err(ConfigError::Invalid(
                "routing table id must be in 1..=2147483647".into(),
            ));
        }
        Ok(())
    }

    pub fn suffix_set(&self) -> Result<SuffixSet, ConfigError> {
        SuffixSet::new(self.direct_suffixes.iter().map(String::as_str))
    }

    pub fn direct_nets(&self) -> Result<Vec<IpNet>, ConfigError> {
        parse_cidrs(&self.direct_cidrs, "direct_cidrs")
    }

    pub fn override_nets(&self) -> Result<Vec<IpNet>, ConfigError> {
        parse_cidrs(&self.tunnel_override_cidrs, "tunnel_override_cidrs")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_dns_listen")]
    pub listen: Vec<SocketAddr>,
    #[serde(default = "default_dns_server_v4")]
    pub server_v4: Ipv4Addr,
    #[serde(default = "default_dns_server_v6")]
    pub server_v6: Ipv6Addr,
    #[serde(default = "default_intercept_stub")]
    pub intercept_stub: bool,
    #[serde(default = "default_doh_fallback")]
    pub doh_fallback: bool,
    #[serde(default)]
    pub direct_upstreams: Vec<IpAddr>,
    #[serde(default = "default_true")]
    pub use_system_direct_upstreams: bool,
    #[serde(default)]
    pub degraded: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            listen: default_dns_listen(),
            server_v4: default_dns_server_v4(),
            server_v6: default_dns_server_v6(),
            intercept_stub: default_intercept_stub(),
            doh_fallback: default_doh_fallback(),
            direct_upstreams: Vec::new(),
            use_system_direct_upstreams: true,
            degraded: false,
        }
    }
}

fn default_dns_listen() -> Vec<SocketAddr> {
    vec![
        "127.0.0.53:53".parse().expect("valid address"),
        "127.0.0.1:53".parse().expect("valid address"),
        "[::1]:53".parse().expect("valid address"),
    ]
}

fn default_dns_server_v4() -> Ipv4Addr {
    Ipv4Addr::new(10, 66, 0, 1)
}

fn default_dns_server_v6() -> Ipv6Addr {
    Ipv6Addr::new(0xfd66, 1, 0, 0, 0, 0, 0, 1)
}

fn default_intercept_stub() -> bool {
    true
}

fn default_doh_fallback() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    pub endpoint: EndpointConfig,
    pub device: DeviceConfig,
    #[serde(default)]
    pub obfs: ObfsParams,
    #[serde(default)]
    pub transports: TransportPrefs,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default = "default_true")]
    pub kill_switch: bool,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            endpoint: EndpointConfig::default(),
            device: DeviceConfig::default(),
            obfs: ObfsParams::default(),
            transports: TransportPrefs::default(),
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
            kill_switch: true,
            log_level: default_log_level(),
        }
    }
}

impl ClientConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.endpoint.host.trim().is_empty() {
            return Err(ConfigError::Invalid("endpoint host is empty".into()));
        }
        if self.endpoint.port == 0 {
            return Err(ConfigError::Invalid("endpoint port is zero".into()));
        }
        if !self.endpoint.ws_path.starts_with('/') {
            return Err(ConfigError::Invalid(
                "websocket path must start with '/'".into(),
            ));
        }
        if self.endpoint.alpn != "http/1.1" {
            return Err(ConfigError::Invalid(
                "websocket transport requires ALPN http/1.1".into(),
            ));
        }
        parse_private_key(&self.device.private_key)?;
        parse_public_key(&self.device.peer_public_key)?;
        if let Some(psk) = &self.device.preshared_key {
            parse_public_key(psk)?;
        }
        if !(1280..=1500).contains(&self.device.mtu_obfs) {
            return Err(ConfigError::Invalid(
                "mtu_obfs must be in 1280..=1500".into(),
            ));
        }
        if !(1280..=1500).contains(&self.device.mtu_ws) {
            return Err(ConfigError::Invalid("mtu_ws must be in 1280..=1500".into()));
        }
        self.obfs.validate()?;
        self.transports.validate()?;
        self.routing.validate()?;
        if self.dns.listen.is_empty() {
            return Err(ConfigError::Invalid("dns listen list is empty".into()));
        }
        Ok(())
    }

    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn to_toml(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| ConfigError::Invalid(format!("cannot read config: {error}")))?;
        Self::from_toml(&text)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        write_secure(path.as_ref(), self.to_toml()?.as_bytes())
    }

    pub fn preshared_key_bytes(&self) -> Result<Option<[u8; 32]>, ConfigError> {
        match &self.device.preshared_key {
            Some(value) => Ok(Some(crate::keys::parse_private_key(value)?)),
            None => Ok(None),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub private_key: String,
    #[serde(default = "default_server_tun")]
    pub tun_name: String,
    #[serde(default = "default_server_v4")]
    pub address_v4: Ipv4Addr,
    #[serde(default = "default_server_v6")]
    pub address_v6: Ipv6Addr,
    #[serde(default = "default_server_prefix_v4")]
    pub prefix_v4: u8,
    #[serde(default = "default_server_prefix_v6")]
    pub prefix_v6: u8,
    #[serde(default = "default_server_obfs_listen")]
    pub obfs_listen: Vec<SocketAddr>,
    #[serde(default = "default_server_ws_listen")]
    pub ws_listen: SocketAddr,
    #[serde(default = "default_server_peers_dir")]
    pub peers_dir: String,
    #[serde(default)]
    pub obfs: ObfsParams,
    #[serde(default = "default_server_mtu")]
    pub mtu: u16,
    #[serde(default = "default_wg_port")]
    pub listen_port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            tun_name: default_server_tun(),
            address_v4: default_server_v4(),
            address_v6: default_server_v6(),
            prefix_v4: default_server_prefix_v4(),
            prefix_v6: default_server_prefix_v6(),
            obfs_listen: default_server_obfs_listen(),
            ws_listen: default_server_ws_listen(),
            peers_dir: default_server_peers_dir(),
            obfs: ObfsParams::default(),
            mtu: default_server_mtu(),
            listen_port: default_wg_port(),
            log_level: default_log_level(),
        }
    }
}

fn default_server_tun() -> String {
    "rtun0".into()
}
fn default_server_v4() -> Ipv4Addr {
    Ipv4Addr::new(10, 66, 0, 1)
}
fn default_server_v6() -> Ipv6Addr {
    Ipv6Addr::new(0xfd66, 1, 0, 0, 0, 0, 0, 1)
}
fn default_server_prefix_v4() -> u8 {
    24
}
fn default_server_prefix_v6() -> u8 {
    64
}
fn default_server_obfs_listen() -> Vec<SocketAddr> {
    vec![
        "0.0.0.0:443".parse().expect("valid address"),
        "[::]:443".parse().expect("valid address"),
    ]
}
fn default_server_ws_listen() -> SocketAddr {
    "127.0.0.1:9443".parse().expect("valid address")
}
fn default_server_peers_dir() -> String {
    "/etc/rtun/peers".into()
}
fn default_server_mtu() -> u16 {
    DEFAULT_OBFS_MTU
}
fn default_wg_port() -> u16 {
    443
}

impl ServerConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.prefix_v4 > 32 || self.prefix_v6 > 128 {
            return Err(ConfigError::Invalid("invalid tunnel prefix length".into()));
        }
        if !(1280..=1500).contains(&self.mtu) {
            return Err(ConfigError::Invalid(
                "server mtu must be in 1280..=1500".into(),
            ));
        }
        if self.obfs_listen.is_empty() {
            return Err(ConfigError::Invalid("obfs listen list is empty".into()));
        }
        parse_private_key(&self.private_key).map_err(|error| {
            ConfigError::Invalid(format!("invalid server private key: {error}"))
        })?;
        if self.private_key.trim().is_empty() {
            return Err(ConfigError::Invalid("server private key is empty".into()));
        }
        self.obfs.validate()?;
        Ok(())
    }

    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn to_toml(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| ConfigError::Invalid(format!("cannot read config: {error}")))?;
        Self::from_toml(&text)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        write_secure(path.as_ref(), self.to_toml()?.as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerConfig {
    pub name: String,
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    pub address_v4: Ipv4Addr,
    pub address_v6: Ipv6Addr,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl PeerConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::Invalid("peer name is empty".into()));
        }
        if !self
            .name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        {
            return Err(ConfigError::Invalid(
                "peer name may contain only ASCII alphanumerics, '.', '_' and '-'".into(),
            ));
        }
        parse_public_key(&self.public_key)?;
        if let Some(psk) = &self.preshared_key {
            parse_public_key(psk)?;
        }
        Ok(())
    }

    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let peer: Self = toml::from_str(text)?;
        peer.validate()?;
        Ok(peer)
    }

    pub fn to_toml(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }
}

pub fn write_secure(path: &Path, contents: &[u8]) -> Result<(), ConfigError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                ConfigError::Invalid(format!("cannot create config directory: {error}"))
            })?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| ConfigError::Invalid(format!("cannot write config: {error}")))?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| ConfigError::Invalid(format!("cannot set permissions: {error}")))?;
        file.write_all(contents)
            .map_err(|error| ConfigError::Invalid(format!("cannot write config: {error}")))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
            .map_err(|error| ConfigError::Invalid(format!("cannot write config: {error}")))
    }
}

pub fn random_psk() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn random_private_key() -> String {
    crate::keys::generate_private_key()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_client() -> ClientConfig {
        let private = crate::keys::generate_private_key();
        let public = crate::keys::public_key_from_private(&private).unwrap();
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
            ..ClientConfig::default()
        }
    }

    #[test]
    fn default_client_config_roundtrips() {
        let config = valid_client();
        let text = config.to_toml().unwrap();
        let parsed = ClientConfig::from_toml(&text).unwrap();
        assert_eq!(config, parsed);
        assert_eq!(parsed.device.mtu_for(TransportKind::ObfsUdp), 1360);
        assert_eq!(parsed.device.mtu_for(TransportKind::WsTls), 1280);
    }

    #[test]
    fn rejects_h2_alpn() {
        let mut config = valid_client();
        config.endpoint.alpn = "h2".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_obfs_magic() {
        let mut config = valid_client();
        config.obfs.h2 = config.obfs.h1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn generated_obfs_params_are_distinct() {
        let params = ObfsParams::generate();
        params.validate().unwrap();
        assert_ne!(params.h1, params.h2);
        assert_ne!(params.h2, params.h3);
        assert_ne!(params.h3, params.h4);
    }

    #[test]
    fn debug_redacts_magic() {
        let params = ObfsParams::default();
        let text = format!("{params:?}");
        assert!(!text.contains(&format!("{:x}", params.h1)));
    }

    #[test]
    fn server_config_roundtrips() {
        let config = ServerConfig {
            private_key: crate::keys::generate_private_key(),
            ..ServerConfig::default()
        };
        let text = config.to_toml().unwrap();
        let parsed = ServerConfig::from_toml(&text).unwrap();
        assert_eq!(config, parsed);
        assert_eq!(parsed.obfs_listen.len(), 2);
    }

    #[test]
    fn peer_config_rejects_path_injection() {
        let peer = PeerConfig {
            name: "../evil".into(),
            public_key: crate::keys::public_key_from_private(&crate::keys::generate_private_key())
                .unwrap(),
            preshared_key: None,
            address_v4: Ipv4Addr::new(10, 66, 0, 9),
            address_v6: Ipv6Addr::new(0xfd66, 1, 0, 0, 0, 0, 0, 9),
            enabled: true,
        };
        assert!(peer.validate().is_err());
    }

    #[test]
    fn rejects_global_unicast_override_zero_mark() {
        let mut config = valid_client();
        config.routing.mark = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn psk_is_valid_key_material() {
        let psk = random_psk();
        assert_eq!(crate::keys::parse_private_key(&psk).unwrap().len(), 32);
    }
}
