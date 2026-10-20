use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::RData;
use rt_proto::{ClientConfig, SuffixSet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Mutex, Semaphore};
use tracing::{debug, warn};

use crate::cache::{CacheKey, DnsCache};
use crate::error::{DnsError, Result};
use crate::split::{discover_direct_upstreams, SplitPolicy, UpstreamClass};

#[derive(Debug, Clone)]
pub struct DnsEvent {
    pub name: String,
    pub addresses: Vec<IpAddr>,
    pub direct_domain: bool,
    pub ttl: u32,
}

#[derive(Debug, Clone)]
pub struct DnsSettings {
    pub listen: Vec<SocketAddr>,
    pub tunnel_upstreams: Vec<SocketAddr>,
    pub direct_upstreams: Vec<SocketAddr>,
    pub suffixes: SuffixSet,
    pub smart_routing: bool,
    pub degraded: bool,
    pub timeout: Duration,
}

impl DnsSettings {
    pub fn from_config(config: &ClientConfig, degraded: bool) -> Result<Self> {
        let suffixes = config
            .routing
            .suffix_set()
            .map_err(|error| DnsError::Config(error.to_string()))?;
        let tunnel_upstreams = vec![
            SocketAddr::new(IpAddr::V4(config.dns.server_v4), 53),
            SocketAddr::new(IpAddr::V6(config.dns.server_v6), 53),
        ];
        let direct_upstreams = if config.dns.direct_upstreams.is_empty() {
            discover_direct_upstreams(&[
                std::path::Path::new("/run/systemd/resolve/resolv.conf"),
                std::path::Path::new("/etc/resolv.conf"),
            ])
            .into_iter()
            .map(|ip| SocketAddr::new(ip, 53))
            .collect()
        } else {
            config
                .dns
                .direct_upstreams
                .iter()
                .map(|ip| SocketAddr::new(*ip, 53))
                .collect()
        };
        Ok(Self {
            listen: config.dns.listen.clone(),
            tunnel_upstreams,
            direct_upstreams,
            suffixes,
            smart_routing: config.routing.smart_routing,
            degraded: degraded || config.dns.degraded,
            timeout: Duration::from_secs(5),
        })
    }

    pub fn with_listen(mut self, listen: Vec<SocketAddr>) -> Self {
        self.listen = listen;
        self
    }
}

pub struct DnsProxy {
    settings: DnsSettings,
    split: SplitPolicy,
    cache: Mutex<DnsCache>,
    feedback: mpsc::Sender<DnsEvent>,
}

impl DnsProxy {
    pub fn new(settings: DnsSettings, feedback: mpsc::Sender<DnsEvent>) -> Self {
        let split = SplitPolicy::new(
            settings.suffixes.clone(),
            settings.smart_routing,
            settings.degraded,
        );
        Self {
            settings,
            split,
            cache: Mutex::new(DnsCache::new(4096)),
            feedback,
        }
    }

    pub fn classify(&self, domain: &str) -> UpstreamClass {
        self.split.classify(domain)
    }

    pub async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>> {
        let (name, record_type) = parse_query(query)?;
        let class = self.split.classify(&name);
        let key = CacheKey::new(&name, record_type);
        if let Some(mut cached) = self.cache.lock().await.get(&key, Instant::now()) {
            if let (Some(query_id), true) = (query_id(query), cached.len() >= 2) {
                cached[0..2].copy_from_slice(&query_id.to_be_bytes());
            }
            return Ok(cached);
        }
        let upstreams = match class {
            UpstreamClass::Direct => &self.settings.direct_upstreams,
            UpstreamClass::Tunnel => &self.settings.tunnel_upstreams,
        };
        if upstreams.is_empty() {
            return Err(DnsError::NoUpstream);
        }
        let response = self.exchange(upstreams, query).await?;
        let (ttl, addresses) = analyze_response(&response)?;
        if !addresses.is_empty() {
            self.cache
                .lock()
                .await
                .insert(key, response.clone(), ttl, Instant::now());
            let event = DnsEvent {
                name,
                addresses,
                direct_domain: class == UpstreamClass::Direct,
                ttl,
            };
            let _ = self.feedback.try_send(event);
        }
        Ok(response)
    }

    async fn exchange(&self, upstreams: &[SocketAddr], query: &[u8]) -> Result<Vec<u8>> {
        let mut last_error = None;
        for upstream in upstreams {
            match exchange_udp(*upstream, query, self.settings.timeout).await {
                Ok(response) => {
                    if is_truncated(&response) {
                        match exchange_tcp(*upstream, query, self.settings.timeout).await {
                            Ok(response) => return Ok(response),
                            Err(error) => {
                                last_error = Some(error);
                                continue;
                            }
                        }
                    }
                    return Ok(response);
                }
                Err(error) => {
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or(DnsError::NoUpstream))
    }
}

fn parse_query(query: &[u8]) -> Result<(String, u16)> {
    let message = Message::from_vec(query)
        .map_err(|error| DnsError::Message(format!("cannot parse query: {error}")))?;
    let question = message
        .queries
        .first()
        .ok_or_else(|| DnsError::Message("query has no questions".into()))?;
    let name = question
        .name()
        .to_ascii()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    Ok((name, u16::from(question.query_type())))
}

fn analyze_response(response: &[u8]) -> Result<(u32, Vec<IpAddr>)> {
    let message = Message::from_vec(response)
        .map_err(|error| DnsError::Message(format!("cannot parse response: {error}")))?;
    let mut addresses = Vec::new();
    let mut ttl = u32::MAX;
    for record in &message.answers {
        ttl = ttl.min(record.ttl);
        match &record.data {
            RData::A(address) => addresses.push(IpAddr::V4(address.0)),
            RData::AAAA(address) => addresses.push(IpAddr::V6(address.0)),
            _ => {}
        }
    }
    if ttl == u32::MAX {
        ttl = 0;
    }
    Ok((ttl, addresses))
}

fn is_truncated(response: &[u8]) -> bool {
    Message::from_vec(response)
        .map(|message| message.metadata.truncation)
        .unwrap_or(false)
}

async fn exchange_udp(server: SocketAddr, query: &[u8], timeout: Duration) -> Result<Vec<u8>> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid address")
    } else {
        "[::]:0".parse().expect("valid address")
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.send_to(query, server).await?;
    let mut buffer = vec![0u8; 65_535];
    let (len, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buffer))
        .await
        .map_err(|_| DnsError::Timeout)??;
    let response = buffer[..len].to_vec();
    if query_id(&response) != query_id(query) {
        return Err(DnsError::Message("upstream response id mismatch".into()));
    }
    Ok(response)
}

async fn exchange_tcp(server: SocketAddr, query: &[u8], timeout: Duration) -> Result<Vec<u8>> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(server))
        .await
        .map_err(|_| DnsError::Timeout)??;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed).await?;
    let mut length = [0u8; 2];
    tokio::time::timeout(timeout, stream.read_exact(&mut length))
        .await
        .map_err(|_| DnsError::Timeout)??;
    let length = u16::from_be_bytes(length) as usize;
    let mut response = vec![0u8; length];
    tokio::time::timeout(timeout, stream.read_exact(&mut response))
        .await
        .map_err(|_| DnsError::Timeout)??;
    Ok(response)
}

fn query_id(data: &[u8]) -> Option<u16> {
    if data.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([data[0], data[1]]))
}

fn servfail(query: &[u8]) -> Vec<u8> {
    let Ok(mut message) = Message::from_vec(query) else {
        return Vec::new();
    };
    message.metadata.message_type = MessageType::Response;
    message.metadata.response_code = ResponseCode::ServFail;
    message.to_vec().unwrap_or_default()
}

pub struct DnsProxyHandle {
    shutdown: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl DnsProxyHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        }
    }
}

pub async fn spawn(
    settings: DnsSettings,
    feedback: mpsc::Sender<DnsEvent>,
) -> Result<DnsProxyHandle> {
    let proxy = Arc::new(DnsProxy::new(settings.clone(), feedback));
    let (shutdown, _) = watch::channel(false);
    let mut tasks = Vec::new();
    let semaphore = Arc::new(Semaphore::new(256));

    for address in &settings.listen {
        let udp = UdpSocket::bind(address)
            .await
            .map_err(|error| DnsError::Config(format!("cannot bind DNS UDP {address}: {error}")))?;
        let tcp = TcpListener::bind(address)
            .await
            .map_err(|error| DnsError::Config(format!("cannot bind DNS TCP {address}: {error}")))?;
        let udp = Arc::new(udp);
        let mut shutdown_rx = shutdown.subscribe();
        let proxy_udp = proxy.clone();
        let sem = semaphore.clone();
        tasks.push(tokio::spawn(async move {
            let mut buffer = vec![0u8; 65_535];
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    result = udp.recv_from(&mut buffer) => {
                        let Ok((len, peer)) = result else { continue; };
                        let query = buffer[..len].to_vec();
                        let proxy = proxy_udp.clone();
                        let udp = udp.clone();
                        let permit = match sem.clone().acquire_owned().await {
                            Ok(permit) => permit,
                            Err(_) => break,
                        };
                        tokio::spawn(async move {
                            let _permit = permit;
                            let response = match proxy.resolve(&query).await {
                                Ok(response) => response,
                                Err(error) => {
                                    debug!(%error, "DNS query failed");
                                    servfail(&query)
                                }
                            };
                            if !response.is_empty() {
                                let _ = udp.send_to(&response, peer).await;
                            }
                        });
                    }
                }
            }
        }));

        let mut shutdown_rx = shutdown.subscribe();
        let proxy_tcp = proxy.clone();
        let sem = semaphore.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    result = tcp.accept() => {
                        let Ok((stream, peer)) = result else { continue; };
                        let proxy = proxy_tcp.clone();
                        let permit = match sem.clone().acquire_owned().await {
                            Ok(permit) => permit,
                            Err(_) => break,
                        };
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(error) = serve_tcp(stream, peer, proxy).await {
                                debug!(%error, "DNS TCP connection failed");
                            }
                        });
                    }
                }
            }
        }));
    }
    if tasks.is_empty() {
        return Err(DnsError::Config("no DNS listen addresses".into()));
    }
    Ok(DnsProxyHandle { shutdown, tasks })
}

async fn serve_tcp(mut stream: TcpStream, peer: SocketAddr, proxy: Arc<DnsProxy>) -> Result<()> {
    let mut length = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut length))
        .await
        .map_err(|_| DnsError::Timeout)??;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 {
        return Err(DnsError::Message("empty DNS TCP message".into()));
    }
    let mut query = vec![0u8; length];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut query))
        .await
        .map_err(|_| DnsError::Timeout)??;
    let response = proxy.resolve(&query).await.unwrap_or_else(|error| {
        debug!(%error, %peer, "DNS TCP query failed");
        servfail(&query)
    });
    let mut framed = Vec::with_capacity(response.len() + 2);
    framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
    framed.extend_from_slice(&response);
    stream.write_all(&framed).await?;
    Ok(())
}

pub fn warn_degraded(settings: &DnsSettings) {
    if settings.degraded {
        warn!("DNS domain rules disabled: running in GeoIP-only degraded mode");
    } else if settings.direct_upstreams.is_empty() {
        warn!("no direct DNS upstream discovered; direct-domain queries will fail");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, Record, RecordType};
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc;

    async fn fake_upstream(address: SocketAddr, ip: Ipv4Addr) -> Arc<UdpSocket> {
        let socket = Arc::new(UdpSocket::bind(address).await.unwrap());
        let server = socket.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = server.recv_from(&mut buffer).await else {
                    break;
                };
                let query = Message::from_vec(&buffer[..len]).unwrap();
                let question = query.queries.first().unwrap();
                let mut response =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                response.add_query(question.clone());
                response.add_answer(Record::from_rdata(
                    question.name().clone(),
                    60,
                    RData::A(A(ip)),
                ));
                let _ = server.send_to(&response.to_vec().unwrap(), peer).await;
            }
        });
        socket
    }

    fn settings(tunnel: SocketAddr, direct: SocketAddr) -> DnsSettings {
        DnsSettings {
            listen: Vec::new(),
            tunnel_upstreams: vec![tunnel],
            direct_upstreams: vec![direct],
            suffixes: SuffixSet::new(["ru"]).unwrap(),
            smart_routing: true,
            degraded: false,
            timeout: Duration::from_secs(2),
        }
    }

    fn query(name: &str) -> Vec<u8> {
        query_with_id(name, 42)
    }

    fn query_with_id(name: &str, id: u16) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        message.to_vec().unwrap()
    }

    #[tokio::test]
    async fn routes_domain_to_correct_upstream() {
        let tunnel =
            fake_upstream("127.0.0.1:0".parse().unwrap(), Ipv4Addr::new(10, 66, 0, 1)).await;
        let direct = fake_upstream("127.0.0.1:0".parse().unwrap(), Ipv4Addr::new(5, 5, 5, 5)).await;
        let (tx, mut rx) = mpsc::channel(16);
        let proxy = DnsProxy::new(
            settings(tunnel.local_addr().unwrap(), direct.local_addr().unwrap()),
            tx,
        );
        let response = proxy.resolve(&query("example.ru")).await.unwrap();
        let (_, addresses) = analyze_response(&response).unwrap();
        assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5))]);
        let event = rx.recv().await.unwrap();
        assert!(event.direct_domain);
        assert_eq!(event.name, "example.ru");

        let response = proxy.resolve(&query("example.com")).await.unwrap();
        let (_, addresses) = analyze_response(&response).unwrap();
        assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))]);
        let event = rx.recv().await.unwrap();
        assert!(!event.direct_domain);
    }

    #[tokio::test]
    async fn cache_avoids_second_upstream_query() {
        let tunnel =
            fake_upstream("127.0.0.1:0".parse().unwrap(), Ipv4Addr::new(10, 66, 0, 1)).await;
        let direct = fake_upstream("127.0.0.1:0".parse().unwrap(), Ipv4Addr::new(5, 5, 5, 5)).await;
        let (tx, mut rx) = mpsc::channel(16);
        let proxy = DnsProxy::new(
            settings(tunnel.local_addr().unwrap(), direct.local_addr().unwrap()),
            tx,
        );
        let first = proxy
            .resolve(&query_with_id("example.com", 42))
            .await
            .unwrap();
        rx.recv().await.unwrap();
        let second = proxy
            .resolve(&query_with_id("example.com", 4242))
            .await
            .unwrap();
        assert_eq!(Message::from_vec(&first).unwrap().metadata.id, 42);
        assert_eq!(Message::from_vec(&second).unwrap().metadata.id, 4242);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn degraded_mode_uses_tunnel_upstream() {
        let tunnel =
            fake_upstream("127.0.0.1:0".parse().unwrap(), Ipv4Addr::new(10, 66, 0, 1)).await;
        let direct = fake_upstream("127.0.0.1:0".parse().unwrap(), Ipv4Addr::new(5, 5, 5, 5)).await;
        let (tx, _rx) = mpsc::channel(16);
        let mut cfg = settings(tunnel.local_addr().unwrap(), direct.local_addr().unwrap());
        cfg.degraded = true;
        let proxy = DnsProxy::new(cfg, tx);
        let response = proxy.resolve(&query("example.ru")).await.unwrap();
        let (_, addresses) = analyze_response(&response).unwrap();
        assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))]);
    }

    #[tokio::test]
    async fn no_upstream_returns_error_and_servfail() {
        let (tx, _rx) = mpsc::channel(16);
        let mut cfg = settings(
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        cfg.direct_upstreams.clear();
        let proxy = DnsProxy::new(cfg, tx);
        assert!(proxy.resolve(&query("example.ru")).await.is_err());
        let failure = servfail(&query("example.ru"));
        let message = Message::from_vec(&failure).unwrap();
        assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
    }

    #[test]
    fn classifies_without_network() {
        let cfg = settings(
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (tx, _rx) = mpsc::channel(1);
        let proxy = DnsProxy::new(cfg, tx);
        assert_eq!(proxy.classify("a.ru"), UpstreamClass::Direct);
        assert_eq!(proxy.classify("a.com"), UpstreamClass::Tunnel);
    }
}
