use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use rand::Rng;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

use crate::error::{Result, TransportError};
use crate::ws::tls_client_config;

const CACHE_TTL: Duration = Duration::from_secs(300);
const DOH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DOH_RESPONSE: usize = 64 * 1024;

#[derive(Debug, Clone)]
struct CacheEntry {
    addresses: Vec<SocketAddr>,
    fetched_at: Instant,
}

#[derive(Debug, Clone)]
pub struct EndpointResolver {
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    doh: Option<DohResolver>,
}

impl EndpointResolver {
    pub fn new(use_doh: bool) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            doh: if use_doh {
                Some(DohResolver::cloudflare())
            } else {
                None
            },
        }
    }

    pub fn disabled_doh() -> Self {
        Self::new(false)
    }

    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let key = format!("{host}:{port}");
        let cache = self.cache.lock().await;
        let cached = cache.get(&key).cloned();
        drop(cache);

        let fetched = match &self.doh {
            Some(doh) => match doh.resolve(host, port).await {
                Ok(addresses) if !addresses.is_empty() => Ok(addresses),
                _ => resolve_system(host, port).await,
            },
            None => resolve_system(host, port).await,
        };

        match fetched {
            Ok(addresses) if !addresses.is_empty() => {
                let entry = CacheEntry {
                    addresses: addresses.clone(),
                    fetched_at: Instant::now(),
                };
                self.cache.lock().await.insert(key, entry);
                Ok(addresses)
            }
            _ => match cached {
                Some(entry) => Ok(entry.addresses),
                None => Err(TransportError::Resolve(format!(
                    "no addresses found for {host}"
                ))),
            },
        }
    }

    pub async fn last_known_good(&self, host: &str, port: u16) -> Option<Vec<SocketAddr>> {
        let cache = self.cache.lock().await;
        cache
            .get(&format!("{host}:{port}"))
            .map(|entry| entry.addresses.clone())
    }

    pub async fn cache_is_fresh(&self, host: &str, port: u16) -> bool {
        let cache = self.cache.lock().await;
        cache
            .get(&format!("{host}:{port}"))
            .map(|entry| entry.fetched_at.elapsed() < CACHE_TTL)
            .unwrap_or(false)
    }
}

pub async fn resolve_endpoint(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let resolver = EndpointResolver::disabled_doh();
    resolver.resolve(host, port).await
}

async fn resolve_system(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| TransportError::Resolve(format!("{host}: {error}")))?
        .collect::<Vec<_>>();
    Ok(interleave_families(addresses))
}

pub fn interleave_families(mut addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addresses.sort_by_key(|address| if address.is_ipv6() { 0 } else { 1 });
    let mut v6 = Vec::new();
    let mut v4 = Vec::new();
    for address in addresses {
        if address.is_ipv6() {
            v6.push(address);
        } else {
            v4.push(address);
        }
    }
    let mut ordered = Vec::with_capacity(v6.len() + v4.len());
    let mut v6_iter = v6.into_iter();
    let mut v4_iter = v4.into_iter();
    loop {
        let mut pushed = false;
        if let Some(address) = v6_iter.next() {
            ordered.push(address);
            pushed = true;
        }
        if let Some(address) = v4_iter.next() {
            ordered.push(address);
            pushed = true;
        }
        if !pushed {
            break;
        }
    }
    ordered
}

#[derive(Debug, Clone)]
pub struct DohResolver {
    servers: Vec<IpAddr>,
    tls: Arc<rustls::ClientConfig>,
}

impl DohResolver {
    pub fn new(servers: Vec<IpAddr>) -> Self {
        Self {
            servers,
            tls: tls_client_config(&["http/1.1"]),
        }
    }

    pub fn cloudflare() -> Self {
        Self::new(vec![
            "1.1.1.1".parse().expect("valid address"),
            "9.9.9.9".parse().expect("valid address"),
        ])
    }

    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let a = self.query(host, RecordType::A).await;
        let aaaa = self.query(host, RecordType::AAAA).await;
        let mut addresses = Vec::new();
        if let Ok(records) = aaaa {
            addresses.extend(records.into_iter().map(|ip| SocketAddr::new(ip, port)));
        }
        if let Ok(records) = a {
            addresses.extend(records.into_iter().map(|ip| SocketAddr::new(ip, port)));
        }
        if addresses.is_empty() {
            return Err(TransportError::Resolve(format!(
                "DoH returned no records for {host}"
            )));
        }
        Ok(interleave_families(addresses))
    }

    async fn query(&self, host: &str, record_type: RecordType) -> Result<Vec<IpAddr>> {
        let mut message = Message::new(rand::thread_rng().gen(), MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        let name = Name::from_ascii(host)
            .map_err(|error| TransportError::Resolve(format!("invalid hostname: {error}")))?;
        message.add_query(Query::query(name, record_type));
        let wire = message.to_vec().map_err(|error| {
            TransportError::Resolve(format!("cannot encode DNS query: {error}"))
        })?;
        let encoded = URL_SAFE_NO_PAD.encode(wire);
        let mut last_error = None;
        for server in &self.servers {
            match tokio::time::timeout(DOH_TIMEOUT, self.query_server(*server, host, &encoded))
                .await
            {
                Ok(Ok(records)) if !records.is_empty() => return Ok(records),
                Ok(Ok(_)) => last_error = Some(TransportError::Resolve("empty DoH answer".into())),
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => last_error = Some(TransportError::Timeout),
            }
        }
        Err(last_error.unwrap_or_else(|| TransportError::Resolve("DoH failed".into())))
    }

    async fn query_server(
        &self,
        server: IpAddr,
        host: &str,
        encoded_query: &str,
    ) -> Result<Vec<IpAddr>> {
        let address = SocketAddr::new(server, 443);
        let tcp = TcpStream::connect(address).await?;
        let server_name = ServerName::IpAddress(server.into());
        let connector = TlsConnector::from(self.tls.clone());
        let mut stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|error| TransportError::Tls(format!("DoH TLS handshake: {error}")))?;
        let request = format!(
            "GET /dns-query?dns={encoded_query} HTTP/1.1\r\nHost: {host}\r\nAccept: application/dns-message\r\nUser-Agent: rtun\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..read]);
            if response.len() > MAX_DOH_RESPONSE {
                return Err(TransportError::Resolve("DoH response too large".into()));
            }
            if let Some(header_end) = find_header_end(&response) {
                if let Some(length) = content_length(&response[..header_end]) {
                    if response.len() >= header_end + 4 + length {
                        break;
                    }
                }
            }
        }
        parse_http_dns_response(&response)
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(headers).ok()?;
    for line in text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse().ok();
        }
    }
    None
}

fn parse_http_dns_response(response: &[u8]) -> Result<Vec<IpAddr>> {
    let header_end = find_header_end(response)
        .ok_or_else(|| TransportError::Resolve("truncated DoH HTTP response".into()))?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| TransportError::Resolve("invalid DoH HTTP headers".into()))?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    if status != 200 {
        return Err(TransportError::Resolve(format!(
            "DoH server returned HTTP {status}"
        )));
    }
    let body = &response[header_end + 4..];
    let message = Message::from_vec(body)
        .map_err(|error| TransportError::Resolve(format!("invalid DoH DNS answer: {error}")))?;
    let mut addresses = Vec::new();
    for record in &message.answers {
        match &record.data {
            RData::A(address) => addresses.push(IpAddr::V4(address.0)),
            RData::AAAA(address) => addresses.push(IpAddr::V6(address.0)),
            _ => {}
        }
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, Record};

    #[test]
    fn interleaves_families() {
        let addresses = vec![
            "1.1.1.1:443".parse().unwrap(),
            "2.2.2.2:443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
        ];
        let ordered = interleave_families(addresses);
        assert!(ordered[0].is_ipv6());
        assert!(ordered[1].is_ipv4());
        assert!(ordered[2].is_ipv6());
        assert!(ordered[3].is_ipv4());
    }

    #[test]
    fn parses_doh_http_response() {
        let name = Name::from_ascii("example.com").unwrap();
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(
            name,
            60,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        ));
        let wire = message.to_vec().unwrap();
        let mut response =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: "
                .to_vec();
        response.extend_from_slice(wire.len().to_string().as_bytes());
        response.extend_from_slice(b"\r\n\r\n");
        response.extend_from_slice(&wire);
        let addresses = parse_http_dns_response(&response).unwrap();
        assert_eq!(
            addresses,
            vec![IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))]
        );
    }

    #[test]
    fn rejects_non_200_doh() {
        let response = b"HTTP/1.1 503 Service Unavailable\r\n\r\n";
        assert!(parse_http_dns_response(response).is_err());
    }
}
