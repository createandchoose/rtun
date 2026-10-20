pub mod cache;
pub mod error;
pub mod proxy;
pub mod split;
pub mod stub;

pub use cache::{CacheKey, DnsCache};
pub use error::{DnsError, Result};
pub use proxy::{spawn, DnsEvent, DnsProxy, DnsProxyHandle, DnsSettings};
pub use split::{discover_direct_upstreams, SplitPolicy, UpstreamClass};
pub use stub::{ResolvedManager, TakeoverMode};
