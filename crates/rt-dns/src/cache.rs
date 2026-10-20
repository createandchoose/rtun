use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub record_type: u16,
}

impl CacheKey {
    pub fn new(name: &str, record_type: u16) -> Self {
        Self {
            name: name.trim_end_matches('.').to_ascii_lowercase(),
            record_type,
        }
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
    inserted_at: Instant,
}

#[derive(Debug)]
pub struct DnsCache {
    entries: HashMap<CacheKey, CacheEntry>,
    max_entries: usize,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: max_entries.max(16),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&mut self, key: &CacheKey, now: Instant) -> Option<Vec<u8>> {
        let entry = self.entries.get(key)?;
        if entry.expires_at <= now {
            self.entries.remove(key);
            return None;
        }
        Some(entry.response.clone())
    }

    pub fn insert(&mut self, key: CacheKey, response: Vec<u8>, ttl: u32, now: Instant) {
        if ttl == 0 || self.max_entries == 0 {
            return;
        }
        self.evict(now);
        if self.entries.len() >= self.max_entries {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.inserted_at)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            key,
            CacheEntry {
                response,
                expires_at: now + Duration::from_secs(u64::from(ttl)),
                inserted_at: now,
            },
        );
    }

    pub fn evict(&mut self, now: Instant) {
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_hit_and_expiry() {
        let mut cache = DnsCache::new(10);
        let now = Instant::now();
        let key = CacheKey::new("Example.COM.", 1);
        assert!(cache.get(&key, now).is_none());
        cache.insert(key.clone(), vec![1, 2, 3], 60, now);
        assert_eq!(
            cache.get(&key, now + Duration::from_secs(30)).unwrap(),
            vec![1, 2, 3]
        );
        assert!(cache.get(&key, now + Duration::from_secs(61)).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn zero_ttl_is_not_cached() {
        let mut cache = DnsCache::new(10);
        let now = Instant::now();
        let key = CacheKey::new("example.com", 1);
        cache.insert(key.clone(), vec![1], 0, now);
        assert!(cache.get(&key, now).is_none());
    }

    #[test]
    fn bounded_cache_evicts_oldest() {
        let mut cache = DnsCache::new(16);
        let now = Instant::now();
        for index in 0..32 {
            cache.insert(
                CacheKey::new(&format!("name{index}.example"), 1),
                vec![index as u8],
                60,
                now + Duration::from_millis(index),
            );
        }
        assert_eq!(cache.len(), 16);
        assert!(cache
            .get(
                &CacheKey::new("name0.example", 1),
                now + Duration::from_secs(1)
            )
            .is_none());
        assert!(cache
            .get(
                &CacheKey::new("name31.example", 1),
                now + Duration::from_secs(1)
            )
            .is_some());
    }
}
