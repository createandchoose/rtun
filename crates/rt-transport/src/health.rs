use std::collections::HashMap;
use std::time::Duration;

use rt_proto::{TransportKind, TransportPrefs};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkKey {
    pub ssid: Option<String>,
    pub gateway: Option<String>,
}

impl NetworkKey {
    pub fn new(ssid: Option<String>, gateway: Option<String>) -> Self {
        Self { ssid, gateway }
    }

    pub fn unknown() -> Self {
        Self {
            ssid: None,
            gateway: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthConfig {
    pub misses: u8,
    pub handshake_timeout: Duration,
    pub min_switch_interval: Duration,
    pub gain_pct: u8,
    pub probe_interval: Duration,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            misses: 3,
            handshake_timeout: Duration::from_secs(4),
            min_switch_interval: Duration::from_secs(300),
            gain_pct: 30,
            probe_interval: Duration::from_secs(300),
        }
    }
}

impl From<&TransportPrefs> for HealthConfig {
    fn from(prefs: &TransportPrefs) -> Self {
        Self {
            misses: prefs.health_misses,
            handshake_timeout: Duration::from_millis(prefs.handshake_timeout_ms),
            min_switch_interval: Duration::from_secs(prefs.min_switch_interval_secs),
            gain_pct: prefs.preferred_gain_pct,
            probe_interval: Duration::from_secs(prefs.probe_interval_secs),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverDecision {
    Stay,
    Switch(TransportKind),
    GiveUp,
}

#[derive(Debug, Clone)]
pub struct FailoverController {
    config: HealthConfig,
    priority: Vec<TransportKind>,
    active: TransportKind,
    misses: u8,
    handshake_started_ms: Option<u64>,
    last_switch_ms: Option<u64>,
    last_probe_ms: Option<u64>,
    rtt_ms: HashMap<TransportKind, f64>,
    preferences: HashMap<NetworkKey, TransportKind>,
    network: NetworkKey,
}

impl FailoverController {
    pub fn new(config: HealthConfig, priority: Vec<TransportKind>, now_ms: u64) -> Self {
        assert!(!priority.is_empty(), "transport priority is empty");
        let active = priority[0];
        Self {
            config,
            priority,
            active,
            misses: 0,
            handshake_started_ms: None,
            last_switch_ms: Some(now_ms),
            last_probe_ms: Some(now_ms),
            rtt_ms: HashMap::new(),
            preferences: HashMap::new(),
            network: NetworkKey::unknown(),
        }
    }

    pub fn active(&self) -> TransportKind {
        self.active
    }

    pub fn network(&self) -> &NetworkKey {
        &self.network
    }

    pub fn set_network(&mut self, key: NetworkKey, now_ms: u64) {
        if key == self.network {
            return;
        }
        self.network = key.clone();
        self.misses = 0;
        self.handshake_started_ms = None;
        self.last_switch_ms = Some(now_ms);
        if let Some(preferred) = self.preferences.get(&key) {
            self.active = *preferred;
        } else {
            self.active = self.priority[0];
        }
    }

    pub fn preferences(&self) -> &HashMap<NetworkKey, TransportKind> {
        &self.preferences
    }

    pub fn start_handshake(&mut self, now_ms: u64) {
        self.handshake_started_ms = Some(now_ms);
    }

    pub fn handshake_completed(&mut self) {
        self.handshake_started_ms = None;
        self.misses = 0;
    }

    pub fn record_success(&mut self, kind: TransportKind, rtt_ms: f64, now_ms: u64) {
        self.rtt_ms.insert(kind, rtt_ms);
        if kind == self.active {
            self.misses = 0;
            self.handshake_started_ms = None;
        }
        self.last_probe_ms = Some(now_ms);
    }

    pub fn record_miss(&mut self, now_ms: u64) -> FailoverDecision {
        if let Some(started) = self.handshake_started_ms {
            if now_ms.saturating_sub(started) >= self.config.handshake_timeout.as_millis() as u64 {
                return self.failover(now_ms);
            }
        }
        self.misses = self.misses.saturating_add(1);
        if self.misses >= self.config.misses {
            self.failover(now_ms)
        } else {
            FailoverDecision::Stay
        }
    }

    pub fn manual_switch(&mut self, kind: TransportKind, now_ms: u64) -> bool {
        if !self.priority.contains(&kind) {
            return false;
        }
        self.active = kind;
        self.misses = 0;
        self.handshake_started_ms = None;
        self.last_switch_ms = Some(now_ms);
        self.preferences.insert(self.network.clone(), kind);
        true
    }

    pub fn failover(&mut self, now_ms: u64) -> FailoverDecision {
        let index = self
            .priority
            .iter()
            .position(|kind| *kind == self.active)
            .unwrap_or(0);
        if self.priority.len() <= 1 {
            return FailoverDecision::GiveUp;
        }
        let next = self.priority[(index + 1) % self.priority.len()];
        if next == self.active {
            return FailoverDecision::GiveUp;
        }
        self.active = next;
        self.misses = 0;
        self.handshake_started_ms = None;
        self.last_switch_ms = Some(now_ms);
        self.preferences.insert(self.network.clone(), next);
        FailoverDecision::Switch(next)
    }

    pub fn should_probe(&self, now_ms: u64) -> bool {
        match self.last_probe_ms {
            Some(last) => {
                now_ms.saturating_sub(last) >= self.config.probe_interval.as_millis() as u64
            }
            None => true,
        }
    }

    pub fn consider_better(
        &mut self,
        candidate: TransportKind,
        candidate_rtt_ms: f64,
        now_ms: u64,
    ) -> bool {
        if candidate == self.active || !self.priority.contains(&candidate) {
            return false;
        }
        if let Some(last) = self.last_switch_ms {
            if now_ms.saturating_sub(last) < self.config.min_switch_interval.as_millis() as u64 {
                return false;
            }
        }
        let Some(active_rtt) = self.rtt_ms.get(&self.active).copied() else {
            return false;
        };
        if active_rtt <= 0.0 || candidate_rtt_ms <= 0.0 {
            return false;
        }
        let gain = (active_rtt - candidate_rtt_ms) / active_rtt * 100.0;
        if gain > f64::from(self.config.gain_pct) {
            self.active = candidate;
            self.last_switch_ms = Some(now_ms);
            self.misses = 0;
            self.preferences.insert(self.network.clone(), candidate);
            true
        } else {
            false
        }
    }

    pub fn rtt(&self, kind: TransportKind) -> Option<f64> {
        self.rtt_ms.get(&kind).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller() -> FailoverController {
        FailoverController::new(
            HealthConfig::default(),
            vec![TransportKind::ObfsUdp, TransportKind::WsTls],
            0,
        )
    }

    #[test]
    fn three_misses_switch_transport() {
        let mut controller = controller();
        assert_eq!(controller.record_miss(5_000), FailoverDecision::Stay);
        assert_eq!(controller.record_miss(10_000), FailoverDecision::Stay);
        assert_eq!(
            controller.record_miss(15_000),
            FailoverDecision::Switch(TransportKind::WsTls)
        );
        assert_eq!(controller.active(), TransportKind::WsTls);
    }

    #[test]
    fn handshake_timeout_switches_without_waiting_for_misses() {
        let mut controller = controller();
        controller.start_handshake(1_000);
        assert_eq!(
            controller.record_miss(5_100),
            FailoverDecision::Switch(TransportKind::WsTls)
        );
    }

    #[test]
    fn success_resets_misses() {
        let mut controller = controller();
        controller.record_miss(1_000);
        controller.record_miss(2_000);
        controller.record_success(TransportKind::ObfsUdp, 20.0, 3_000);
        assert_eq!(controller.record_miss(4_000), FailoverDecision::Stay);
    }

    #[test]
    fn anti_flap_blocks_early_switch_back() {
        let mut controller = controller();
        controller.record_success(TransportKind::ObfsUdp, 100.0, 0);
        controller.record_success(TransportKind::WsTls, 20.0, 0);
        assert!(!controller.consider_better(TransportKind::ObfsUdp, 20.0, 100_000));
        controller.failover(10_000);
        assert!(!controller.consider_better(TransportKind::ObfsUdp, 10.0, 20_000));
    }

    #[test]
    fn switch_back_requires_gain() {
        let mut controller = controller();
        controller.record_success(TransportKind::ObfsUdp, 100.0, 0);
        controller.failover(0);
        controller.record_success(TransportKind::WsTls, 80.0, 0);
        assert!(!controller.consider_better(TransportKind::ObfsUdp, 80.0, 400_000));
        assert!(controller.consider_better(TransportKind::ObfsUdp, 50.0, 400_000));
        assert_eq!(controller.active(), TransportKind::ObfsUdp);
    }

    #[test]
    fn network_preference_is_remembered() {
        let mut controller = controller();
        let home = NetworkKey::new(Some("home".into()), Some("192.168.1.1".into()));
        controller.set_network(home.clone(), 0);
        controller.manual_switch(TransportKind::WsTls, 0);
        let other = NetworkKey::new(Some("cafe".into()), Some("10.0.0.1".into()));
        controller.set_network(other, 10_000);
        assert_eq!(controller.active(), TransportKind::ObfsUdp);
        controller.set_network(home, 20_000);
        assert_eq!(controller.active(), TransportKind::WsTls);
    }

    #[test]
    fn duplicate_network_does_not_reset_state() {
        let mut controller = controller();
        let home = NetworkKey::new(Some("home".into()), None);
        controller.set_network(home.clone(), 0);
        controller.record_miss(1_000);
        controller.set_network(home, 2_000);
        assert_eq!(controller.misses, 1);
    }

    #[test]
    fn probe_interval_is_respected() {
        let controller = controller();
        assert!(!controller.should_probe(100_000));
        assert!(controller.should_probe(300_000));
    }

    #[test]
    fn single_transport_gives_up() {
        let mut controller =
            FailoverController::new(HealthConfig::default(), vec![TransportKind::ObfsUdp], 0);
        assert_eq!(controller.failover(1_000), FailoverDecision::GiveUp);
    }
}
