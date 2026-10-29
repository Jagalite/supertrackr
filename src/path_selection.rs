//! Bounded, round-trip-validated path selection. Called only after WireGuard authentication.
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};
const TRUST: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const CAP: usize = 16;
struct Path {
    configured: bool,
    seen: Instant,
    pending: Option<(u64, Instant)>,
    pong: Option<(Instant, Duration)>,
}
#[derive(Default)]
pub(crate) struct Paths {
    paths: HashMap<SocketAddr, Path>,
    selected: Option<SocketAddr>,
}
impl Paths {
    pub fn configure(&mut self, addresses: &[SocketAddr], now: Instant) {
        // Withdrawn advertised endpoints lose their measurements and pending challenges.
        self.paths
            .retain(|addr, p| !p.configured || addresses.contains(addr));
        self.prune(now);
        for &addr in addresses {
            if !self.paths.contains_key(&addr)
                && self.paths.len() >= CAP
                && let Some(old) = self
                    .paths
                    .iter()
                    .filter(|(_, p)| !p.configured)
                    .min_by_key(|(_, p)| p.seen)
                    .map(|(&addr, _)| addr)
            {
                self.paths.remove(&old);
            }
            self.paths
                .entry(addr)
                .and_modify(|p| p.configured = true)
                .or_insert(Path {
                    configured: true,
                    seen: now,
                    pending: None,
                    pong: None,
                });
        }
        self.prune(now);
    }
    pub fn learn(&mut self, addr: SocketAddr, now: Instant) {
        self.prune(now);
        if let Some(p) = self.paths.get_mut(&addr) {
            p.seen = now;
        } else if self.paths.len() < CAP {
            self.paths.insert(
                addr,
                Path {
                    configured: false,
                    seen: now,
                    pending: None,
                    pong: None,
                },
            );
        }
    }
    fn prune(&mut self, now: Instant) {
        self.paths.retain(|_, p| {
            p.configured || now.saturating_duration_since(p.seen) < Duration::from_secs(10)
        });
    }
    pub fn targets(&mut self, now: Instant) -> Vec<SocketAddr> {
        self.prune(now);
        self.paths.keys().copied().collect()
    }
    pub fn challenge(&mut self, addr: SocketAddr, now: Instant) -> Option<u64> {
        let p = self.paths.get_mut(&addr)?;
        let nonce = rand::random();
        p.pending = Some((nonce, now));
        Some(nonce)
    }
    pub fn confirm(&mut self, addr: SocketAddr, nonce: u64, now: Instant) -> bool {
        let Some(p) = self.paths.get_mut(&addr) else {
            return false;
        };
        let Some((expected, sent)) = p.pending else {
            return false;
        };
        if expected != nonce || now < sent || now.duration_since(sent) > PROBE_TIMEOUT {
            return false;
        }
        p.pending = None;
        let measured = now.duration_since(sent);
        let rtt = p.pong.map_or(measured, |(_, old)| {
            old.mul_f64(0.75) + measured.mul_f64(0.25)
        });
        p.pong = Some((now, rtt));
        let old = self
            .selected
            .and_then(|addr| self.fresh(addr, now).map(|rtt| (addr, rtt)));
        let best = self
            .paths
            .keys()
            .filter_map(|&addr| self.fresh(addr, now).map(|rtt| (addr, rtt)))
            .min_by_key(|(addr, rtt)| (*rtt, *addr));
        if let Some((candidate, rtt)) = best {
            // Require a material improvement to avoid oscillating between similar paths.
            if old.is_none_or(|(addr, current)| addr == candidate || rtt < current.mul_f64(0.75)) {
                self.selected = Some(candidate);
            }
        }
        true
    }
    fn fresh(&self, addr: SocketAddr, now: Instant) -> Option<Duration> {
        let (at, rtt) = self.paths.get(&addr)?.pong?;
        (now.saturating_duration_since(at) < TRUST).then_some(rtt)
    }
    pub fn best(&self, now: Instant) -> Option<SocketAddr> {
        self.selected
            .filter(|&addr| self.fresh(addr, now).is_some())
            .or_else(|| {
                self.paths
                    .keys()
                    .filter_map(|&addr| self.fresh(addr, now).map(|rtt| (rtt, addr)))
                    .min()
                    .map(|(_, addr)| addr)
            })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn challenges_bind_nonce_endpoint_and_time_and_prefer_stable_low_latency() {
        let now = Instant::now();
        let a = "127.0.0.1:1".parse().unwrap();
        let b = "127.0.0.1:2".parse().unwrap();
        let mut p = Paths::default();
        p.configure(&[a, b], now);
        let n = p.challenge(a, now).unwrap();
        assert!(!p.confirm(b, n, now));
        assert!(!p.confirm(a, n ^ 1, now));
        assert_eq!(p.best(now), None);
        assert!(p.confirm(a, n, now + Duration::from_millis(100)));
        assert!(!p.confirm(a, n, now + Duration::from_millis(101)));
        let n = p.challenge(b, now).unwrap();
        assert!(p.confirm(b, n, now + Duration::from_millis(90)));
        assert_eq!(p.best(now + Duration::from_millis(101)), Some(a));
        let n = p.challenge(b, now + Duration::from_secs(1)).unwrap();
        assert!(p.confirm(b, n, now + Duration::from_millis(1010)));
        assert_eq!(p.best(now + Duration::from_millis(1010)), Some(b));
        let n = p.challenge(a, now).unwrap();
        assert!(!p.confirm(a, n, now + Duration::from_secs(3)));
        assert_eq!(p.best(now + Duration::from_secs(7)), None);
    }
    #[test]
    fn observed_addresses_cannot_select_paths_and_state_is_bounded() {
        let now = Instant::now();
        let mut p = Paths::default();
        for port in 1..100 {
            p.learn(SocketAddr::from(([127, 0, 0, 1], port)), now);
        }
        assert_eq!(p.targets(now).len(), 16);
        assert_eq!(p.best(now), None);
        assert!(p.targets(now + Duration::from_secs(10)).is_empty());
        let a = SocketAddr::from(([127, 0, 0, 1], 1));
        p.configure(&[a], now);
        let n = p.challenge(a, now).unwrap();
        assert!(p.confirm(a, n, now));
        p.configure(&[], now);
        assert_eq!(p.best(now), None);
    }
}
