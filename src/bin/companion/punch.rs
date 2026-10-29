//! Endpoint-only hole punching. Hints never install keys or authorize inner IP traffic.
use super::*;
use std::collections::HashMap;
struct Attempt {
    until: Instant,
    next: Instant,
}
pub struct Puncher {
    attempts: HashMap<SocketAddr, Attempt>,
    pub dropped: u64,
    pub hints: u64,
}
impl Puncher {
    pub fn new() -> Self {
        Self {
            attempts: HashMap::new(),
            dropped: 0,
            hints: 0,
        }
    }
    pub fn add(&mut self, hint: supertrackr::PunchHint, at: Instant, now: Instant, network: bool) {
        self.attempts.retain(|_, a| a.until > now);
        if !(2..=5).contains(&hint.remaining_seconds)
            || hint.candidates.is_empty()
            || hint.candidates.len() > 8
            || hint.candidates.iter().any(|&v| !allowed(v, network))
        {
            self.dropped += 1;
            return;
        }
        let until = (at + Duration::from_secs(hint.remaining_seconds - 1))
            .min(now + Duration::from_secs(3));
        if until <= now {
            self.dropped += 1;
            return;
        }
        self.hints += 1;
        for endpoint in hint.candidates {
            if self.attempts.len() >= 64 && !self.attempts.contains_key(&endpoint) {
                self.dropped += 1;
                continue;
            }
            self.attempts.insert(endpoint, Attempt { until, next: now });
        }
    }
    pub fn due(&mut self, now: Instant) -> Vec<(SocketAddr, [u8; 16])> {
        self.attempts.retain(|_, a| a.until > now);
        let mut out = vec![];
        for (&addr, a) in &mut self.attempts {
            if a.next <= now {
                let mut packet = [0; 16];
                packet[..4].copy_from_slice(b"STH1");
                packet[4..].copy_from_slice(&rand::random::<[u8; 12]>());
                out.push((addr, packet));
                a.next = now + Duration::from_millis(300);
            }
        }
        out
    }
    pub fn is_probe(p: &[u8]) -> bool {
        p.len() == 16 && p.starts_with(b"STH1")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hints_are_bounded_expire_and_do_not_cause_reply_loops() {
        let now = Instant::now();
        let mut p = Puncher::new();
        for port in 1000..1100 {
            p.add(
                supertrackr::PunchHint {
                    binding: None,
                    candidates: vec![format!("127.0.0.1:{port}").parse().unwrap()],
                    remaining_seconds: 5,
                },
                now,
                now,
                false,
            );
        }
        assert_eq!(p.attempts.len(), 64);
        assert_eq!(p.dropped, 36);
        let first = p.due(now);
        assert_eq!(first.len(), 64);
        assert!(Puncher::is_probe(&first[0].1));
        assert!(p.due(now).is_empty());
        assert!(p.due(now + Duration::from_secs(3)).is_empty());
        assert!(p.attempts.is_empty());
        p.add(
            supertrackr::PunchHint {
                binding: None,
                candidates: vec!["192.0.2.1:1".parse().unwrap()],
                remaining_seconds: 5,
            },
            now,
            now,
            false,
        );
        assert!(p.attempts.is_empty());
        p.add(
            supertrackr::PunchHint {
                binding: None,
                candidates: vec!["127.0.0.1:1".parse().unwrap()],
                remaining_seconds: 2,
            },
            now,
            now + Duration::from_secs(2),
            false,
        );
        assert!(p.attempts.is_empty());
    }
}
