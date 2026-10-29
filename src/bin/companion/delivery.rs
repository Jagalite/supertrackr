//! Bounded interface delivery, polled as one branch of the companion event loop.
use std::{
    collections::VecDeque,
    future::Future,
    io,
    time::{Duration, Instant},
};
const CAPACITY: usize = 128;
const MAX_AGE: Duration = Duration::from_millis(20);
struct Packet {
    bytes: Vec<u8>,
    until: Instant,
}
#[derive(Default)]
pub struct Queue {
    packets: VecDeque<Packet>,
}
impl Queue {
    pub fn push(&mut self, bytes: Vec<u8>, lease: Instant, now: Instant) -> bool {
        if self.packets.len() >= CAPACITY || lease <= now {
            return false;
        }
        self.packets.push_back(Packet {
            bytes,
            until: lease.min(now + MAX_AGE),
        });
        true
    }
    pub fn pop(&mut self) {
        self.packets.pop_front();
    }
    /// Cancellation is safe for Adapter::send: it waits for readiness before a
    /// single packet write. The owning loop pops only when this future completes.
    pub async fn send<'a, F, Fut>(&'a self, lease: Instant, send: F) -> bool
    where
        F: FnOnce(&'a [u8]) -> Fut,
        Fut: Future<Output = io::Result<usize>>,
    {
        let Some(p) = self.packets.front() else {
            return std::future::pending().await;
        };
        let until = p.until.min(lease);
        if Instant::now() >= until {
            return false;
        }
        tokio::select! {
            biased;
            _=tokio::time::sleep_until(until.into())=>false,
            result=send(&p.bytes)=>matches!(result,Ok(n) if n==p.bytes.len()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn stalled_delivery_is_bounded_and_does_not_block_events_or_expiry() {
        let now = Instant::now();
        let lease = now + Duration::from_secs(10);
        let mut q = Queue::default();
        for _ in 0..CAPACITY {
            assert!(q.push(vec![1; 1280], lease, now));
        }
        assert!(!q.push(vec![1], lease, now));
        // A blocked interface branch must leave independent work selectable.
        tokio::select! {
            biased;
            _=q.send(lease, |_|std::future::pending::<io::Result<usize>>())=>panic!("blocked send completed"),
            _=async {}=>{},
        }
        assert_eq!(q.packets.len(), CAPACITY);
        assert!(
            !q.send(lease, |_| std::future::pending::<io::Result<usize>>())
                .await
        );
        q.pop();
        // Already-expired packets must never call the underlying writer.
        assert!(
            !q.send(Instant::now(), |_| {
                panic!("expired delivery attempted");
                #[allow(unreachable_code)]
                std::future::ready(Ok(1))
            })
            .await
        );
        assert_eq!(q.packets.len(), CAPACITY - 1);
    }
}
