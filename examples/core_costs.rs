//! Diagnostic only: actual core methods, Statelessness clock/histograms, counted allocator.
//! Allocation/timer instrumentation affects absolute timings; no HTTP capacity claim.
use serde_json::json;
use statelessness_debug::effects::{Clock, ClockDomain, MonotonicClock};
use statelessness_debug::metrics::{
    GaugeScope, HistogramSchema, LabelCatalog, Labels, MetricFamily, MetricLimits, MetricsStore,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
};
use supertrackr::{
    Config,
    core::{Credentials, Key, Registry},
    model::{Lease, valid},
};
struct Counted;
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
// SAFETY: every allocation/deallocation is forwarded unchanged to System.
unsafe impl GlobalAlloc for Counted {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(layout.size() as u64, Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(layout.size() as u64, Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(size as u64, Relaxed);
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Counted = Counted;
fn key(i: usize) -> Key {
    let mut k = [0; 32];
    k[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
    k
}
fn measured<T>(clock: &MonotonicClock, f: impl FnOnce() -> T) -> (T, u64, u64, u64) {
    let a = ALLOCS.load(Relaxed);
    let b = BYTES.load(Relaxed);
    let start = clock.now().unwrap();
    let value = black_box(f());
    let ns = clock.now().unwrap().elapsed_since(start).unwrap();
    (value, ns, ALLOCS.load(Relaxed) - a, BYTES.load(Relaxed) - b)
}
fn report(name: &str, n: usize, repeat: usize, mut samples: Vec<u64>, allocs: u64, bytes: u64) {
    let mut metrics = MetricsStore::new(
        1,
        None,
        LabelCatalog {
            operations: vec![name.into()],
            ..Default::default()
        },
        HistogramSchema::default(),
        MetricLimits::default(),
        GaugeScope::CompleteParticipation,
    )
    .unwrap();
    for &ns in &samples {
        metrics.observe(MetricFamily::AttemptElapsed, Labels::default(), ns);
    }
    let snapshot = metrics.snapshot(None);
    assert!(snapshot.complete);
    assert_eq!(snapshot.health.omitted_measurements, 0);
    assert_eq!(snapshot.health.rejected_series, 0);
    samples.sort_unstable();
    let len = samples.len();
    println!(
        "{}",
        json!({"operation":name,"population":n,"repeat":repeat,"samples":len,
        "min_ns":samples[0],"p50_ns":samples[(len-1)/2],"p99_ns":samples[(len-1)*99/100],"max_ns":samples[len-1],
        "total_ns":samples.iter().map(|&v|v as u128).sum::<u128>(),"allocations":allocs,"allocated_bytes":bytes,
        "statelessness_metrics_complete":snapshot.complete,"histogram":format!("{:?}",snapshot.series)})
    );
}
fn sample(
    clock: &MonotonicClock,
    name: &str,
    n: usize,
    repeat: usize,
    count: usize,
    mut f: impl FnMut(),
) {
    let mut samples = Vec::with_capacity(count);
    let (mut allocations, mut bytes) = (0, 0);
    for _ in 0..count {
        let (_, ns, a, b) = measured(clock, &mut f);
        samples.push(ns);
        allocations += a;
        bytes += b;
    }
    report(name, n, repeat, samples, allocations, bytes);
}
fn main() {
    let clock = MonotonicClock::new(ClockDomain(1));
    let endpoint: SocketAddr = "127.0.0.1:51820".parse().unwrap();
    for repeat in 0..3 {
        for n in [10_000, 100_000, 1_000_000] {
            let (mut registry, ns, allocs, bytes) = measured(&clock, || {
                Registry::new(Config {
                    capacity: n + 1,
                    ttl_seconds: 3600,
                    open_registration: true,
                })
            });
            report("initialize", n, repeat, vec![ns], allocs, bytes);
            let mut times = Vec::with_capacity(n);
            let mut growth = Vec::with_capacity(64);
            let (mut allocations, mut bytes) = (0, 0);
            for i in 0..n {
                let k = key(i);
                let (result, ns, a, b) = measured(&clock, || {
                    registry.register_or_refresh(k, endpoint, None, [7; 32], 0)
                });
                result.unwrap();
                times.push(ns);
                allocations += a;
                bytes += b;
                if a > 0 {
                    growth.push(json!({"size":i+1,"ns":ns,"allocations":a,"requested_bytes":b}));
                }
            }
            assert_eq!(registry.len(), n);
            println!(
                "{}",
                json!({"operation":"registration_growth_events","population":n,"repeat":repeat,"events":growth})
            );
            report("register", n, repeat, times, allocations, bytes);
            let mut i = 0;
            sample(&clock, "refresh", n, repeat, 10_000, || {
                let k = key(i % n);
                i += 1;
                black_box(
                    registry
                        .register_or_refresh(
                            k,
                            endpoint,
                            Some(Credentials {
                                key: k,
                                token_hash: [7; 32],
                            }),
                            [0; 32],
                            0,
                        )
                        .unwrap(),
                );
            });
            let mut i = 0;
            sample(&clock, "verify", n, repeat, 10_000, || {
                let caller = Credentials {
                    key: key(i % n),
                    token_hash: [7; 32],
                };
                i += 1;
                black_box(
                    registry
                        .verify_peer(caller, key(i % n), endpoint, 1)
                        .unwrap(),
                );
            });
            let caller = Credentials {
                key: key(0),
                token_hash: [7; 32],
            };
            for limit in [20, 100] {
                sample(
                    &clock,
                    &format!("discovery_{limit}"),
                    n,
                    repeat,
                    10_000,
                    || {
                        let peers = registry.get_peers(caller, limit, 1).unwrap();
                        assert_eq!(peers.len(), limit);
                        black_box(peers);
                    },
                );
            }
            sample(&clock, "cleanup_batch_live", n, repeat, 100, || {
                registry.cleanup_batch(1, 4096);
                assert_eq!(registry.len(), n);
            });
            sample(&clock, "cleanup_live", n, repeat, 10, || {
                registry.cleanup(1);
                assert_eq!(registry.len(), n);
            });
            registry
                .register_or_refresh(caller.key, endpoint, Some(caller), [0; 32], 3599)
                .unwrap();
            sample(&clock, "discovery_expired_4096", n, repeat, 100, || {
                assert!(registry.get_peers(caller, 20, 3600).unwrap().is_empty());
            });
            sample(&clock, "cleanup_expired", n, repeat, 1, || {
                registry.cleanup(3600);
                assert_eq!(registry.len(), 1);
            });
            sample(&clock, "cleanup_sparse", n, repeat, 10, || {
                registry.cleanup(3600);
                assert_eq!(registry.len(), 1);
            });
            drop(registry);
            let mut expired = Registry::new(Config {
                capacity: n + 1,
                ttl_seconds: 3600,
                open_registration: true,
            });
            for i in 0..n {
                expired
                    .register_or_refresh(key(i), endpoint, None, [7; 32], 0)
                    .unwrap();
            }
            sample(
                &clock,
                "cleanup_batch_expired",
                n,
                repeat,
                n.div_ceil(4096),
                || {
                    expired.cleanup_batch(3600, 4096);
                },
            );
            assert!(expired.is_empty());
        }
    }
    sample(&clock, "timer_control", 0, 0, 100_000, || {
        black_box(());
    });
    for (name, now) in [("lease_live", 1), ("lease_expired", 3600)] {
        sample(&clock, name, 0, 0, 100_000, || {
            black_box(valid(
                black_box(Lease {
                    expires: 3600,
                    active: true,
                }),
                black_box(now),
            ));
        });
    }
}
