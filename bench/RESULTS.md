# Native prototype measurements — 2026-10-28

The API was subsequently changed to register/refresh, get peers, and verify peer.
Earlier lookup/brokering figures below are historical and do not measure the new API.
See the final section for the current API smoke test.

Executed on macOS 26.5.2 arm64 using loopback plaintext HTTP/1.1. Aquatic comparison is deferred. No VM is required; the Colima default VM and its data disk were deleted after the local-only decision.

Each measured interval lasted 10 seconds, with 10,000 initial registrations, 32 load workers, bounded worker queues, and two Tokio threads per process. Setup was outside the timed interval. Each server trial followed a matching response-shape echo calibration. Public keys were synthetic claims; no WireGuard handshake occurred.

## Clean bounded observations

- Registration: 50,000 of 50,000 requests completed at 5,000 offered requests/s. Request-to-response p99 was 237 µs; scheduled-offer-to-response p99 was 3,157 µs. Sampled peak server RSS was 31,664 KiB as registrations grew from 10,000 to 60,000. [Receipt](results/20261028-141827/0-server-register.json).
- Authenticated peer lookup: 50,000 of 50,000 completed at 5,000 offered requests/s. Request-to-response p99 was 226 µs; scheduled-offer-to-response p99 was 2,452 µs. Sampled peak RSS was 10,336 KiB. [Receipt](results/20261028-142220/1-server-authorize.json).
- Connection brokering: 250,000 of 250,000 completed at 25,000 offered requests/s. Request-to-response p99 was 704 µs; scheduled-offer-to-response p99 was 3,396 µs. Sampled peak RSS was 61,248 KiB. This created distinct requests across the initial population, up to 25 pending callers per target, below the inbox limit of 32. [Receipt](results/20261028-142119/0-server-connect.json).

Each listed trial and its matching calibration had zero late offers, queue drops, or request errors. Drain time was at most 1 ms. RSS samples include setup and are not heap allocation measurements. Scheduled latency includes generator batching and scheduling delay.

## Failed gates retained

These are individual successful observations, not uniformly repeatable throughput or capacity claims:

- The first 5,000/s lookup and brokering server trials missed 118 and 139 offers respectively because the generator was late. Their calibrations passed, but the server trials failed the accounting gate. [Full run](results/20261028-141827/summary.json).
- At 25,000/s, lookup calibration missed 520 offers and registration calibration missed 564. Those server arms were skipped. [Full run](results/20261028-142119/summary.json).
- The final lookup series first had a calibration miss 47 offers; that server arm was skipped. The second calibration and server trial passed. [Full run](results/20261028-142220/summary.json).

No throughput ceiling, long-duration stability, cross-machine scaling, TLS cost, recipient polling load, or Aquatic speedup is established. Open lab registration issues session tokens but does not prove ownership of a WireGuard private key. NAT traversal, relaying, and encrypted peer data transfer were not tested.

## Reproduction and validation

### 100,000 requests/s attempt

Executed `python3 scripts/bench.py --rate 100000 --seconds 10 --population 50000 --repeats 1`. All three echo calibrations failed the zero-loss gate, so all server arms were skipped. [Full receipt](results/20261028-142728/summary.json).

- Lookup calibration: 1,000,000 offered, 997,546 accepted and completed; 2,454 queue drops.
- Brokering calibration: 1,000,000 offered, 990,996 accepted and completed; 9,004 queue drops.
- Registration calibration: 1,000,000 offered, 994,095 accepted and completed; 5,905 queue drops.

All had zero late offers and zero request errors among accepted requests. These are echo calibration results, not coordinator throughput measurements. The current local HTTP harness did not qualify 100,000/s; no server ceiling follows.

This attempt used 50,000 initial peers to keep planned brokering inbox occupancy below 32. The driver now sizes configured registration capacity to at least initial population plus offered requests (1,050,000 here), and records that capacity and its own hash in the manifest. Server code, release binaries, worker counts, and queue limits were unchanged; their hashes matched the preceding measurements. No compilation was needed.

See [README](../README.md) for build and native server instructions. The benchmark driver is [scripts/bench.py](../scripts/bench.py). All three run directories contain source/binary SHA-256 manifests, exact generator commands, logs, and JSON accounting. Current source and release binaries were verified against all three manifests after execution. Raw result directories are locally retained and gitignored.

Executed validation: two model tests and four API tests passed, including concurrent registration capacity, expiry, revocation, credential rejection, duplicate handling, and inbox bounds. `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` passed. Compilation was coordinated through Kyoto; test executables were run separately after compilation.

Example bounded repeat:

```sh
python3 scripts/bench.py --rate 5000 --seconds 10 --population 10000 --repeats 3
```

Inspect each result's `passed` field and the retained calibration outcomes; driver completion alone does not imply every trial passed.

## Generator revision and follow-up trials

The HTTP generator now uses a persistent Hyper HTTP/1.1 connection per worker, typed response decoding, a dedicated 250 µs pacing thread, and bounded fallback to another existing worker queue. It reads and validates every complete response and retains the 3-second timeout and 10 ms late-offer rejection. Waiting capacity remains at most 1,024 requests; concurrency is separately configurable. HTTPS still uses Reqwest and was not tested. Server source and server/echo binaries were unchanged. Cargo gained direct dependencies used by the generator.

A low-rate check caught and fixed slice rounding: the scheduler now assigns request indices using ceiling division so requests at rates below 4,000/s are offered in their correct slices. At 100,000/s and 50,000/s the division is exact, so this correction does not change the tested offer schedule.

Executed validation of the final binary: `scripts/check_load.py` accepted all ten valid responses and rejected all ten responses containing the wrong peer key. Formatting, Python syntax checks, release compilation, and `cargo clippy --bin load -- -D warnings` passed. Builds used Kyoto.

All exploratory trials are retained below. Settings changed between candidates, so these are not a controlled speedup comparison. No 100k/s calibration passed.

| Receipt | Candidate/configuration | Calibration passes | Server arms |
|---|---|---:|---:|
| [20261028-143436](results/20261028-143436/summary.json) | Dedicated pacing and typed decode; 32 workers, 2 Tokio threads | 0/3 | 0 |
| [20261028-143523](results/20261028-143523/summary.json) | Same candidate; 4 generator Tokio threads | 0/3 | 0 |
| [20261028-143638](results/20261028-143638/summary.json) | Separate Reqwest pool per worker; 32 workers, 2 threads | 0/3 | 0 |
| [20261028-143741](results/20261028-143741/summary.json) | 64 workers, 16 waiting slots each; 2 threads | 0/3 | 0 |
| [20261028-143940](results/20261028-143940/summary.json) | Direct Hyper HTTP connections; 32 workers, 2 threads | 0/3 | 0 |
| [20261028-144115](results/20261028-144115/summary.json) | Direct Hyper plus queue fallback; fixed three-repeat series | 0/9 | 0 |
| [20261028-144349](results/20261028-144349/summary.json) | Final low-rate rounding fix; 50k/s follow-up | 1/3 | 1 |

The fixed three-repeat 100k/s series planned one million requests per calibration:

| Repeat | Operation | Completed | Late | Queue drops |
|---:|---|---:|---:|---:|
| 1 | authorize | 999,973 | 27 | 0 |
| 1 | connect | 994,979 | 862 | 4,159 |
| 1 | register | 999,958 | 28 | 14 |
| 2 | authorize | 992,715 | 3,346 | 3,939 |
| 2 | connect | 999,407 | 0 | 593 |
| 2 | register | 998,738 | 28 | 1,234 |
| 3 | authorize | 994,315 | 246 | 5,439 |
| 3 | connect | 999,270 | 0 | 730 |
| 3 | register | 982,136 | 8,624 | 9,240 |

Every admitted request in that series completed without a request error; every calibration nevertheless failed the full-accounting gate, so no coordinator 100k/s arm ran. Other CPU-active processes were observed during testing, but their causal contribution was not measured.

The final 50k/s brokering echo calibration completed 500,000/500,000 cleanly. Its server arm completed 499,986/500,000 planned requests: 14 late offers, zero queue drops, zero errors. Successful requests had service p99 205 µs and scheduled-to-completion p99 518 µs; sampled peak server RSS was 137,488 KiB. This remains a failed gate, not a 50k/s capacity qualification. Lookup and registration calibration failed and their server arms were skipped.

Reproduce the final candidate with `python3 scripts/bench.py --rate 100000 --seconds 10 --population 50000 --repeats 3 --load-threads 2 --workers 32`. No throughput ceiling or causal speedup is established.

## Fresh 100k/s run — 14:49

All three matching echo calibrations completed 1,000,000/1,000,000 with zero late offers, queue drops, or errors. All three server arms therefore ran. [Full receipt](results/20261028-144955/summary.json). Settings: 10 seconds, 50,000 initial peers, 32 HTTP workers, two Tokio threads per process, 1,024 total waiting slots.

| Operation | Completed / 1,000,000 | Late offers | Generator queue drops | Errors | Service p99 (µs) | Scheduled p99 (µs) |
|---|---:|---:|---:|---:|---:|---:|
| authorize | 996,950 | 0 | 3,050 | 0 | 565 | 11789 |
| connect | 993,802 | 3,082 | 3,116 | 0 | 501 | 6491 |
| register | 990,977 | 1,663 | 7,360 | 0 | 650 | 12095 |

All admitted requests completed successfully. All server arms failed the zero-loss gate, so this does not establish clean 100k/s capacity. Queue drops are generator Tokio mpsc admission failures before HTTP transmission, not socket packet drops or server HTTP rejections. They can reflect insufficient end-to-end service rate as well as generator/host scheduling; no causal bottleneck was isolated. Server sampled peak RSS: lookup 22,656 KiB, brokering 271,280 KiB, registration 661,280 KiB.

## Generator queue policy change

After the above measurements, the generator worker channels were changed to unbounded Tokio mpsc channels at user request. New receipts label `queue_mode: unbounded` and `queue_per_worker: null`; they include enqueue-to-dequeue p99/max and retain original scheduled latency, late-offer counts, and drain time. Closed channels are reported separately from capacity drops. Historical results above used bounded channels. No performance result above measures this new queue policy.

## Unbounded queue trial — 14:54

Ran all three modes at 100,000 scheduled requests/s for 10 seconds, with 50,000 initial peers, 32 workers and two Tokio threads per process. [Full receipt](results/20261028-145416/summary.json). Final source and binary hashes match the receipt manifest.

- Lookup echo calibration: 997,724 completed, 2,276 late offers, no queue drops or errors. Server skipped.
- Brokering echo calibration: 999,582 completed, 418 late offers, no queue drops or errors. Server skipped.
- Registration echo calibration: all 1,000,000 completed, no late offers, queue drops, or errors. Server trial ran.
- Registration server: 998,807 completed out of 1,000,000 scheduled; 1,193 offers rejected by the unchanged 10 ms scheduling-lateness gate. No queue drops, closed channels, or request errors. Request-to-response p99 572 µs; queue wait p99 29,113 µs and maximum 41,032 µs; scheduled-to-completion p99 30,051 µs. Drain after the 10-second offer interval: 10 ms. Sampled peak server RSS 663,312 KiB.

The unbounded channels removed capacity drops, but the scheduling-lateness gate still applies. The registration trial failed complete-offer accounting; this is not clean 100k/s qualification. Queue wait includes enqueue-to-worker-receive time for all dequeued requests. Service and end-to-end latency percentiles cover successful requests.

## One-million-per-second burst with RAM monitoring

Offered 1,000,000 requests in one second per mode, then drained all queued work. This shorter diagnostic burst was selected on the 8 GiB Mac to avoid creating ten million retained registrations. Settings: 50,000 initial peers, 32 workers, two Tokio threads per process, unlimited generator channels. [Receipts](results/20261028-145815/summary.json). All three echo and server arms completed every request with zero late offers, drops, closed channels, or errors.

**This did not sustain one million completed requests per second.** Echo arms took 6.711–7.099 seconds to finish, so calibration itself backlogged. JSON `passed` and `accounting_passed` mean complete request accounting, not rate qualification.

| Server operation | Total completion time (s) | Post-offer drain (s) | Mean completed/s over entire interval | Queue-wait p99 (s) | Server peak RSS (MiB) | Generator peak RSS (MiB) | Combined peak RSS (MiB) |
|---|---:|---:|---:|---:|---:|---:|---:|
| authorize | 7.360 | 6.360 | 135,870 | 6.296 | 22.4 | 90.1 | 112.4 |
| connect | 7.495 | 6.495 | 133,422 | 6.427 | 265.1 | 91.7 | 356.8 |
| register | 8.464 | 7.464 | 118,147 | 7.382 | 646.3 | 131.2 | 777.5 |

RSS was sampled about every 250 ms across setup, the burst, and draining; per-arm `.ram.json` files retain the time series. Combined peak is the maximum simultaneous sampled sum, not the sum of independent peaks. Sampling can miss short peaks, and RSS is not a precise heap allocation or total system-memory measure. macOS memory_pressure reported 77% system-wide free before the run and 78% on two checks during the run. All processes exited after each arm. Source, binary, and driver hashes match the manifest.

## Three-operation API smoke validation

The server now implements register/refresh, peer discovery, and exact binding verification. Pending brokering state and the old lookup/poll/removal routes were removed. Five executed model/API tests passed, including refresh authorization, endpoint changes, expiry, old-token rejection, bounded discovery, concurrent capacity and removed routes. All-target Clippy with warnings denied, formatting, release builds, and generator valid/invalid response checks passed.

[Native HTTP smoke receipts](results/20261028-151316/summary.json): 1,000 offered requests/s for two seconds per mode, 1,000 initial peers, discovery limit 20, 32 workers and two Tokio threads per process. All four calibrations completed 2,000/2,000 without errors. Registration, refresh and verification server arms also completed 2,000/2,000 cleanly. Discovery completed all 1,963 admitted requests with valid responses; 37 late offers made its performance accounting gate fail. No admitted request failed validation. Source, binary and driver hashes match the manifest.

This is functionality/smoke evidence, not high-rate qualification of the new API. Historical performance numbers above have not been carried over. Unlimited generator queues and per-arm server/generator RAM sampling remain enabled.

## Review fixes and regression validation

Fixed verification's target-existence disclosure to an invalid session: caller authentication now precedes target lookup under the ordered shard locks. Fixed permanent discovery omissions by advancing a cursor over a compact key index within each shard; cleanup keeps that index consistent. The index adds 32 bytes per registration before vector spare capacity, so previous memory/performance figures do not measure this layout.

The benchmark driver now rejects invalid settings before launching processes, and SIGINT/SIGTERM or errors terminate and reap both generator and server. Peer-list-size validation applies only to discovery, so small verification/refresh runs no longer require an irrelevant peer-limit override.

Validation: six Rust model/API tests passed; two Python driver tests passed (invalid-input rejection and interruption cleanup for both signals); valid/invalid HTTP response checks passed; all-target Clippy with warnings denied, formatting and release builds passed. The discovery regression exercises eventual coverage of every stable peer, including peers omitted by a fixed hash-map prefix.

[HTTP smoke receipt](results/20261028-153309/summary.json): each of register, refresh, peers and verify completed 100/100 requests in both calibration and server arms, with zero late offers, errors or queue drops. This is a functional smoke test, not high-rate qualification. Source, binary and driver hashes match the manifest.

## Core policy and shared-read-lock refactor

Moved caller/peer eligibility, self-query rejection, target expiry and exact endpoint matching into the production Statelessness Access model. The host supplies synchronized records, constant-time credential comparison facts and explicit time. Decisions are recomputed; no authorization cache or persistent grant was introduced.

Replaced exclusive shard mutexes with read/write locks: verification and discovery share read guards, while creation, refresh and cleanup retain write guards. Discovery validates multiple candidates per shard visit instead of reacquiring locks per peer. Sampling cursors are atomic, and response encoding and new-token generation/hashing are outside write locks. Ordered caller/target locking remains for coherent observations.

Validation: nine executed Rust model/API tests passed, including concurrent discovery/verification/refresh/cleanup, authorization precedence, expiry, endpoint changes and discovery coverage. All-target Clippy with warnings denied, formatting and release builds passed.

[HTTP smoke receipt](results/20261028-154520/summary.json): 100 scheduled requests per arm. Detailed accounting follows; any late offers invalidate the corresponding performance gate. All admitted requests received valid responses. These are functional diagnostics, not speedup or capacity evidence. Source and binary hashes matched the manifest.

- calibration register: 99/100 completed, 1 late, 0 errors.
- server register: 100/100 completed, 0 late, 0 errors.
- calibration refresh: 100/100 completed, 0 late, 0 errors.
- server refresh: 100/100 completed, 0 late, 0 errors.
- calibration peers: 100/100 completed, 0 late, 0 errors.
- server peers: 100/100 completed, 0 late, 0 errors.
- calibration verify: 100/100 completed, 0 late, 0 errors.
- server verify: 100/100 completed, 0 late, 0 errors.


## Single-owner registry refactor — 2026-10-28

Checkpoint before refactor: `05c963d`. The candidate replaces shared registry
shards with a synchronous `Registry` owned by one Tokio command task. Registry
storage, capacity, discovery cursor, refresh, verification, and cleanup have no
locks or atomics. The unbounded command channel still provides synchronization
outside the core; it is separate from the generator queues.

Validation: 13 executed Rust tests passed (7 unit, 6 API), including concurrent
API operations and owner cancellation/shutdown behavior. All-target Clippy with
`-D warnings`, release binaries, formatting, and diff checks passed.

Native HTTP diagnostic: `bench/results/20261028-160227`, 100 scheduled requests
per second for one second per arm, population 100, peer limit 10, one repeat.
Register, peers, and verify each completed 100/100 server requests. Refresh
completed 99/100, with one generator-late offer. Every accepted server request
returned a validated response; no request errors or queue drops occurred. Peer
calibration completed 98/100 with two late offers, so refresh and peers failed
the full accounting/calibration gate. This is functional diagnostic evidence,
not throughput qualification or a performance comparison with the checkpoint.
Server peak sampled RSS ranged from 4,704 to 5,872 KiB across these small arms;
this is not a large-population memory result. Source and release-binary hashes
were checked against the run manifest.


## Single-owner performance diagnostic — 2026-10-28

Native macOS loopback HTTP/1.1, five seconds per arm, one repeat, 10,000 initial peers, discovery limit 20, 32 connections, two Tokio threads per process. Generator queues remain unbounded. Every operation ran against echo calibration and a fresh server. No TLS or WireGuard traffic.

| Target/s | Operation | Completed/offered | Late offers | Elapsed ms | Drain ms | E2E p99 ms | Server peak MiB | Calibration + accounting |
|---:|---|---:|---:|---:|---:|---:|---:|---|
| 100,000 | register | 500,000/500,000 | 0 | 5,002 | 2 | 28.464 | 226.0 | fail |
| 100,000 | refresh | 500,000/500,000 | 0 | 5,003 | 3 | 5.823 | 9.9 | pass |
| 100,000 | peers | 500,000/500,000 | 0 | 6,316 | 1,316 | 1305.467 | 10.0 | fail |
| 100,000 | verify | 497,261/500,000 | 2,739 | 5,002 | 2 | 32.435 | 10.0 | fail |
| 25,000 | register | 124,411/125,000 | 589 | 5,000 | 0 | 3.152 | 59.7 | fail |
| 25,000 | refresh | 125,000/125,000 | 0 | 5,000 | 0 | 0.436 | 9.8 | pass |
| 25,000 | peers | 124,692/125,000 | 308 | 5,000 | 0 | 28.654 | 10.0 | fail |
| 25,000 | verify | 125,000/125,000 | 0 | 5,000 | 0 | 0.424 | 9.8 | pass |

All accepted requests returned validated responses, with zero errors, queue drops, or closed channels. At 100k/s, registration calibration missed 2,717 offers; discovery calibration missed 2,526 and drained for 2,586 ms. Verification server missed 2,739 offers. All 25k/s calibrations passed, but registration and discovery server arms missed 589 and 308 offers respectively. These misses are generator offers over 10 ms late, not server response errors.

Refresh passed the five-second 100k/s point; refresh and verification passed the 25k/s point. This is a single-run result, not sustained production capacity. Discovery at 100k/s accumulated a 1,316 ms drain and cannot be called sustained 100k/s even though its server completed every offer. No speedup claim versus the checkpoint is supported because it was not rerun. RSS is sampled every approximately 250 ms over setup and measurement, not precise heap usage. Registration grows the registry while other arms retain their initial population; their RSS values are not equal-population comparisons.

Receipt: [results/20261028-160957/summary.json](results/20261028-160957/summary.json).
Receipt: [results/20261028-161049/summary.json](results/20261028-161049/summary.json).
Source and binary hashes matched both manifests.


## One million resident peers — 2026-10-28

[Receipts](results/20261028-162256/summary.json). Native macOS loopback HTTP/1.1; one million distinct registrations on each fresh server, 25,000 scheduled requests/s for ten seconds per operation, one repeat, 32 connections, two Tokio threads per process. Discovery returns 20 peers. Each operation has its own matching echo calibration. Server capacity 1,250,000; lease TTL 3,600 seconds so the entire population stays live through setup and measurement.

| Operation | Setup seconds | Completed/offered | E2E p50 ms | E2E p99 ms | Server peak MiB | Combined peak MiB |
|---|---:|---:|---:|---:|---:|---:|
| refresh | 51.634 | 250,000/250,000 | 0.287 | 32.231 | 461.9 | 761.8 |
| peers | 51.528 | 250,000/250,000 | 0.335 | 43.624 | 462.0 | 767.9 |
| verify | 51.506 | 250,000/250,000 | 0.318 | 33.985 | 461.9 | 761.7 |

All three calibration and server pairs passed request accounting, with zero late offers, errors, queue drops or closed channels. Server arms each finished in 10,001 ms, including 1 ms drain. This demonstrates the tested million-record workload at 25k/s; it does not establish maximum capacity, mixed-workload performance, or a million simultaneous connections. The timed workload exercises 250,000 distinct callers within the resident population.

Peak RSS was sampled approximately every 250 ms across setup and measurement; combined means simultaneous server plus generator RSS. It is not precise heap usage. Median latency remains below 0.4 ms, but p99 is 32–44 ms. The owner performs whole-registry cleanup every five seconds; its contribution to tail latency requires profiling and is not established by these receipts. Two host health snapshots reported normal memory pressure; these are spot checks, not continuous pressure monitoring.

Harness changes: allow up to one million HTTP identities while retaining Aquatic's 50,000 limit; preallocate the identity vector; record setup duration; expose server TTL in the driver. No server implementation change was made for this test. Kyoto release build succeeded; both Python driver tests, formatting and diff checks passed. Source, driver and binary hashes match the manifest.


## Core cost measurements and HTTP correlation — 2026-10-28

Direct production `Registry` methods were measured with the pinned `statelessness-debug` monotonic clock and bounded duration histograms. A counted System allocator records allocation/reallocation calls and requested bytes. Three fresh-registry repetitions at each population. Reporting, histogram insertion, and percentile sorting are outside timed operations. Instrumentation affects absolute timings; nanosecond-scale results include timer overhead (median control 41 ns). This is a diagnostic, not capacity or CPU-profile attribution.

[Core raw receipts](results/core-costs-20261028-164158/results.jsonl), [manifest](results/core-costs-20261028-164158/manifest.json), and [process resource report](results/core-costs-20261028-164158/stderr.txt).

| Operation | 10k peers | 100k peers | 1M peers |
|---|---:|---:|---:|
| cleanup_live | 229.250 µs | 3,676.750 µs | 69,149.459 µs |
| cleanup_expired | 564.958 µs | 7,036.583 µs | 57,684.083 µs |
| discovery_20 | 1.167 µs | 2.292 µs | 4.250 µs |
| discovery_100 | 5.417 µs | 11.833 µs | 18.542 µs |
| discovery_expired_4096 | 245.333 µs | 624.125 µs | 768.041 µs |
| refresh | 0.125 µs | 0.208 µs | 0.292 µs |
| verify | 0.125 µs | 0.125 µs | 0.125 µs |

Table values are medians of the three run medians. Live cleanup has ten samples per run; mass expiry has one destructive sample per fresh population. Request methods use 10,000 samples; expired discovery uses 100. Direct method latencies exclude HTTP, command-channel waiting, and encoding. Key generation and result destruction are included in some request measurements; this is not a cycle-level isolated model benchmark.

**Findings:**

- Live million-peer cleanup run medians were 67.774, 70.369, and 69.149 ms. Across all 30 sweeps the range was 65.602–126.256 ms, with zero allocations. These synchronous scans block the sole owner.
- The largest registration growth event occurred at insertion 917,505: 21.940–36.581 ms across three repetitions, requesting a 236,978,184-byte allocation. Registration performed 39 allocation/reallocation calls while building each million-record registry; cumulative requested bytes were 541,064,796, not retained memory.
- Expiring 999,999 peers left one refreshed peer and made 999,999 temporary error-string allocations (23,999,976 requested bytes). Direct expired-lease checks also measured one allocation each.
- Discovery of 20 or 100 live peers made one result-vector allocation per request. At one million records, exhausting the 4,096-candidate scan against expired peers made 4,097 allocations per request and had run medians 747–771 µs. The result was empty, as expected.
- Refresh and verification made zero allocations in the core. Sparse cleanup after expiry was much cheaper (run medians 7.916–42.125 µs), so table capacity alone did not imply a full populated-table pause.

**HTTP correlation:** [receipt](results/20261028-164216/summary.json), [cleanup spans](results/20261028-164216/0-server-verify.server.log), [bounded slow-response correlation](results/20261028-164216/correlation.json). One million resident peers, verification offered at 25k/s for 15 seconds, 32 connections, 3,600-second leases. Both calibration and server completed 374,993/375,000 with seven late offers each and zero response errors. The accounting/calibration gate failed, so no capacity claim follows. Server p99 was 32.697 ms. Three full-population cleanup spans lasted 72.788, 69.689, and 73.130 ms.

Nine of the 32 captured first-slow responses had send-to-completion intervals overlapping a 72.788 ms cleanup; their end-to-end latency was about 72 ms. The other 23 were earlier approximately 10 ms delays dominated by generator waiting, illustrating that not every tail event is server cleanup. Sampling retains only the first >10 ms successful response per worker, and wall-clock alignment is approximate. The measured synchronous stalls plus request overlap establish cleanup as a real latency concern; they do not attribute every p99 event or prove a speedup from an unimplemented replacement.

Priority: avoid unconditional whole-population cleanup work and bound maintenance pauses; then address growth spikes and allocation-producing expiry checks. No optimization was implemented in this measurement pass. The only server change is opt-in cleanup timestamps, disabled unless `SUPERTRACKR_COST_DIAGNOSTICS` is present. Statelessness debug is a dev dependency used by the standalone example, not a normal-server runtime dependency.

Validation: Kyoto release builds and all-target Clippy with warnings denied passed. All 13 Rust tests executed with diagnostics enabled passed; both Python driver tests passed. Source/binary/driver hashes matched the recorded manifests.

The separate `scripts/check_load.py` check did not complete: on both attempts its
first valid-response arm admitted 9/10 requests, with one late offer and zero
response errors. Its strict completeness assertion stopped execution before the
remaining cases. This is recorded as a failed validation run, not a passing
response-validation suite.


## Basic fixes for measured stalls — 2026-10-28

Implemented four limited changes: shared allocation-free lease eligibility; map and discovery-vector reservation for configured capacity at initialization; skipping full index compaction when explicit cleanup removes nothing; and periodic maintenance in batches of at most 4,096 candidates every 20 ms. Expired entries use swap removal from the index. No locks, sharding, new expiry queue, or new storage representation were introduced. Authorization still checks expiry at processing time, independently of physical reclamation. Reclamation duration depends on population and load. The explicit full-cleanup method retains its complete-reclamation semantics and can still block for a full scan.

Reservation trades upfront allocation/reserved memory for avoiding initial-fill growth reallocations. It does not establish absence of rehash costs under sustained churn.

[Core receipts](results/core-fixes-20261028-165215/results.jsonl), [manifest](results/core-fixes-20261028-165215/manifest.json). Same instrumented direct-core harness, now also measuring initialization and maintenance batches. Three fresh-registry repetitions. At one million peers:

| Operation | Median of run medians | Allocations per operation |
|---|---:|---:|
| initialize | 36.792 µs | 2 |
| register | 0.125 µs | 0 |
| cleanup_live | 4,469.750 µs | 0 |
| cleanup_batch_live | 292.042 µs | 0 |
| cleanup_batch_expired | 608.458 µs | 0 |
| cleanup_expired | 26,848.917 µs | 0 |
| discovery_expired_4096 | 405.208 µs | 1 |

Initialization made two allocations; all one million subsequent registration inserts made zero allocations/reallocations. The largest measured insert was 52.041 µs, versus 21.940–36.581 ms growth events in the previous diagnostic. Initialization requested memory up front; allocation cost and storage were moved, not eliminated.

Live 4,096-entry batch run medians were 290–368 µs; expired-entry batch medians were 607–621 µs. Largest expired batch was 1.159 ms. Mass full cleanup of 999,999 expired records now made zero allocations; expired discovery retained only its single result-vector allocation. The standalone explicit full-cleanup live scan still takes roughly 4.5 ms, and full mass expiry roughly 27 ms; these are not used by periodic maintenance. Batch timing measures a smaller work unit than the prior full sweep and must not be interpreted as an equal-work throughput speedup. Batching bounds uninterrupted work, and can increase total reclamation work by doing individual lookups/removals.

**HTTP diagnostic:** [receipt](results/20261028-165255/summary.json). One million peers, verification at 25k scheduled requests/s for 15 seconds, diagnostics enabled, matching echo calibration. Calibration completed 374,923/375,000 with 77 late offers; server completed 374,860/375,000 with 140 late offers. Both had zero response errors, zero queue drops and 1 ms drain. The full accounting/calibration gate failed. Observed server p99 was 0.730 ms (previous diagnostic 32.697 ms); this is diagnostic latency evidence, not a qualified capacity or throughput ratio.

At full population, 727 logged maintenance batches had a median of 512 µs, p99 of 699 µs, and maximum of 5,098 µs. Server peak sampled RSS was 269,280 KiB (263.0 MiB), and combined server/generator peak was 581,568 KiB (567.9 MiB); sampling spans setup and measurement. Source, driver and binary hashes match the manifests.

Validation: 15 executed Rust tests passed with diagnostics enabled, including mixed expiry/refresh during batched cleanup, bounded removal, discovery coverage after swaps, capacity reuse, and lease-boundary agreement. Kyoto release build, all-target Clippy with warnings denied, formatting, diff checks and both Python driver tests passed. `scripts/check_load.py` again stopped on 9/10 admitted requests with one late offer and zero errors, so its remaining response-validation cases were not executed. No changes were committed in this pass.

## Final review fixes and validation — 2026-10-28

Reviewed the complete single-owner refactor and bounded cleanup change before
commit. Fixed benchmark process output handling: generator stdout/stderr now go
directly to receipt files, avoiding a deadlock when diagnostics exceed pipe
capacity. A regression test emits 256 KiB to each stream and completes both arms.
Diagnostic logging now tolerates a failed stderr write and an unavailable wall
clock; a live release-server check closed its stderr reader and confirmed that
registrations continued after periodic cleanup ticks.

The response-validator check now tests every admitted response and explicitly
reports late offers. It requires nonzero admission, exact accounting, and correct
success/error/exit status; it does not relax the load binary's `passed` criterion
or the benchmark calibration gate. Both valid-response and wrong-peer-key cases
executed successfully after this correction.

Final validation: 15 executed Rust tests with diagnostics enabled, three Python
driver tests, both response-validator cases, all-target Clippy with warnings
denied, release binaries, formatting and diff checks passed. These review fixes
were not subjected to a new high-rate capacity run. Earlier benchmark receipts
remain historical evidence tied to their recorded source and binary hashes.
