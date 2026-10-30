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


## First client milestone — 2026-10-28

[Two-process receipt](results/client-20261028-171808/summary.json), with matching
Rust source/dependency and binary hashes in its manifest. Two independent release
`client` processes registered distinct persisted WireGuard keys through a local
HTTP server, discovered and verified each other's exact public key/UDP endpoint,
and exchanged real BoringTun WireGuard handshake/data traffic over loopback UDP.
Each client completed eight IPv4/UDP ping/pong round trips in eight seconds and
five successful registration refreshes with a three-second server lease. Both
rejected an injected unknown-source datagram. Test private keys were created as
mode 0600 files in an isolated temporary directory and removed after completion;
receipts contain only public keys, endpoints and counters.

All 20 executed Rust tests passed (15 existing server/core/API tests and five
client tests). Client tests cover persisted-key consistency and unsafe key-file
rejection; explicit loopback HTTP opt-in; inner-packet address/length/checksum
checks; wrong-private-key handshake rejection; successful encrypted delivery;
ciphertext tampering and replay rejection. Release builds, all-target Clippy with
warnings denied, formatting and diff checks passed.

This proves the local client handshake and in-process data path, not an OS TUN
interface, general IP forwarding, standard-client interoperability, NAT traversal,
relay behavior, remote-network reachability, HTTPS control transport, or client
performance. The lab configures one peer and manually supplied inner IPv4
addresses; session tokens are RAM-only, reconnect is deferred, and open
registration still permits public-key squatting. No server protocol or registry
implementation change was needed.

## 2026-10-28: NAT traversal and ciphertext relay prototype

Functional qualification only; no throughput, Internet NAT, or router-mapping
capacity claim. Final release receipts (source and binary hashes rechecked):

- `bench/results/client-20261028-182926/summary.json`: direct loopback, 12
  authenticated round trips per client, five refreshes each, injected garbage rejected.
- `bench/results/traversal-nat-20261028-182926/summary.json`: two client processes,
  one passive, using a userspace NAT/filter simulator. Clients completed 29 and 30 round
  trips and ten refreshes. Assertions passed for startup relay (UDP blocked),
  coordinated direct hole punching, relay fallback after path loss, and direct
  recovery after a mapped-port change. Six STUN replies, 82 forwarded packets,
  33 deliberately blocked packets, five filtering drops, one rebind; one client
  relay admission/queue drop was recorded. Rejected WireGuard packets are retained
  in client counters (including duplicate/replay traffic during path races).
- `bench/results/traversal-relay-20261028-182926/summary.json`: forced relay-only,
  eight authenticated round trips per client, three refreshes each, zero direct
  packets sent and zero direct paths validated. No relay queue/admission drops.

29 default-feature Rust tests executed and passed (16 library/model/core/STUN,
six client, seven HTTP API). Coverage includes mutual relay selection, invalid
credentials, source-session replacement, expiry, candidate replacement, per-peer
and global relay capacity, STUN transaction/source/length/IPv4/IPv6/fingerprint
checks, an actual UDP STUN reflector, and existing WireGuard key/tamper/replay tests.
The optional router-mapping build also compiled and its 28 then-current tests
passed before the final common fingerprint test was added. Router-mapping code
was checked again by the final all-target/all-feature Clippy run with warnings
denied. Gateway discovery and actual mapping acquisition/renewal/removal were not
executed; no router settings were changed by the checks.

Final Kyoto jobs: default test compilation `19604ba0895149a8868904a47e21135e`,
all-feature Clippy `b66cf3f5b9e24dee836a84f6ba2e7b73`, release binaries
`60cb7f22b3e04bb284a59e879d7724f0`. Test binaries were executed explicitly after
Kyoto's compilation-only policy. Formatting and diff checks passed. The optional
`portmapper` dependency raises the declared Rust minimum to 1.91; this session used
the installed compiler, not a separate minimum-version toolchain qualification.

Final review found an avoidable short-lease tunnel reset with one-second peer
metadata polling. The final client uses 500 ms polling; the repeated direct lab
now asserts exactly one tunnel creation per client across five lease refreshes.
This last cadence change was checked by the final release integration runs and
all-feature Clippy after the 29-test run above.

## 2026-10-28: encrypted traffic simulation

Release client workload: 100 requested application packets/s per client, 1,200-byte
inner IPv4 packets, plus small path probes. Real WireGuard traffic between two
processes on this Mac. No final drain; pending requests remain separate from
five-second timeouts. Tests ran concurrently and do not establish capacity.

Receipts `traversal-{direct,relay,nat}-20261028-221051`:

| Scenario | Duration | Generated | Completed round trips | Timed out | Pending at exit | Relay drops |
|---|---:|---:|---:|---:|---:|---:|
| Direct | 8 s | 1,578 | 1,578 | 0 | 0 | 0 |
| Relay-only | 8 s | 1,490 | 1,421 | 39 | 30 | 39 |
| Simulated NAT/outages/rebind | 27 s | 5,444 | 4,345 | 1,073 | 26 | 42 |

Counts sum both clients; generated = completed + timed out + pending. Relay-drop
counts are datagram queue/admission failures and are not additional round-trip
losses. The NAT fixture deliberately blocked 2,251 datagrams and filtered 233.
All functional transition and accounting assertions passed; relay traffic was
not lossless. This identifies a limitation of the current polling relay without
measuring its isolated throughput ceiling. Six client tests (including variable
payload validation, encryption/tamper/replay) and client Clippy passed. Final
release build: Kyoto `e9ade179fc8042d38baafdcbb7567fdf`.

## Native companion integration — 2026-10-29

Debug macOS build, three companion processes plus a local tracker. Receipts:
`bench/results/companion-20261029/{tests.txt,direct.json,relay.json}`.
These are functional raw-IP Unix datagram adapter checks, **not utun, real TCP
socket, throughput, or capacity qualification**. Six directed peer pairs each
carry TCP-shaped and UDP payloads; the harness retries until each expected packet
arrives and separately verifies the authenticated delivery path counters.

- 35 Rust tests executed and passed, including multi-peer WireGuard decryption,
  forged inner-source rejection, address non-reuse/exhaustion, route conflicts,
  and HTTP virtual-address resolution/reciprocal introductions.
- Direct: 12 checks passed, 12 test packets offered, 12 direct inner deliveries;
  three I/O/relay drop events and four rejected inputs (including the intentional
  source-spoof test). No pending-resolution queue drops.
- Forced relay: 12 checks passed, 49 test packets offered with retries, 49 relay
  inner deliveries; three I/O/relay drop events and nine rejected inputs. No
  pending-resolution queue drops. This is not a lossless/capacity claim; counters
  include control-path WireGuard traffic and duplicate/replayed inputs.
- All-target/all-feature Clippy with warnings denied passed.
- Native adapter's non-root startup correctly refused before registration or
  route changes. `sudo -n true` reported a password was required. Privileged
  interface creation, real application TCP/UDP and route cleanup were not run.

## Direct peer introductions — 2026-10-29

This supersedes the companion's earlier server-introduction/forced-relay workflow;
the old packet lab and its historical receipts remain separate.

39 Rust tests executed successfully after Kyoto compile-only job
`599044c8719c46e38b2d6b421ee59164`. All-target/all-feature Clippy with warnings denied
passed in job `a4537522949c4a5091fd4da58af81cd6`.

`python3 scripts/check_companion.py` ran three companion processes with a proxy
that rejects `/v1/connect`, `/v1/resolve`, `/v1/events` and `/v1/relay`. It passed
12 directed protocol checks (six peer pairs, TCP-shaped and UDP payloads), with
12 packets offered and 12 direct encrypted inner deliveries. Each companion
completed two direct introductions. No introduction rejection, I/O drop or
pending-resolution drop occurred. One intentionally forged inner source was
rejected. The HTTP counts were exactly three each for registration, candidate
publication, own-interface metadata, read-only destination lookup and read-only
binding verification; zero calls to the four forbidden signaling/relay routes.

Unit/API checks cover challenge-before-verification, duplicate suppression,
wrong authority/source, expired challenges and late verification, pending/rate
bounds, and read-only lookup/verification leaving both introduction inboxes and
reciprocal relay permissions untouched. These are prototype functional results,
not production DoS, NAT reachability, throughput or privileged utun qualification.

## Endpoint-only NAT rendezvous, no companion relay — 2026-10-29

Added server-assisted reciprocal UDP attempts while retaining direct public-key
introductions. The companion still makes zero calls to legacy `/v1/connect`,
`/v1/resolve`, `/v1/events`, and `/v1/relay`; the integration proxy rejects those
routes. `/v1/rendezvous` carries candidate addresses and a short lifetime only.

42 Rust tests passed after Kyoto compile-only job
`8d0526aea1c74ba09ae3f4183162266c`; all-target/all-feature Clippy with warnings denied
passed in `eafda0b471bf470fba2ae48db84b6cee`. Unit/API coverage includes authentication,
deduplication, queue/rate limits, expiry, stale registration rejection, endpoint-only
responses, and absence of key-introduction or relay grants. Test logs plus direct
and negative-control receipts: `bench/results/rendezvous-20261029/`.

Three real companion processes, synthetic inner TCP-shaped/UDP packets, loopback
userspace NAT with endpoint-independent mappings and endpoint-dependent filtering:

- Rendezvous enabled (`--nat`): 12 directed protocol checks passed. 15 test packets
  offered and 15 direct inner deliveries, six completed introduction sides,
  three endpoint hints, 14 outbound punch probes. The NAT fabric recorded three
  STUN exchanges, 68 forwarded datagrams (42 WireGuard), and three filter drops.
  No companion I/O, punch, or pending-resolution queue drops; one intentionally
  forged inner source was rejected. No relay deliveries.
- Rendezvous suppressed (`--nat --disable-rendezvous`): expected disconnection
  confirmed. Zero introductions, WireGuard forwarding or inner deliveries; 11
  NAT filter drops. 18 test packets offered and 16 pending-resolution drops;
  remaining buffered work at shutdown is not separately reported. This is a
  negative reachability check, not a loss/capacity measurement.
- Plain loopback: all 12 directed checks passed with 12 offered/direct deliveries.

The simulator removes private same-host candidate addresses from advertisements,
preventing a direct loopback bypass. These results establish the rendezvous
mechanism for this modeled filter, not general Internet/router NAT compatibility,
production load, or privileged macOS utun application acceptance.

## Both introduction options — 2026-10-29

`--introduction direct` remains the default. `--introduction server` requests a
current server-owned key/IP binding with rendezvous, bypassing the separate UDP
key-introduction exchange. Receivers accept either option. Neither creates relay
permission or enables data relay.

43 Rust tests passed. Initial API coverage expected HTTP 400 for a forbidden
caller-supplied binding; Axum correctly rejected that JSON with 422. The assertion
was corrected and all 11 API tests then passed. Compile jobs:
`4a2b994464324a2baea792fa0e175429`, then `cd9f051aa0c64ec7843ff5951a2d5eda` for the
corrected API test. All-target/all-feature Clippy with warnings denied passed in
`07752dbcd5e84b1086e1d082f71dd919`.

Three-companion NAT simulation passed all 12 directed TCP-shaped/UDP packet checks
in direct, server-assisted and mixed preference configurations. Server mode used
zero direct introduction exchanges and received six tracker bindings across the
three companions; mixed mode exercised two direct introduction sides and four
tracker bindings. All three runs made zero legacy key-introduction/event/relay
calls, delivered no relay traffic, and reported zero I/O, punch or resolution
queue drops. One intentional forged-source input was rejected in each run.

These are bounded functional packet-adapter tests, not real TCP socket, privileged
utun, physical-router, production DoS or performance qualification. Direct/mixed
receipts and test output are in `bench/results/introduction-modes-20261029/`.

## Tailscale source audit and path validation — 2026-10-29

Reference source pinned to `tailscale/tailscale` commit
`f7c1b8e52600c1926623b29c91972a5ea1364d2f`; findings and remaining gaps are recorded in
`docs/CONNECTIVITY-AUDIT.md`. This is not an equivalence or performance claim.

47 Rust tests passed after compile-only job `82463b09e06241ccb7210c272d30ef65`.
All-target/all-feature Clippy passed in `f7992ebd9c7c405d88cb803f0a12e190` following
a style-only nested-if correction. Added coverage includes nonce/endpoint/time
correlation, replay rejection, path trust expiry, RTT hysteresis, bounded learned
endpoints, fresh STUN mapping classification and disabled router-mapping behavior.
Real router mapping acquisition/renewal/removal remains untested.

The mixed-introduction userspace NAT run passed all 12 initial directed packet
checks and two recovery checks (temporary UDP outage and replacement of all public
NAT mappings). It recorded 13 validated encrypted Pongs, seven path selections,
24 deliberately blocked datagrams and four filter drops. No relay calls/deliveries
occurred. Recovery packet offers were not counted separately in that initial
receipt; the harness now reports them separately. This was a reachability check,
not loss-rate or throughput qualification.

Endpoint-dependent mappings plus endpoint-dependent filtering correctly stayed
blocked (32 filter drops, zero forwarded WireGuard or inner deliveries). The
peer-UDP-blocked model likewise stayed blocked (31 blocked datagrams, zero
WireGuard/inner deliveries). Both allowed STUN and HTTP rendezvous; one STUN
server is insufficient to classify mapping variation, so diagnostics remained
unknown. Neither negative outcome is a claim about every real NAT of that class.

Receipts: `bench/results/tailscale-audit-20261029/`. All traffic used raw-IP test
adapters, not a privileged macOS interface or real TCP application sockets.

## Anonymous enrollment validation — 2026-10-29

New registrations now require an encrypted X25519 key-possession challenge and
proof completion; refresh still uses its bearer token. Previous one-request
registration measurements do not measure this two-request workflow. No new
high-rate capacity claim is made.

Executed validation: 50 Rust tests passed (25 library, 6 lab client, 7 companion,
12 API). Test compilation used Kyoto job `659b6a0f34c1404f83fb5587440c8191`, then
all emitted test binaries were executed. Clippy all targets/all features with
warnings denied passed in job `20e478e7fcb4431b949ecfa07aa20bd1`.

Both debug lab clients enrolled, refreshed five times each and received encrypted
pongs. The mixed-mode companion raw-IP adapter test passed all 12 directed protocol
checks, rejected forged inner source traffic, and recovered from simulated UDP
outage and mapping rebind. These are loopback/user-space NAT simulation results,
not privileged utun or Internet NAT qualification. An initial companion invocation
during build activity failed to start its server; the completed-build run passed.

Debug load functional receipts: `bench/results/enrollment-20261029/`. At 10 offers
per second for one second, registration completed 10/10 with zero errors. Refresh
and verify runs completed 9/9 admitted operations, with one late unsent offer each;
their performance gate correctly remained false, including the refresh follow-up.
Both response-shape fixture checks passed (valid response accepted, wrong key
rejected), explicitly using `--calibration-only`. These checks establish functional
integration only; fixture calibration omits the enrollment proof workload.

## Userspace connection API validation — 2026-10-29

Added `userspace::Network`, a poll-driven smoltcp TCP/UDP stack behind the shared
WireGuard peer manager. This is functional validation, not a throughput benchmark.
All 53 tests passed after Kyoto test compilation `785cbdbe8d1340668e060686bc09676c`
and direct execution of all emitted binaries. The three userspace tests were
recompiled in `ce936da223c14c8d82638e239650b710` and executed again after tightening
the loss injection to encrypted data packets larger than 200 bytes. All passed:
64 KiB TCP transfer with loss, half-close, listener reuse, UDP boundaries, socket
limits/handles, unknown-peer resolution, untrusted input and local expiry.

Clippy all targets/all features with warnings denied passed in
`86e5e918698748299cff7fb441d2ced9`. The example initially requested its interface
before publishing candidates and received 404; that ordering was corrected.
The rebuilt `userspace_echo` (`b7bfce8a5aad4e2abb05fc0801834df4`) then executed
successfully: two proof-enrolled peers obtained tracker bindings and echoed TCP
and UDP through real loopback WireGuard datagrams, with no virtual interface.
No Internet NAT or production performance qualification is implied.

## Tokio userspace API validation — 2026-10-29

`async_userspace::Client` now owns the polling engine and outer UDP transport in
one task. TCP handles implement Tokio AsyncRead/AsyncWrite; TCP accept/connect
and UDP send/receive are awaitable. Tracker control remains explicit.

Executed 62 tests: the existing 53 plus 9 async integration tests. Full compilation
used Kyoto `72e780970c064e65bdc319b5b9526faa`; the final async test revision used
`9242d59ed5844e4699aa3f44962da77d`. All corresponding binaries were executed.
Async checks cover 256 KiB transfer/half-close, shutdown-and-drop byte preservation,
final-owner draining and transport release, independent UDP progress under TCP
backpressure, 80 cancelled connects with complete capacity recovery, UDP receive
cancellation and bounds, expiry/explicit shutdown waking blocked operations, and
an incompatible address candidate not terminating a usable path. The candidate
check initially asserted before the scheduled probe; it now waits for that probe
and passed. Clippy all targets/all features with warnings denied passed via
`318fb14ce1b34dbaa33895356fe00acf`.

The updated `userspace_echo` executable also passed: proof-bearing enrollment,
tracker-provided reciprocal bindings, and async TCP/UDP echo over real loopback
WireGuard sockets without application polling or virtual interfaces. This remains
functional transport evidence, not Internet NAT or throughput qualification.
Kyoto intermittently deferred compilation for host memory pressure; final test
compilation used a single Cargo job without changing shared queue policy.

## Listener recovery fix validation — 2026-10-29

Closed pending TCP listeners now re-arm in place when accepted again. The same
listener ID/port is retained, and recovery does not require an additional socket
slot. Capacity is checked only when accepting an established connection.

Kyoto compilation `c919550d3a0d43abaaddc773fa2fb408` succeeded; both emitted test
binaries were then executed: 4 userspace and 9 async userspace tests passed.
The new regression reproduces a dropped SYN-ACK timeout, re-arms at all 64 slots
occupied, completes a new handshake, preserves pending connection data while
acceptance is capacity-blocked, and transfers that data after freeing one slot.
Clippy job `e9962fd74ad34987a6a8de2e11e8070d` subsequently succeeded (exit 0)
for the library and both userspace test targets with warnings denied. Kyoto's
normal scheduling was preserved while the checks remained queued.

## Optional BitTorrent library and overlay API — 2026-10-29

Added the dependency-free `supertrackr-bittorrent` workspace crate and optional
`bittorrent` server feature. Membership updates execute in the coordinator owner
task after authentication, using the authenticated identity and lease deadline.
The API supports announce, stopped and scrape events for v1 and full v2 hashes.
This is an overlay JSON API, not a standard HTTP/UDP BitTorrent tracker endpoint.

Kyoto compilation `dbf4d4ad15e04e76adcc0775f64ff228` succeeded. All emitted test
binaries were executed: 67 tests passed, including authenticated swarm discovery,
spoofed-credential rejection, malformed input, stop, hash isolation and lease-bound
expiry. Default-feature-disabled library compilation passed in
`4176047b4e4e430c941f194a0e7570b1`. Formatting and diff checks passed.
Clippy `a38943760c584185b99cb7e33a744c6c` passed across the workspace and all
targets with the BitTorrent feature and warnings denied, after Kyoto retried a
host-memory-pressure interruption. No performance or Internet NAT qualification
is implied.

## Companion selectable exits — 2026-10-29

Added overlay-only (default), local IPv4 TCP/UDP exit and explicitly pinned remote
WireGuard gateway modes. Gateway forwarding requires an explicit peer-key allowlist;
expired bindings remove gateway flow engines. Remote mode never creates a local
exit engine. Scoped native default routing and MTU 1200 are requested only when
an exit mode is selected; the host unscoped default is unchanged.

Workspace compilation `32b4ed25029444508c32fe49fab2791d` succeeded and all emitted
binaries executed: 71 tests passed. New tests include 32 KiB real TCP echo with
half-close, connected UDP flow isolation/expiry, packet validation, and a real
WireGuard-encrypted gateway UDP round trip with authorization/fail-closed checks.
After queue-bound and delivery-timeout fixes, final focused compilation
`33c90a0845d84f7bb0b7170fa169aeb6` succeeded and its 29 library plus 8 companion
tests executed successfully. Initial Clippy attempts found two collapsible-if
style issues; both were fixed. Final workspace/all-target Clippy with BitTorrent
and warnings denied passed in `8fe24ac6d2ec45c489374b640edb263c`.
Formatting and diff checks passed.

Native macOS interface routing and application binding remain UNVERIFIED:
`sudo -n true` reported that a password is required. No privileged host-route test
was performed. This is functional packet/socket evidence, not native-interface,
Internet NAT, throughput, IPv6 or general-purpose VPN qualification. See
`docs/EXIT-MODES.md` for forwarding and DNS limitations.

## IPv6 exits and explicit inbound mappings — 2026-10-29

Extended the exit engine to IPv4/IPv6 TCP/UDP with IPv6 transport checksums and
1280-byte inner MTU. Gateway envelopes permit 1304 bytes without raising ordinary
overlay packet limits. Added explicit local and authorized per-client gateway
TCP/UDP listeners, per-flow replies, same-port separate-family listeners,
proactive binding lookup/retry and lease-bound listener cleanup. Native IPv6
addresses derive from the authenticated IPv4 identity under fdcb::/96.

Initial check `eb41af03f77142278cd7bdcf5bef8acd` caught two IPv4-only exhaustive
patterns after enabling smoltcp IPv6; these now explicitly reject IPv6 in the
separate IPv4 overlay API. Check `d1609704e684461ea3a66a414983258f` passed.
Focused compilation `4f6e8f6ad0424f2a8760777020089cb3` passed and its emitted
binaries executed: 32 library plus 9 companion tests passed. Coverage includes
IPv4/IPv6 inbound TCP/UDP, half-close, IPv6 checksums/full-MTU envelopes, encrypted
gateway round trips and authorized listener expiry.

The final listener change sets IPV6_V6ONLY before bind and adds a same-port
separate-family test. A concurrent earlier Clippy run observed the source change
before the new direct socket2 dependency was in its loaded build graph; it failed
and is not passing evidence. Final workspace compilation
`4b9bbaad789d44a085607aa55052aea4` and workspace/all-target Clippy with BitTorrent
and warnings denied `d3cfffd9cc2a47e3812ad58b71bf1fc5` both passed.

Final workspace test execution completed after a macOS loader delay: all 76 tests
passed (33 library, 6 client, 9 companion, 13 API, 9 async userspace, 4 userspace,
2 BitTorrent library). During the delay, a sample showed the first binary at
`_dyld_start` before test startup; the original run was preserved and completed.
Formatting and whitespace checks passed. Native privileged utun IPv6 routing,
real-client binding and external Internet inbound reachability remain unverified;
no host router/NAT/firewall changes were performed.

## Review fixes: mapped UDP and interface backpressure — 2026-10-29

Outbound-first UDP now selects the configured mapping matching the application's
port and address family instead of allocating an ephemeral socket. IPv4/IPv6
regressions verify the observed external source port and subsequent replies.

Interface writes now run as a separate event-loop branch against a bounded
128-packet queue. Packets expire after at most 20 ms, capped by local/remote lease
deadlines; deadline readiness takes precedence over writes. Overflow is dropped.
Peer-manager timer/send operations use fresh timestamps after exit polling.
The regression covers overflow, other-event progress with a blocked writer,
cancellation preserving the queue and expiry without invoking the writer.

Kyoto workspace test compilation `62ee01735623449b97736b9ef44b9c61` passed. Final
companion compilation after tightening deadline precedence used
`eb51e0f53ade4c2c828e1b2b11bbefd1`; all emitted workspace binaries (including that
final companion artifact) then executed: 78 tests passed. Workspace/all-target
Clippy with BitTorrent and warnings denied passed in
`17ed4d48cc4c4dce97474559897a249a`. Formatting and diff checks passed. Native
privileged interface routing remains unverified.

## Logical identity and WireGuard credential linking — 2026-10-29

Kyoto workspace test compilation with BitTorrent enabled passed as job
`b999c309f514438f9530cd9e2e4c188a` (compilation only). Its emitted test
binaries were subsequently executed through Kyoto as job
`d6a81fe3a210433cb84d8d1d082a14ea`: 85 tests passed, including identity
linking, proof replay, revocation, linked swarm selection and a loopback HTTP
client-helper flow. Default-feature workspace check job
`3b330f2ca141443493bcb5b4db6cdd45` passed. This does not establish native utun
routing, live transport key rotation, immediate distributed revocation, or QUIC
and DTLS support.

The first identity Clippy job `5937106e0adc46e085d1f93f5a9655c2` failed on
`clippy::collapsible_if` in credential-index cleanup; the source was adjusted
and a new Clippy job was queued. The 85-test execution above predates that
style-only adjustment.

After the Clippy style fix, `9a5c2f820e1f4790b2708f24fdda74b0` passed.
A new workspace test compilation `c4d25439b5a94f63ba2809cb615c8e3a`
passed, followed by execution of the async userspace suite
`dc04682b125b4ec9a033ecc8eba237e5`: 10 tests passed. The added test registered
and linked two WireGuard keys over loopback HTTP, exchanged encrypted datagrams
to both over loopback UDP, revoked one registration, checked its binding was
unavailable and exchanged traffic with the remaining credential. This does not
exercise privileged utun, actual client rekeying of one interface, or instant
revocation of cached bindings. Clippy including the new test passed as
`3e1a527e135d4f75af6c53266acb89ba`.

After adding the typed credential index and wrong-key/wrong-audience proof tests,
workspace test compilation `a802f2078fb94f0281a65ea6df7479e2` and the updated
API compilation `83d42db778964c02aea8f0086cf4fa26` passed. All emitted test
binaries then executed in job `622e064dd5ed4705a55bb7686982d7d3`: 86 tests
passed. Workspace Clippy with BitTorrent and warnings denied passed in
`57473a1dbc534c64a046f97135d841df`; the default-feature workspace check passed
in `ecbd27ab61624cea8f44d65866531f06`. These results do not change the native
utun, in-place rekeying or cached-binding limitations stated above.

## Independent endpoint lifetime — 2026-10-29

Workspace test compilation `b18fcd79e740441499f02c0c5e2496d5` passed; all
emitted test binaries executed in `eefeaced3fef4031b266dbd0295e77a0` with
90 tests passed. Coverage includes endpoint expiry without credential expiry,
publication authorization, peer-list lifetime caps, and queued relay expiry.
Workspace Clippy with BitTorrent and warnings denied passed in
`bea1de93dd31431cbb60685e0afa960a`; default-feature workspace check passed in
`fca53ac3b5ea4f3aa057b10d2d2dc8d1`. These checks do not validate immediate
recall of previously issued bindings or privileged native utun routing.

The unsupported-credential-type API regression was added after that workspace
run. Its focused test compilation `58d34d81c68248498040495202324922` passed;
the API binary then executed in `422ed70e730f43f69c0ef75f41fd252d` with all
17 tests passing, including rejection of the unsupported type.

## Endpoint review fixes — 2026-10-29

Explicit endpoint settings now survive credential refresh; changed or expired
endpoints require newly published traversal candidates before peer discovery.
Kyoto workspace test compilation `0804542db7294c6ca23621042621a56e` passed
after pressure-related deferrals; emitted binaries executed in
`71fbaf7df5624c6d84a4266c07d91529`, with 91 tests passing. The default-feature
workspace check `fa993bc513bc4d1da0793c8b75f0b93f` passed. Clippy job
`0c15e8bb9dec4481a6b085c3bb12fd9e` initially failed on an unused test variable;
after its removal, Clippy `f4900a85026c4e91b25f1f8de253e78f` passed.
