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
