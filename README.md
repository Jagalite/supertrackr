# Supertrackr prototype

A minimal Rust coordinator for on-demand WireGuard peer setup. Tokio/Axum serves
HTTP(S); Statelessness models registration lifecycle and caller/peer access decisions. Runtime state is RAM-only. This is a new prototype, not the archived
Go server.

## Local run

Build through the shared Rust queue:

```sh
python3 /path/to/kyoto/kyoto.py submit -- cargo build --release --bins
```

After the job succeeds:

```sh
TOKIO_WORKER_THREADS=2 target/release/supertrackr \
  --lab-http --listen 127.0.0.1:8443 --open-registration
```

`--lab-http` explicitly permits plaintext on a loopback IP only. Without it,
`--cert` and `--key` PEM files are required. Certificate provisioning and HTTPS
qualification are deferred. Registration is closed unless `--open-registration`
is supplied. No UDP listener, VM, database, or Tailscale client is required.

## API

Public keys are 64 hexadecimal characters encoding 32 bytes. Endpoint hints
are socket addresses such as `127.0.0.1:51820`.

- `POST /v1/register`: JSON `{"public_key":"…","endpoint":"127.0.0.1:51820"}`.
  With no credentials, creates a registration and returns a random session token
  plus `expires_in_seconds`. With matching caller credentials, refreshes the lease
  and endpoint, returning the same token. A public key alone cannot overwrite a record.
- `GET /v1/peers?limit=20`: returns an array of peers with `public_key`, `endpoint`
  and `remaining_seconds`. Excludes the caller; accepts a limit of 1–100.
- `POST /v1/verify`: JSON with the incoming peer's `public_key` and `endpoint`.
  Returns `verified: true` plus the matched peer fields only if the exact binding
  is currently registered. Unknown/expired targets return 404; endpoint mismatch 409.
- `GET /health`: process liveness only.

Refresh, discovery and verification require `X-Peer-Key: <caller public key>` and
`Authorization: Bearer <session token>`. Initial registration requires
`--open-registration`. Tokens are stored as SHA-256 digests and compared in constant
time. Private WireGuard keys are never sent to this server.

## Prototype policy and boundaries

All live registrations may discover and verify each other. Open registration is
**not WireGuard private-key proof of possession** and permits key squatting.
There is no account, invitation or swarm policy. Verification establishes a current
registered binding, not endpoint reachability or successful WireGuard configuration.
The WireGuard handshake will authenticate key possession on clients.

Registrations expire after 300 seconds by default (`--ttl-seconds`, 1–86400).
Authenticated refresh before expiry extends the lease and can change the endpoint;
expired tokens cannot refresh or resurrect records. Periodic cleanup checks at most
4,096 entries every 20 ms; total reclamation time grows with population and load.
Expired entries can temporarily occupy capacity or return a registration conflict.
Restart clears everything. Key rotation and administrative revocation are deferred.

The synchronous `core::Registry` owns all records, a compact discovery key index,
and separate discovery and cleanup cursors. It has no locks, atomics, channels, clocks or I/O. One
Tokio owner task processes commands sequentially and runs periodic expiry cleanup.
HTTP handlers parse requests, generate/hash new session tokens, submit commands,
and encode responses. The owner supplies processing-time timestamps; queued work
cannot renew or verify a registration using an old enqueue timestamp.

Storage is reserved up front for the configured capacity, trading startup allocation
and reserved memory for avoiding growth reallocations during the initial fill.
The default registration capacity is 100,000, request bodies are limited to 2 KiB,
and discovery examines at most 4,096 records per command. The key index adds 32
bytes per registration before vector spare capacity. Discovery is a bounded,
rotating sample rather than complete pagination or uniform random selection.
Each operation observes a consistent registry state at its processing timestamp;
responses can still become stale after execution.

The coordinator's command channel is unbounded and separate from the benchmark
worker queues. Channel internals provide synchronization, but nothing shares or
locks the registry. All operations and cleanup serialize on the owner task, so
throughput and cleanup pauses need measurement. Dropping all handles closes the
owner after queued commands have been handled. Cancellation observed before
execution skips a command; once an operation starts, it may commit even if its
HTTP client disconnects. An unavailable owner returns HTTP 503.

There are no pending brokering requests, per-peer inboxes, or poll endpoints.
The old `/v1/peers/{key}`, `/v1/connect/{key}`, `/v1/pending`, and `/v1/self` routes
are removed. Statelessness models the lease lifecycle and deterministic access
decisions (caller eligibility, target expiry, self-query rejection and endpoint
matching). The registry supplies authentication facts; these models perform no
I/O, crypto or locking. The registry itself performs constant-time token-hash
comparisons. Complete runtime verification and capacity qualification remain open.

This server does not implement the direct peer-introduction protocol, configure
WireGuard, assign tunnel addresses, perform NAT traversal/relaying, or close an
existing tunnel when a registration expires.

## Tests and benchmarks

```sh
python3 /path/to/kyoto/kyoto.py submit -- cargo test
```

Kyoto may compile tests with `--no-run`. Execute the test binaries named in its
completed build log separately before claiming runtime tests passed.

After a release build, the native benchmark script starts fresh loopback servers,
calibrates the generator against an echo fixture, and records each operation:

```sh
python3 scripts/bench.py --rate 5000 --seconds 10 --population 10000 --repeats 3
```

Receipts under `bench/results/` include source/binary hashes, commands, accepted
and completed work, late offers, queue drops, failures, status codes, latency,
and sampled server/generator/combined RSS, with per-arm RAM time series. Setup is outside timing. By default each process uses two
Tokio worker threads; `--load-threads` changes only the generator. The driver also
accepts `--workers` (default 32). Generator worker channels are currently unbounded. Receipts explicitly label
this mode and report queue wait p99/max plus post-offer drain time. Each HTTP worker owns a persistent Hyper HTTP/1.1 connection. HTTPS retains
the Reqwest path and is untested. A dedicated pacing thread releases offers in
250-microsecond slices, after their scheduled times. Offers delayed over 10 ms
are counted as late and not sent. Both service and scheduled-to-completion
latency are reported for successful requests. Failed calibration prevents the
corresponding server run. Server failures remain in the receipt. Interrupting the
driver with SIGINT or SIGTERM stops and reaps both server and generator. Invalid
settings are rejected before either process is launched. Generator stdout/stderr
are written directly to receipt files so verbose diagnostics cannot fill a pipe
and block process completion.

Run `python3 scripts/check_load.py` after rebuilding the release load binary to
check valid HTTP responses and rejection of a response containing the wrong peer key.
This functional check reports late offers and validates every admitted response;
it does not qualify throughput or relax the benchmark's completeness gate.

Benchmark modes are `register`, `refresh`, `peers`, and `verify`. Creation and
refresh use the same API but are measured separately. Discovery requests 20 peers
by default (`--peer-limit`), validates known keys/endpoints, excludes the caller,
and rejects duplicates. The echo fixture retains at most 101 sample keys for list
response shapes; it implements no registration or authentication policy.

Historical lookup/brokering measurements in `bench/RESULTS.md` apply to the previous
API. They must not be relabeled as measurements of the current design.

Aquatic comparison is deferred. The optional `load --mode aquatic` implements a
one-peer HTTP announce reference but has **not been run or qualified**. Aquatic's
current HTTP implementation requires Linux/Glommio; its native macOS UDP tracker
would be a different protocol and workload. No comparative speedup is claimed.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the broader design. Old files and Git
history remain under the ignored `untracked/` archive.

`--diagnostic` runs server arms even after failed calibration; receipts retain the calibration result. `passed` and `accounting_passed` check completeness only. Always inspect total elapsed time and drain time before interpreting the offered rate as throughput.

Benchmark driver regression tests: `python3 tests/bench_driver_test.py`. These use temporary fake processes to test interruption cleanup and argument validation.

Core cost diagnostics use the pinned `statelessness-debug` monotonic clock and
bounded metric histograms, with a counted allocator in a standalone example:

```sh
python3 /path/to/kyoto/kyoto.py submit -- cargo build --release --example core_costs
# After the build succeeds:
target/release/examples/core_costs > core-costs.jsonl
```

The example measures the production registry at 10k, 100k, and one million peers,
with three repetitions. Timers and allocation counters affect absolute timings;
reporting and histogram updates are outside the timed regions. Allocated-byte
counts are cumulative requested bytes, not live heap usage. This is separate from
HTTP throughput qualification.

For HTTP correlation, set `SUPERTRACKR_COST_DIAGNOSTICS=1` when running
`scripts/bench.py`. The server logs each periodic cleanup batch's wall-clock start and
monotonic duration. The generator retains the first successful response exceeding
10 ms per worker, with approximate wall-clock timestamps for its scheduled offer,
send, and completion. Samples are deliberately bounded and are not a complete
latency trace. Diagnostics are off unless the environment variable is present.


## Local WireGuard client prototype

`client` uses [BoringTun](https://github.com/cloudflare/boringtun), pinned to 0.7.1,
for WireGuard handshakes and encrypted transport. It sends small IPv4/UDP ping/pong
packets in-process over loopback UDP. It requires no root privileges and creates
no OS tunnel interface or routes. This is a single-peer client lab, not general IP
forwarding or BitTorrent integration.

Build through Kyoto, then run the two-process integration check:

```sh
python3 /path/to/kyoto/kyoto.py submit -- cargo build --release --bins
# After the build succeeds:
python3 scripts/check_client.py
```

The check starts a local server and two clients with three-second registration
leases, verifies bidirectional encrypted traffic and repeated refresh, injects an
unknown-source datagram, and saves receipts under `bench/results/client-*`. Private
keys live in a temporary directory and are deleted after the check.

For a manual lab, start `target/release/supertrackr --lab-http --open-registration` and run these
commands in separate terminals (key-file parents must already exist):

```sh
target/release/client --server http://127.0.0.1:8443 --lab-http \
  --key-file /tmp/supertrackr-a.wgkey --tunnel-ip 10.77.0.1 --peer-ip 10.77.0.2
target/release/client --server http://127.0.0.1:8443 --lab-http \
  --key-file /tmp/supertrackr-b.wgkey --tunnel-ip 10.77.0.2 --peer-ip 10.77.0.1
```

Each client binds an ephemeral loopback UDP port, registers, discovers and verifies
a peer, and pins that peer's key for the run. Use `--peer-key <hex-public-key>` to
require a specific peer. `--run-seconds` defaults to 30. Successful completion
requires at least one authenticated round trip. JSON stdout contains public
metadata and counters, never private keys or session tokens.

Private keys are created with mode 0600 and reused; unsafe permissions and final
symlinks are rejected. Store manual keys in a private directory outside the repo.
Session tokens are RAM-only: after a client restart, its previous registration
must expire before the same key can create a new session. Control failures stop
the client; automatic reconnect is deferred. HTTP requires explicit loopback-only
`--lab-http`; HTTPS uses normal certificate validation but has not been exercised
by this lab. Open registration still permits key squatting and does not itself
prove possession of a private key; the WireGuard handshake provides that proof.
