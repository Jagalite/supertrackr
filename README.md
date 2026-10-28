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
expired tokens cannot refresh or resurrect records. Cleanup runs every five seconds,
so expired entries can temporarily occupy capacity or return a registration conflict.
Restart clears everything. Key rotation and administrative revocation are deferred.

The server has 64 maps protected by read/write locks, a capacity limit of 100,000 records
by default, ordered pair locking, and a 2 KiB request-body limit. Discovery rotates
its starting shard and its position within each shard, examines at most 4,096
records, and returns a bounded sample. A compact key index adds 32 bytes per
registration before vector spare capacity; stable registrations are not permanently
excluded by a fixed iteration prefix.
It may return fewer than requested and is neither full pagination nor uniform
random selection. Discovery checks multiple peers under each ordered pair of shared shard locks,
without relocking per returned peer. Verification also uses shared locks; registration,
refresh and cleanup use exclusive locks. Sampling cursors are atomic. Token parsing,
new-token generation/hashing and response encoding occur outside the write locks.
Each peer is checked with the caller; the list is not an atomic snapshot. Endpoint changes and expiry can make a response stale.

There are no pending brokering requests, per-peer inboxes, or poll endpoints.
The old `/v1/peers/{key}`, `/v1/connect/{key}`, `/v1/pending`, and `/v1/self` routes
are removed. Statelessness models the lease lifecycle and deterministic access decisions
(caller eligibility, target expiry, self-query rejection and endpoint matching).
The host supplies credential comparisons and synchronized facts; the core performs
no I/O, crypto or locking. Complete concurrent
host verification and large-population cleanup costs remain unqualified.

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
settings are rejected before either process is launched.

Run `python3 scripts/check_load.py` after rebuilding the release load binary to
check valid HTTP responses and rejection of a response containing the wrong peer key.

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
