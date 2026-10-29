# Supertrackr prototype

A minimal Rust coordinator for on-demand WireGuard peer setup. Tokio/Axum serves
HTTP(S); Statelessness models registration lifecycle and caller/peer access decisions. Runtime state is RAM-only. This is a new prototype, not the archived
Go server.

Requires Rust 1.91 or newer.

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
`--cert` and `--key` PEM files plus `--public-origin https://tracker.example/` are required. Certificate provisioning and HTTPS
qualification are deferred. Registration is closed unless `--open-registration`
is supplied. No UDP listener, VM, database, or Tailscale client is required.

## API

Public keys are 64 hexadecimal characters encoding 32 bytes. Endpoint hints
are socket addresses such as `127.0.0.1:51820`.

- `POST /v1/register/challenge`: JSON `{"public_key":"…","endpoint":"127.0.0.1:51820","client_nonce":"<32 random bytes as hex>"}`.
  Returns `id`, `server_key`, `nonce`, and `ciphertext` for a 30-second encrypted
  key-possession challenge. Requires `--open-registration`; creates no registration.
- `POST /v1/register`: JSON `{"public_key":"…","endpoint":"127.0.0.1:51820","proof":{"id":"…","response":"…"}}`.
  Without credentials, consumes a valid proof and returns a random session token
  plus `expires_in_seconds`. Both bundled clients perform this exchange automatically.
  With matching caller credentials, omit `proof` to refresh the lease and endpoint,
  returning the same token. An established registration cannot be overwritten.
- `GET /v1/peers?limit=20`: returns an array of peers with `public_key`, `endpoint`
  and `remaining_seconds`. Excludes the caller; accepts a limit of 1–100.
- `POST /v1/verify`: JSON with the incoming peer's `public_key` and `endpoint`.
  Returns `verified: true` plus the matched peer fields only if the exact binding
  is currently registered. Unknown/expired targets return 404; endpoint mismatch 409.
- `POST /v1/candidates`: JSON `{"candidates":["127.0.0.1:51820"]}` replaces
  the caller's list (1–8 unique addresses) and opts it into traversal.
- `POST /v1/connect`: JSON `{"public_key":"…"}` selects a peer (up to 64 per caller), returns its
  current key/candidates/lifetime, and requests reciprocal connection through the tracker.
- `GET /v1/events`: consumes connection requests and queued relay packets.
- `POST /v1/relay`: JSON `{"public_key":"…","packet":"<hex ciphertext>"}` queues
  one WireGuard datagram, up to 2,048 bytes, only between mutually selected peers.
- `GET /health`: process liveness only.

Refresh, discovery, verification and all traversal operations require `X-Peer-Key: <caller public key>` and
`Authorization: Bearer <session token>`. Initial registration requires
`--open-registration`. Tokens are stored as SHA-256 digests and compared in constant
time. Private WireGuard keys are never sent to this server.

## Prototype policy and boundaries

All live registrations may discover and verify each other. Public registration
is account-free: no name, email, or real-world identity is required. Enrollment
proves control of the WireGuard private key; the public key is a pseudonymous
identity. It does not hide IP addresses or prevent one party creating many keys.
Rate limiting and Sybil defenses remain separate, deferred work. Verification
checks the current registered binding, not endpoint reachability or a live tunnel.
See [the enrollment protocol](docs/ENROLLMENT.md) for the proof and its boundaries.

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
The default registration capacity is 100,000, request bodies are limited to 8 KiB,
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

Traversal participants opt into bounded candidate lists, connection requests and relay inboxes.
The old `/v1/peers/{key}`, `/v1/connect/{key}`, `/v1/pending`, and `/v1/self` routes
are removed. Statelessness models the lease lifecycle and deterministic access
decisions (caller eligibility, target expiry, self-query rejection and endpoint
matching). The registry supplies authentication facts; these models perform no
I/O, crypto or locking. The registry itself performs constant-time token-hash
comparisons. Complete runtime verification and capacity qualification remain open.

The server assigns virtual addresses and verifies registrations. The companion
implements direct peer introductions, configures WireGuard, and stops accepting
traffic when its cached authorization expires. The server does not control OS
interfaces or directly close remote tunnels.

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
refresh are measured separately. Creation now includes an encrypted challenge and
proof completion (two HTTP requests); refresh remains one request. Echo calibration
uses `--calibration-only` and tests response handling, not the enrollment crypto
workload. Earlier single-request creation rates are not comparable. Discovery requests 20 peers
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
packets in-process over direct UDP or an HTTP ciphertext relay. Loopback is the default. It requires no root privileges and creates
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
by this lab. Both clients prove key possession during enrollment; the subsequent
WireGuard handshake independently authenticates the data connection.

## NAT and relay lab

```sh
# After rebuilding release binaries:
python3 scripts/check_nat.py --scenario nat
python3 scripts/check_nat.py --scenario relay
```

The NAT check starts two clients, one passive, and a userspace UDP NAT/filter
simulator. It checks relay startup, coordinated direct hole punching, fallback
after UDP loss, and recovery after a mapping change. These are real encrypted
packets on loopback, not public-network or kernel-NAT qualification. The relay
check disables direct UDP entirely. Receipts include source/binary hashes and
per-client counters; temporary private keys are removed on exit.

For a self-contained STUN lab, add `--stun-listen 127.0.0.1:3478` to the server
and `--stun 127.0.0.1:3478` to both clients. The reflector reports the observed UDP
source; on loopback that will match the socket's local address. It is optional
and independent of the HTTP listener.

For external testing, the client accepts `--allow-network --listen 0.0.0.0:51820`
and `--stun <numeric-address>:3478`; use an HTTPS tracker. STUN runs on the same
socket as WireGuard. You may supply up to two STUN servers and five explicit
`--candidate <address>:<port>` values. Explicit candidates replace the host
candidate; mapped candidates are then added. A wildcard bind needs a STUN server
or explicit candidate to choose a local route. Each run uses one outer address
family, while the test payload remains IPv4. No live external test is claimed.

`--passive` waits for a tracker request instead of selecting a discovery result.
`--relay-only` disables direct traffic for testing. Peer keys always come from the
tracker; no peer-to-peer key introduction protocol is implemented.

Optional router mapping (PCP/NAT-PMP/UPnP) uses the Rust `portmapper` library:

```sh
python3 /path/to/kyoto/kyoto.py submit -- cargo build --release --bin client --features router-mapping
# Then add --portmap to an external IPv4 client command with --allow-network.
```

Router mapping is off by default and actual gateway acquisition/renewal/deletion
has not been exercised. The feature adds dependencies only to enabled builds.
Mapping addresses are published as hints; WireGuard authentication still validates
peer traffic. Shutdown requests mapping removal, with lease expiry as fallback.

The relay is a bounded HTTP polling prototype, not a throughput-qualified streaming
service. Traversal is limited to 4,096 active participants and up to 64 selected peers
per participant. Each recipient can queue 32 datagrams, with 4,096 datagrams
(8 MiB maximum ciphertext payload) globally and ten-second message lifetimes.
Eight connection requests per recipient are retained. Overflow returns 503 and
client relay drops are counted. These bounds do not bound total process RAM or
the existing unbounded coordinator command channel. See ARCHITECTURE.md for
lifecycle, authorization and delivery semantics.

To simulate larger traffic, use `scripts/check_nat.py --scenario direct` (or
`relay` / `nat`) with `--packets-per-second 100 --packet-size 1200`. The requested
application rate is emitted in 100 ms batches; small path probes are additional.
Client summaries record generated requests, inner bytes, completed round trips,
timeouts and pending requests at shutdown. There is no final drain period; pending
requests are not classified as losses. A harness `passed` result means functional
connectivity and accounting assertions passed, not lossless delivery or capacity.

## Native macOS companion (prototype)

`companion` manages multiple WireGuard peers behind one native `utun` interface.
It discovers virtual destinations through the configured tracker, then exchanges
public-key introductions directly between companions over UDP. The receiver checks
registration with its configured tracker; WireGuard proves private-key possession. The server allocates addresses in `10.203.0.0/16`; only this subnet is
routed into the interface by default. Optional exit modes add interface-scoped
default routes without changing the host defaults or DNS; see [EXIT-MODES.md](docs/EXIT-MODES.md).

Build through Kyoto:

```sh
python3 /path/to/kyoto/kyoto.py submit -- cargo build --bin companion --bin supertrackr
```

For a local tracker, start it normally:

```sh
./target/debug/supertrackr --lab-http --open-registration --listen 127.0.0.1:8443
```

Then launch the native companion from an administrator terminal:

```sh
sudo ./target/debug/companion --server http://127.0.0.1:8443/ \
  --lab-http --key-file /var/root/supertrackr-companion.key
```

The ready record prints the assigned virtual IP and interface name. Applications
connect to a remote peer's virtual IP and application port. For separate machines,
use a trusted HTTPS tracker, `--allow-network`, a concrete `--listen LOCAL_IP:PORT`,
and optionally up to two `--stun IP:PORT` reflectors. `--candidate IP:PORT` adds an
explicit endpoint, and direct introductions use that same UDP socket. Default peer TTL is
300 seconds. Ctrl-C closes the interface. A live registration currently prevents
re-enrolling the same key until its lease has expired and cleanup runs.

This is a root CLI, not a packaged macOS VPN app. The native adapter compiles but
has **not been run with administrator privileges** in this session. Real TCP/UDP
application acceptance through utun and route cleanup still need that test.
Overlay peer routing is IPv4 only; optional Internet exit forwarding supports
IPv4/IPv6 TCP/UDP and explicit inbound mappings. MTU is 1280, with at most 64 active
peer sessions; overlay route conflicts are
rejected. Tracker restarts invalidate registrations and require clearing application
address caches before re-enrollment. BitTorrent announce integration is separate.

Unprivileged integration checks (real WireGuard, synthetic inner IP packets):

```sh
python3 scripts/check_companion.py
```

These run three companion processes using owner-only Unix datagram adapters. The test proxy
rejects the old key-introduction, event and relay endpoints while allowing
endpoint-only rendezvous. Tests verify all
six directed peer pairs with TCP-shaped and UDP payloads, not real TCP
socket connections or native interface routing. Retries and drop counters are
reported; a functional pass does not imply lossless forwarding or performance.

The companion supports two introduction options, both using server-assisted NAT
rendezvous and WireGuard, with no relay fallback. `/v1/rendezvous` queues short-lived endpoint
hints so the target sends outbound UDP probes while the initiator attempts to
connect. With the default `--introduction direct`, hints contain no public keys;
companions exchange keys directly and verify them with the trusted tracker.
With `--introduction server`, the notification also carries the sender's live,
server-owned key/IP binding, letting the target install it and proceed directly
to the WireGuard handshake. WireGuard still proves private-key possession.
This flag selects the outbound preference; inbound connections support either
option, so different preferences interoperate. No fallback is silently selected
if a server-assisted rendezvous fails. STUN and
probes use the same socket as WireGuard. Not every NAT/firewall permits a direct
connection; UDP-blocked peers fail to connect without a relay.

`/v1/lookup` and `/v1/binding` remain read-only discovery/verification endpoints.
The server does not synchronize peer-key maps for this handshake. The old `client`
lab retains its separate signaling/relay experiments.

Test reciprocal punching with a userspace NAT/filter simulation and a negative
control (neither test changes OS networking):

```sh
python3 scripts/check_companion.py --nat
python3 scripts/check_companion.py --nat --introduction server
python3 scripts/check_companion.py --nat --introduction mixed
python3 scripts/check_companion.py --nat --disable-rendezvous
```

The negative control must remain disconnected. The simulator hides private
same-host candidates and drops inbound traffic until the recipient has sent to
the sender's mapped endpoint. These checks are not real-router or Internet NAT
qualification. The companion polls rendezvous every 100 ms in this prototype.

The [Tailscale connectivity audit](docs/CONNECTIVITY-AUDIT.md) records source-backed
gaps and validation. The companion now uses nonce-correlated encrypted path probes,
measured RTT with stable selection, and expiring path trust. Optional router mapping
is available when built with `--features router-mapping` and explicitly launched
with `--portmap --allow-network` on a non-loopback IPv4 address. Actual router mapping
has not been tested here. `mapping_varies_by_destination` in the summary needs fresh
STUN observations from distinct server IPs; null means insufficient evidence.

Expanded simulated network checks:

```sh
python3 scripts/check_companion.py --nat --introduction mixed --recovery
python3 scripts/check_companion.py --nat --nat-mode endpoint-dependent
python3 scripts/check_companion.py --nat --nat-mode udp-blocked
```

The latter two must remain disconnected without relay. Recovery checks cover
simulated UDP loss and public NAT rebinding, not actual OS interface changes.

## Embedded userspace connections

Rust applications can use `supertrackr::async_userspace::Client` for awaitable TCP
and UDP over WireGuard without an OS virtual interface. TCP streams implement
Tokio AsyncRead/AsyncWrite; one background task owns polling and UDP I/O. Tracker
control remains explicit. The lower-level `userspace::Network` API is also available. See [the API guide](docs/USERSPACE.md) and the runnable
[tracker-backed TCP/UDP echo example](examples/userspace_echo.rs).

## Optional BitTorrent swarm tracking

The `bittorrent` Cargo feature enables an authenticated overlay swarm API backed
by the separate `supertrackr-bittorrent` library. See [BITTORRENT.md](docs/BITTORRENT.md)
for request formats, limits and client integration. Default builds remain generic.

## Interface exit options

The companion can optionally forward ordinary IPv4/IPv6 TCP/UDP locally or through an
explicitly authorized WireGuard gateway. Overlay-only remains the default. See
[EXIT-MODES.md](docs/EXIT-MODES.md) for flags, gateway setup and current transport
and native-routing validation limits.
