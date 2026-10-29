# Supertrackr architecture

## Scope

A Rust/Tokio/Axum RAM-only coordination server for WireGuard peers. It exposes
the base operations register/refresh, get peers, and verify peer, plus optional
traversal candidate, rendezvous, event-polling, and ciphertext relay operations. Private keys stay
on clients. The server exchanges metadata; clients establish encrypted tunnels.

HTTPS is the intended deployed transport. Native macOS testing uses the explicit
loopback-only `--lab-http` mode. Certificate provisioning, HTTPS qualification,
UDP tracker support, Aquatic comparison, and VM testing are deferred.

## Register or refresh

`POST /v1/register` accepts a public key and advertised socket endpoint. Initial
registration, enabled only by `--open-registration`, issues a random session token.
An existing registration can renew its lifetime and update its endpoint only by
presenting its current token and the matching caller public key. Refresh keeps
the token unchanged, consumes no extra capacity, and requires an unexpired lease.
Expired registrations must be cleaned up and registered again with a fresh token.

This prototype authenticates ownership of the session credential, not possession
of the WireGuard private key. Open enrollment permits key squatting; stronger
initial enrollment remains deferred. Advertised IP/port information is not proof
of reachability or ownership of that address.

## Get peers

`GET /v1/peers?limit=20` authenticates the caller and returns active registrations'
public keys, endpoints, and remaining lifetimes, excluding the caller. The list
limit is 1–100. Selection advances a registry-owned cursor, examines at most 4,096 records,
and returns at most the requested count. The compact key index prevents permanent exclusion of a fixed suffix.
It is a bounded sample, not complete pagination or a uniformly random sample. It may return fewer peers after concurrent
expiry or when its examination budget is exhausted.

Each command executes sequentially against the exclusively owned registry. Caller
and returned peers are checked at the same processing timestamp without storage
locks or interleaved mutations. Metadata can still become stale immediately after
execution. Clients must refresh discovery or verify a new binding when appropriate.
No peer maps are continuously synchronized.

## Verify peer

`POST /v1/verify` accepts an incoming peer's claimed public key and endpoint and
requires the verifying client's session credentials. It checks both registrations
and an exact match to the stored target endpoint. A successful response contains
`verified: true`, the matched key/endpoint and remaining registration lifetime.
The caller is authenticated before target existence is inspected. Missing or expired targets return 404; a different endpoint returns 409. A caller
cannot verify itself. These checks are observations of current RAM state, not
cryptographic proofs or persistent grants.

A obtains B's public key through the tracker. Both clients configure WireGuard from
tracker metadata; there is no peer-to-peer public-key introduction listener.
`/v1/verify` retains exact-primary-endpoint semantics for existing consumers.
Traversal clients use `/v1/connect` to obtain current key and candidate metadata
atomically under the same caller/target lease checks.

## NAT traversal and rendezvous

The client owns one UDP socket for STUN, WireGuard handshakes, direct probes, and
encrypted data. Up to two numeric STUN servers are queried with random 96-bit
transaction IDs. Responses must match the server address and outstanding ID,
valid length/type/cookie/attributes, and fingerprint when present. IPv4 and IPv6
XOR-MAPPED-ADDRESS are decoded. Mapping hints expire after 30 seconds and are
normally refreshed every 10 seconds, with bounded retransmissions on loss. This
is a minimal unauthenticated Binding usage, not a complete ICE/STUN stack.
STUN mappings are hints, never identity proofs; destination-dependent NAT can
produce a different mapping toward another peer.

`POST /v1/candidates` publishes 1–8 distinct UDP socket addresses for the authenticated
caller. The client combines host or explicit candidates, STUN observations, and
optional router mappings. Publishing replaces the list, including withdrawal of
expired mappings. The base registration endpoint is independent of these hints.

`POST /v1/connect {"public_key":"..."}` authenticates the caller, checks both live
registrations and traversal enrollment, returns the target's current candidates,
and asks the target to connect back. Each traversal participant selects up to 64 peers
in this prototype. `GET /v1/events` consumes current connection requests and queued
relay packets. Incoming requests contain tracker-sourced metadata, not a key
asserted in an unauthenticated peer datagram. A passive client learns its peer here.
The server does not broadcast a full peer map. Known-key connections use a direct
lookup; discovery remains available when no target key has been configured.

Clients send WireGuard traffic toward candidate addresses on both sides. Only a
successfully decrypted packet with the expected inner IPv4 addresses and test
payload can validate a direct path. A new source address is allowed to try WireGuard
authentication; its address alone never promotes it. Direct reachability is trusted
for five seconds after authenticated traffic. Unique encrypted probes every two
seconds keep trying candidates even while using a relay. An unavailable direct path
causes ciphertext to use the HTTP relay; later authenticated direct traffic upgrades
it again. No separate discovery cryptography or peer-supplied public keys are added.

The optional server `--stun-listen` UDP socket supplies a stateless reflector for
attribute-free Binding requests. It derives the reply only from the observed UDP
source and caps replies at 1,000 per second globally. In lab HTTP mode this listener
must also be loopback. This is a NAT helper, not a BitTorrent UDP tracker.

## Relay and resource bounds

`POST /v1/relay {"public_key":"...","packet":"<hex ciphertext>"}` transports one
WireGuard datagram to a mutually selected live peer. The server does not decrypt it.
Both registrations and the sender's credential hash are rechecked when queued data
is delivered. Removing/re-registering a key cannot inherit its former inbox or
make messages from the former session valid. Poll delivery is at-most-once;
HTTP failure after a drain can lose messages. WireGuard retransmits handshakes,
while the test application retries with new packets.

Traversal state is allocated only on candidate publication, separately from the
compact registration records: at most 4,096 traversal participants, eight pending
requests per participant, 32 relay datagrams per recipient, and 4,096 queued relay
datagrams globally. Datagram size is at most 2,048 bytes, so queued ciphertext
payload is bounded at 8 MiB plus structures/allocations. Requests and datagrams
expire after ten seconds. Maintenance reclaims them while visiting their peer;
expiry and session checks reject them even before reclamation. Overflow returns
503; clients count relay drops. These bounds describe stored traversal state, not
total process RAM or the existing unbounded owner-command channel.

The client has bounded relay (32) and control-event (64) channels. HTTP work runs
in an independent task so control latency cannot stall UDP reception. The worker
renews leases, publishes changes, connects to its selected peer, refreshes selected-peer metadata every 500 ms, and polls events
at 100 ms intervals. Any control transport/authentication failure terminates the
client. Relay admission races/full queues are counted as drops rather than fatal.
This HTTP polling relay is a functional fallback for the small packet prototype,
not a high-throughput replacement for DERP or a streaming relay.

## Optional router mapping

The `router-mapping` Cargo feature adds the Rust `portmapper` 0.20.0 library
(PCP, NAT-PMP, and UPnP). It also requires explicit client `--portmap`,
`--allow-network`, and a non-loopback IPv4 bind. No router discovery occurs by
default. The library manages mapping acquisition/renewal; the client republishes
address changes, retries acquisition every 15 seconds, and requests deactivation
on orderly shutdown. Deletion is best effort; router lease expiry remains the
fallback on crash or shutdown failure. Rust 1.91 is required by this optional
library, and is now the package's declared minimum. Real router behavior has not
been qualified in the local tests.

## State, policy and limits

`core::Registry` exclusively owns a hash map, discovery key vector, cursor and
configuration, and lazy traversal mailboxes. Its synchronous methods take an explicit timestamp and contain no
locks, atomics, channels, clocks or I/O. There is no whole-registry cloning. The
record count comes directly from the owned map.

`coordinator::Coordinator` is a command handle. A single spawned Tokio task owns
the registry and processes registration, refresh, discovery, verification, count
and cleanup commands. It supplies current processing time, not enqueue time.
The command channel is currently unbounded, distinct from load-generator queues.
Messages and one-shot replies synchronize callers; the registry itself is never
shared. The owner serializes all operations and maintenance. Periodic cleanup checks
at most 4,096 entries per batch, removes expired index entries with swap removal,
and resets its 20 ms timer after completion. Requests run between batches. The
explicit full-cleanup command remains available for tests and maintenance callers;
it can still pause the owner for a complete scan.

Dropping all sender handles closes the task after queued commands are handled.
A reply already cancelled when dequeued causes that operation to be skipped;
cancellation after execution starts does not roll back mutations. Owner loss maps
to an unavailable response. A Tokio runtime is required to create the command handle;
the registry can also be tested directly without one.

HTTP adapters parse/encode transport data and generate/hash new token material.
The registry handles admission, storage, constant-time credential-hash comparison
and model decisions. Statelessness models creation, refresh, expiry and access
policy. Inputs contain leases, authentication facts, target bindings, claims and
explicit time. No decision is retained as a cached authorization grant. The pure
models contain no I/O, cryptography or synchronization and do not establish a proof
of the entire runtime.
Cleanup advances a separate cursor through the discovery index. Total reclamation
time depends on population and load; expiry checks reject access immediately, before
physical removal. Storage for the configured capacity is reserved during startup
to avoid growth reallocations during the initial fill. Lease eligibility uses the same
allocation-free predicate in the model and cleanup. Restart clears registrations
and credentials.

All live registrations may discover and verify all others under the current open
lab policy. Swarm membership, invitations, accounts, key rotation, administrative
revocation, tunnel-address allocation and allowed-IP policy remain deferred.
Expiry at the server does not automatically close an existing client tunnel.
The base API expresses remaining lifetimes in whole seconds; client deadlines
inherit that granularity and are not an instantaneous revocation mechanism.

The `client` binary remains a single-peer BoringTun 0.7.1 prototype with manually
configured private inner IPv4 addresses. It pins the first tracker-authorized peer
(or `--peer-key`), checks local and peer lease deadlines before data processing,
and stores private keys in owner-only files. Session credentials remain in RAM.
Loopback is the default; external UDP requires `--allow-network`, while off-loopback
HTTP control still requires HTTPS and normal certificate validation.

The client carries real encrypted IPv4/UDP ping/pong payloads but creates no OS TUN,
routes, or general application forwarding API. Local tests include a userspace NAT
and address-dependent filter simulation, forced relay, path loss, and mapped-port
changes. They do not qualify real routers, public NAT traversal, production relay
capacity, or HTTPS deployment. Reconnect recovery, multi-peer routing, QUIC/DTLS,
server persistence/replication, and BitTorrent integration remain deferred.
The previous repository remains under `untracked/`.

Historical benchmark receipts describe earlier APIs. They cannot establish the
performance of the current implementation or its traversal operations. The generator retains unlimited
worker queues and RAM monitoring as requested; completion accounting, queue delay
and drain time must be considered separately from the requested offer rate.

## Reference implementations and protocol

- [Tailscale magicsock](https://github.com/tailscale/tailscale/tree/main/wgengine/magicsock): reference for separating transport path management from WireGuard.
- [STUN RFC 8489](https://www.rfc-editor.org/rfc/rfc8489.html): Binding transactions and XOR-MAPPED-ADDRESS.
- [Rust portmapper](https://github.com/n0-computer/net-tools/tree/main/portmapper): optional router mapping implementation.

This prototype is not wire-compatible with Tailscale disco or DERP.

## Native macOS companion prototype

`companion` now connects a macOS `utun` interface to a shared, socket-independent
multi-peer WireGuard engine. The existing `client` binary remains the single-peer
packet lab. This is an administrator-run CLI, not a signed Network Extension app.

Publishing candidates allocates an IPv4 address from `10.203.0.0/16`. Authenticated
`GET /v1/interface` returns the caller's assignment. The companion uses read-only
`POST /v1/lookup {"virtual_ip":"10.203.0.2"}` for destination discovery and
`POST /v1/binding {"public_key":"..."}` for registration verification/renewal.
Neither selects a peer, queues an introduction, nor grants relay permission.

The default `--introduction direct` delivers introductions over the same UDP
socket as WireGuard:
A sends HELLO with its public key, the SHA-256 identifier of the configured tracker
origin, and a random nonce. B returns a fresh random challenge; A echoes it in
CONFIRM. Only then does B verify A's binding with B's configured trusted tracker,
install it and send ACCEPT. A installs B's previously verified binding after
matching ACCEPT to its pending exchange. WireGuard subsequently proves possession
of private keys. The introduction does not grant IP access by itself, and the
return-address challenge proves reachability, not identity. Peer input cannot
supply an arbitrary URL or change the trust authority.

Messages have a fixed 104-byte versioned format; responses are no larger than
requests. Each side has at most 64 pending exchanges, five-second timeouts and
500 ms initiator retries. A global per-companion budget allows 64 introduction
messages per second. Incoming verification is deduplicated per exchange and
starts only after the return challenge. Late HTTP results cannot revive expired
exchanges. Accepted responses can be retransmitted during that short exchange
window. This is a prototype control protocol, not Tailscale or WireGuard wire
compatibility for introductions, and not production DoS qualification.

The companion never polls `/v1/events` or calls `/v1/connect`, `/v1/resolve`, or
`/v1/relay`. Those APIs remain for the older packet lab. The new companion uses
server-assisted NAT rendezvous without relay. After discovery, authenticated
`POST /v1/rendezvous {"public_key":"..."}` requests that the target open its UDP
mapping toward the caller. The target polls `GET /v1/rendezvous` every 100 ms and
receives candidate endpoints and their short remaining lifetime. In default direct
mode this contains no public keys or virtual addresses and grants no tunnel access.

With `--introduction server`, POST adds `"include_binding":true`. The server stores
only that flag with the authenticated sender credentials; when the target polls,
it revalidates both registrations and creates an optional `binding` object with
the sender's current key, assigned virtual IP, candidates and remaining lease.
The sender cannot supply this binding. The receiver can install that verified
binding directly; the initiator already has the target's binding from lookup.
They then perform WireGuard's normal handshake, which still proves private-key
possession. Binding expiry is distinct from the short NAT-attempt lifetime and
is bounded by both registrations. Expired/replaced sender credentials invalidate
queued notifications. Neither option creates relay permission or pair-selection
state. This is per-connection information, not a synchronized peer-key map.

The CLI mode controls outbound preference; both paths are accepted inbound from
the configured trusted authority. Mixed preferences therefore interoperate.
Server mode waits for a successful rendezvous enqueue before installing the
outbound binding, and does not silently fall back to a direct introduction.

Rendezvous requests are deduplicated by sender, capped at eight pending per target,
expire after five seconds, and are limited to eight per caller per server-clock
second. Delivery rechecks both registrations and the original sender credentials,
then uses current published candidates. A companion keeps at most 64 endpoint
attempts and sends 16-byte probes every 300 ms for at most three seconds, bounded
by hint expiry. Incoming probes are silently discarded; they create no peer state
and trigger no replies. These outbound packets open NAT filters so direct key
introductions and WireGuard authentication can proceed. STUN uses the same UDP
socket to discover external mappings. Candidates remain hints, not ownership or
identity proof; the bounds are not production abuse qualification.

This polling implementation is a prototype, not a high-population control-plane
capacity claim. It supports NAT traversal attempts, not guaranteed reachability
through every NAT/firewall. UDP-blocked or incompatible NAT pairs can fail;
there is deliberately no relay fallback in the companion.

Virtual addresses are never reused during a tracker process lifetime; exhaustion
after 65,534 allocations fails without a partial assignment. At most 4,096 peers
have traversal state. RAM-only restart clears credentials and resets allocation.
Companions fail closed on control failure and do not re-enroll automatically.
Application discovery and cached virtual IPs must be discarded before restarting
a deployment; durable address identity across restart is not implemented.

The companion routes outbound packets by assigned virtual destination and checks
both inner source and destination after WireGuard decryption. Unknown destinations
trigger deduplicated resolution with at most 64 destinations, four buffered packets
each and a three-second lifetime. It supports 64 simultaneous tunnels, with bounded
control channels. Unrecognized UDP packets may try up to 64 WireGuard sessions;
this prototype has no high-rate demultiplexing/performance qualification.

The adapter configures IPv4 MTU 1280 and only the overlay subnet route. Existing
overlapping IPv4 routes cause startup to fail; the default route and DNS settings
are untouched. Dropping the adapter removes its interface-scoped route and closes
the utun descriptor. Cleanup after signals/crashes and real routing behavior still
need privileged runtime validation. Generic IPv4 payloads pass through; internal
path probes use protocol 253 with an STP1 marker. IPv6 overlay routing is absent.
This prototype does not install an OS kill switch: stop applications before
stopping the companion, because removing its route restores ordinary OS routing.
UDP endpoint candidates must be outside the overlay. A concrete local bind IP is
required; same-socket STUN and authenticated path probing are supported. Optional
router mapping is available with the `router-mapping` feature and explicit
`--portmap --allow-network` on a non-loopback IPv4 bind. Real router lifecycle
validation is still pending.

Local and remote leases gate packet processing independently of HTTP progress.
Verified bindings are cached and checked again halfway through their remaining
lifetime, with a maximum 30-second interval. The worker refreshes one due peer per
tick; under load or very short leases peers can expire before refresh and fail closed. Use the default 300-second
TTL for the companion. This is not a lossless transport or capacity claim.

The automated packet adapter uses owner-only Unix datagram sockets and makes no
OS networking changes. Tests exercise three real companion processes, on-demand
direct introductions and multiple encrypted sessions with the old key-introduction
and relay endpoints explicitly blocked, plus server-assisted hole punching under
a userspace NAT simulation,
source-address isolation, bounds and expiry. Their TCP-shaped packets are synthetic;
they do not establish real TCP connections. Native utun creation and application
TCP/UDP traffic remain unverified because this session has no administrator access.

Applications must discover assigned virtual IPs plus their actual listening ports.
The JSON API does not implement native BitTorrent announces. Public DHT/PEX results
do not automatically become encrypted overlay peers. One configured tracker is
supported; multiple authorities require separate address domains or translation.

## Tailscale reference audit

See [CONNECTIVITY-AUDIT.md](docs/CONNECTIVITY-AUDIT.md) for the pinned upstream
source comparison, implemented corrections and remaining acceptance gates.
WireGuard-encrypted path probes now echo nonces and require a matching endpoint
and response window before path selection. Selection uses smoothed RTT, a 25%
improvement threshold and expiring measurements; incoming data alone cannot select
a path. Per-peer path state is bounded at 16 endpoints. STUN can report observed
destination-dependent mapping when two distinct server IPs provide fresh evidence.
This does not establish Tailscale parity or real-network qualification.
