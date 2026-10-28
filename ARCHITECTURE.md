# Supertrackr architecture

## Scope

A Rust/Tokio/Axum RAM-only coordination server for WireGuard peers. It exposes
three operations: register/refresh, get peers, and verify peer. Private keys stay
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
limit is 1–100. Selection rotates the initial shard and a cursor within each shard, examines at most 4,096 records,
and returns at most the requested count. The compact per-shard key index prevents permanent exclusion of a fixed suffix.
It is a bounded sample, not complete pagination or a uniformly random sample. It may return fewer peers after concurrent
expiry or when its examination budget is exhausted.

Each returned record is checked alongside the caller under ordered shared shard locks;
the caller is also checked before returning. A list is not a global atomic
snapshot, and metadata can become stale immediately after a check. Clients must
refresh discovery or verify a new binding when appropriate. No peer maps are
continuously synchronized.

## Verify peer

`POST /v1/verify` accepts an incoming peer's claimed public key and endpoint and
requires the verifying client's session credentials. It checks both registrations
and an exact match to the stored target endpoint. A successful response contains
`verified: true`, the matched key/endpoint and remaining registration lifetime.
The caller is authenticated before target existence is inspected. Missing or expired targets return 404; a different endpoint returns 409. A caller
cannot verify itself. These checks are observations of current RAM state, not
cryptographic proofs or persistent grants.

A obtains B's public key and endpoint through discovery. When B receives A's
introduction, it can verify A's claimed binding if it has not already obtained
trusted metadata. WireGuard subsequently proves possession of each configured
private key. The direct introduction listener/protocol and client implementation
are not part of this server prototype. NAT traversal may require further coordination.

There are no pending introductions, connection-request queues, poll endpoints, or
server-side pair graphs. The old lookup, connect, pending and self-removal routes
have been removed. `/health` remains a process-liveness endpoint.

## State, policy and limits

The host has 64 randomized hash shards protected by read/write locks, compact
binary keys, constant-time token hash comparisons, and a global registration
capacity. Verification and discovery use shared locks. Creation, refresh and
cleanup use exclusive locks. The sampling cursors use atomics, and discovery
checks multiple peers during one ordered shard-pair visit rather than reacquiring
locks per peer. Concurrent samples may overlap; one response has no duplicate keys.

Token parsing, new-token randomness/hashing, and response encoding happen outside
write critical sections. No lock crosses an await. Pair checks lock in a consistent
order and observe the caller and target records together. This remains a synchronized
host, not a lock-free server. Read/write locks permit concurrent readers, but their
performance and writer scheduling depend on the workload and platform.

Statelessness models creation, refresh, expiry and access decisions. The access
model consumes a caller lease, host-supplied credential-match fact, target binding,
claimed endpoint and timestamp. Authentication failure takes precedence over all
target decisions. Discovery and verification share this policy. Decisions are
recomputed for each observation and never retained as authorization grants.
The core performs no I/O, randomness, cryptography or synchronization, and does
not prove the entire concurrent host.
Cleanup scans shards every five seconds. Expired entries fail validity checks
immediately, even before cleanup. Restart clears registrations and credentials.

All live registrations may discover and verify all others under the current open
lab policy. Swarm membership, invitations, accounts, key rotation, administrative
revocation, tunnel-address allocation and allowed-IP policy remain deferred.
Expiry at the server does not automatically close an existing client tunnel.

No WireGuard handshake, reachability, NAT traversal, relay, or data-transfer proof
is claimed. QUIC/DTLS profiles, persistence, replication and BitTorrent application
integration are deferred. The previous repository remains under `untracked/`.

Historical benchmark receipts describe earlier APIs. They cannot establish the
performance of this three-operation design. The generator retains unlimited
worker queues and RAM monitoring as requested; completion accounting, queue delay
and drain time must be considered separately from the requested offer rate.
