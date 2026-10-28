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

A obtains B's public key and endpoint through discovery. When B receives A's
introduction, it can verify A's claimed binding if it has not already obtained
trusted metadata. WireGuard subsequently proves possession of each configured
private key. The direct introduction listener/protocol and client implementation
are not part of this server prototype. NAT traversal may require further coordination.

There are no pending introductions, connection-request queues, poll endpoints, or
server-side pair graphs. The old lookup, connect, pending and self-removal routes
have been removed. `/health` remains a process-liveness endpoint.

## State, policy and limits

`core::Registry` exclusively owns a hash map, discovery key vector, cursor and
configuration. Its synchronous methods take an explicit timestamp and contain no
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

No WireGuard handshake, reachability, NAT traversal, relay, or data-transfer proof
is claimed. QUIC/DTLS profiles, persistence, replication and BitTorrent application
integration are deferred. The previous repository remains under `untracked/`.

Historical benchmark receipts describe earlier APIs. They cannot establish the
performance of this three-operation design. The generator retains unlimited
worker queues and RAM monitoring as requested; completion accounting, queue delay
and drain time must be considered separately from the requested offer rate.
