# Multiple credentials per peer

Status: WireGuard credential linking is implemented and tested. Existing transport
APIs continue to address WireGuard keys, while the registry also tracks logical
identities. Other credential types require their own implementation.

A logical peer needs a server-assigned opaque identifier distinct from transport
credentials. Each credential has a typed public identifier, its own expiry and
revocation state, and belongs to at most one live peer. Endpoints belong to a
credential or explicitly identified transport and have independent lifetimes.
BitTorrent peer IDs are untrusted application identifiers, not credentials.

## Linking and lifecycle

Adding a credential must require both an authenticated existing peer session and
proof of possession of the new credential, with a single-use, bounded, expiring
challenge bound to the server audience, peer ID, credential type and public value.
The proof scheme must be defined per credential type: a WireGuard X25519 key
cannot simply be treated as a signing key. Future TLS certificate credentials
need their own explicit proof and verification rules. Do not accept unsupported
types merely because their public bytes have the right length.

A credential cannot be linked to two peers. Linking, uniqueness checks, proof
consumption and insertion must be atomic. Limit credentials and outstanding
challenges per peer and globally. Revocation must invalidate sessions and endpoint
bindings authorized by that credential; changing a transport key must not silently
transfer an existing key's authority. Define last-credential removal and recovery
before exposing revocation. Peer deletion and expiration must remove reverse indexes.

## Compatibility and integration

Existing enrollment creates a logical peer and its initial WireGuard credential;
existing key-based APIs resolve that credential to its peer and retain their
current authentication and lease checks. WireGuard routing still selects an
actual WireGuard key and endpoint; a logical peer ID is not a WireGuard key.
Existing torrent memberships and peer selection need a deliberate migration to
logical IDs, including exclusion of all credentials owned by the requester.
Avoid merging existing independent registrations without proof and explicit
consent from both identities. RAM-only restart behavior remains unchanged unless
persistence is separately designed.

## Required validation

Exercise successful linking, proof replay, expired or cross-peer challenges,
wrong audience/type/key, duplicate ownership, simultaneous linking, bounded
capacity, unauthorized revocation, session and binding invalidation, expiration,
and old-client compatibility. Validate live WireGuard traffic after key rotation;
unit tests alone cannot establish transport interoperability. QUIC and DTLS are
future credential types, not implied transport implementations.

## Current implementation

The coordinator creates an opaque logical ID per registration and indexes up to
8 linked WireGuard credentials per ID. IDs and registrations are RAM-only;
the membership index distinguishes credential types internally, but currently
only the WireGuard type has an implementation. Expiry of one credential does
not extend or expire the others. Existing
key-and-bearer authentication remains in use. A linked credential still has its
own overlay address and lease. Revoking another credential removes its session,
server-side traversal state and tracker memberships; it cannot revoke the calling
credential. A previously distributed binding may remain usable by clients until
its existing lease expires; there is no immediate push revocation mechanism.
Revocation removes this registration and its association with the peer; it is
not a permanent key ban. With open registration, a holder of the revoked private
key can enroll it again as a new, unlinked identity. If every credential expires,
the logical identity is lost and a new registration creates a new one.

`POST /v1/endpoint` publishes a WireGuard outer endpoint with a `ttl_seconds`
between 1 and 86400. The returned lifetime is capped by the calling credential's
remaining lease; this operation does not refresh that lease. Endpoint expiry
prevents fresh peer bindings and coordinator-relayed packets while leaving the
credential and its logical identity live. Candidates are still published through
`/v1/candidates` and share the endpoint's effective binding lifetime; republish
candidates after changing an endpoint or renewing it after expiry; old candidates
are cleared. For registrations that have never used `/v1/endpoint`, authenticated
`/v1/register` refreshes renew the endpoint to the credential deadline for legacy
compatibility. Once explicitly published, the endpoint and deadline are independent
of registration refresh. Previously
issued bindings cannot be recalled, and may remain usable until their original
deadline; no immediate push invalidation is provided.

The authenticated `GET /v1/identity` returns the ID and live WireGuard keys.
Linking currently requires that both keys already have separate live registrations:
the owner requests `POST /v1/identity/link/challenge` using the same fields as
registration challenge, with the new key's registered endpoint and a nonce. The
new key holder solves the challenge using `enrollment::link_audience(origin,
identity)` as its audience; the owner submits the proof to
`POST /v1/identity/link`. Challenges expire after 30 seconds, are one-use and
are limited to 8 per identity and 4096 globally. A linked group cannot be merged
as a whole. `POST /v1/identity/revoke` with `public_key` removes another linked
key. Only WireGuard credentials are supported; QUIC and DTLS remain future work.

Swarm memberships remain per credential. The server's overlay adapter suppresses
the requester's other keys and returns at most one credential per logical identity
and application ID. Counts group by identity and application; a group is a seeder
if any of its active memberships reports completion. Selection and aggregation scan the bounded
swarm; no throughput qualification is claimed. The standalone library's original
stats remain per membership. An expired endpoint suppresses that credential in
peer lists without removing its still-live membership from counts. See
[validation results](../bench/RESULTS.md) for
tested paths and limitations.
