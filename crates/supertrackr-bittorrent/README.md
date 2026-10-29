# supertrackr-bittorrent

Standalone, dependency-free Rust library for in-memory overlay swarm membership.
The workspace server optionally uses this crate with its `bittorrent` feature.
See [the overlay API](../../docs/BITTORRENT.md).

Create a `Tracker` with explicit `Config` limits. After authenticating a peer with
the coordinator, pass its key, listening port, current lease deadline and torrent
hash to `announce`. Use `peers` for a capped response excluding the requester,
`stats` for current seeder/leecher counts, and `stop` for an authenticated departure.
Propagate coordinator revocations through `remove_peer`. Periodically call `expire`
to reclaim idle state; reads always exclude expired entries. Use one monotonic
seconds timebase for all operations and lease deadlines.

The caller owns authentication, authorization and synchronization. Peer keys in
this API are not credentials. Revalidate discovered identities with the coordinator
before use. Completion is self-reported. v1 and full v2 hashes have distinct keys;
this crate does not translate wire-format truncated v2 hashes or hybrid torrents.

Limits bound swarms, total memberships, peers per swarm and response size. Cleanup
currently scans stored state on announce; peer selection returns an arbitrary
subset without fairness guarantees. This is a functional starting point, not a
high-throughput tracker implementation.

No HTTP/UDP tracker protocol, bencoding, metadata hosting, transfer accounting,
persistence, DHT/PEX or dynamic plugin loading is included.

Validation: `cargo test -p supertrackr-bittorrent` (through Kyoto in this workspace).
