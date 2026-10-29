# Overlay BitTorrent tracker

Build the server with `--features bittorrent` to enable `POST /v1/bittorrent`.
The default build has no BitTorrent routes or tracker state. The standalone
`supertrackr-bittorrent` workspace crate has no networking dependencies.

Enroll, publish candidates and obtain an overlay interface using the normal API.
Send the same `x-peer-key` and `Authorization: Bearer ...` headers to this endpoint.
Only the authenticated identity can update its own swarm memberships.

Announce a listening application port (not the outer WireGuard UDP port):

```json
{"event":"announce","info_hash":"0101010101010101010101010101010101010101","port":6881,"complete":false,"limit":20}
```

The response contains `interval` (seconds until the next announce), `seeders`,
`leechers`, and `peers`. Each peer has `public_key`, `port`, `complete`, and
`remaining_seconds`. Responses omit the requester and cap the peer list at 50.
Resolve each public key through `/v1/binding`, supply the binding to the userspace
client, and connect to its virtual IP and advertised application port. Membership
alone does not install a binding or establish a connection.

The hash is hexadecimal: 40 characters for v1, 64 for full v2. These are separate
namespaces. Hybrid-torrent mapping and wire-format truncated v2 hashes are not
implemented. Ports must be nonzero. Unknown request fields are rejected.

Use `{"event":"stopped","info_hash":"..."}` to remove your membership or
`{"event":"scrape","info_hash":"..."}` for live counts without announcing.
Both require authentication. A stop is idempotent. Completion is self-reported.

Membership expires at the earlier of 300 seconds or the authenticated overlay
lease deadline. Refreshing the overlay lease does not refresh swarm membership;
announce again. Expired membership never appears in reads and is reclaimed on
subsequent tracker requests. State is lost on server restart.

Defaults bound state to 10,000 swarms, 100,000 total memberships and 1,000 peers
per swarm. Capacity rejection returns HTTP 503; invalid hashes return 400 and
invalid credentials return 401. Invalid JSON field values return Axum's 422.
The library accepts configurable limits; server defaults are currently fixed.
Cleanup scans stored state and selection has no fairness guarantee. No throughput
qualification is claimed.

This JSON overlay protocol is not a native HTTP/UDP BitTorrent tracker endpoint.
Existing torrent clients require an adapter. There is no metadata hosting,
indexing, persistence, DHT/PEX integration or transfer accounting.
