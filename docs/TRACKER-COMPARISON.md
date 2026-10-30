# Open-source tracker feature survey

Surveyed 2026-10-29 against the projects' public documentation. This is a
feature inventory, not a code audit, interoperability test, benchmark, or
commitment to implement every feature. Features may differ between releases and
build configurations.

## Projects

- [Aquatic](https://github.com/greatest-ape/aquatic): separate UDP, HTTP and
  WebTorrent tracker implementations, IPv4/IPv6, optional TLS for HTTP and
  WebSocket, hash allow/deny lists, Prometheus metrics, in-memory state, and
  UDP full-scrape exports. Its HTTP and WebSocket implementations have Linux
  requirements; UDP supports Unix-like systems.
- [Torrust Tracker](https://github.com/torrust/torrust-tracker): HTTP, UDP and
  TLS, IPv4/IPv6, private and whitelist modes, management API, database
  backends and metrics. Its README identifies WebTorrent as roadmap work.
- [Chihaya](https://github.com/chihaya/chihaya): HTTP/UDP, IPv4/IPv6,
  middleware hooks, Prometheus metrics, Redis-based high availability, and Helm
  deployment. Check release activity and version compatibility before adoption.
- [WebTorrent bittorrent-tracker](https://github.com/webtorrent/bittorrent-tracker):
  HTTP, UDP and WebTorrent tracker protocols, IPv4/IPv6, scrape, and both client
  and server implementations.
- [opentracker](https://erdgeist.org/arts/software/opentracker/): configurable
  hash allow/deny lists and optional features including full scrape; consult its
  [build options](https://www.erdgeist.org/gitweb/opentracker/tree/Makefile)
  for feature availability.

## Comparison with our overlay tracker

Our optional library and authenticated JSON endpoint provide bounded in-memory
swarm membership, announce/stop, single-hash live scrape counts, v1 and full v2
hash namespaces, and lease-bound peer expiry. Returned identities must be
resolved through the coordinator. See [BITTORRENT.md](BITTORRENT.md) for exact
semantics. This is an overlay-specific API, so ordinary clients cannot use it as
a standard tracker without an adapter.

| Capability | Our current state | Potential work |
| --- | --- | --- |
| Standard HTTP announce and scrape | Separate standard listener and companion bridge | Expand interoperability and native-interface validation. |
| UDP tracker protocol | BEP 15 listener and companion upstream bridge | Expand interoperability and network validation. |
| WebTorrent signaling | No | Separate WebSocket/WebRTC signaling adapter if browser clients matter. |
| IPv4/IPv6 tracker endpoints | Standard listeners support IPv4 and IPv6 | Validate public reachability and more client configurations. |
| Scrape | Overlay single-hash and standard multi-hash scrape | Full scrape needs explicit limits and access policy. |
| Access policies | Overlay identity authentication | Optional per-swarm authorization and hash allow/deny lists, keeping identity checks intact. |
| Persistence and high availability | In-memory, lost on restart | Decide which state and statistics warrant persistence; shared state requires lease and consistency design. |
| Operations | Fixed server tracker limits; library configuration | Configurable limits, metrics, health and management interfaces with bounded access. |
| Scale and selection | Bounded state; cleanup scans state; arbitrary peer selection | Measure realistic workloads, improve expiry and peer rotation, and validate resource limits. |
| Transfer accounting | No | Optional completion history or user accounting requires explicit semantics and trust policy. |

A tracker normally matches peers by info hash; hosting torrent files, search and
metadata indexing are separate responsibilities. None of the above requires
adding those to the generic coordinator.

## Suggested order

1. Validate torrent payload transfer through the native companion interface and
   exercise cross-machine connectivity and NAT traversal.
2. Expand interoperability tests and improve operational controls according to
   measured requirements. A public IP:port response does not establish a
   WireGuard binding or guarantee reachability.
3. Consider WebTorrent, persistence, full scrape and historical accounting only
   when needed; these add state and disclosure costs.

## Direction: peer identity and endpoints

Design for standard clients to discover both Internet and overlay peers when
reachable and authorized. Model a logical peer separately from its credentials,
transport endpoints and torrent-client identifiers. A peer may have multiple
WireGuard keys or future QUIC/DTLS credentials, with authenticated linking,
independent expiry and revocation. A BitTorrent peer ID is not proof of ownership.
Associate endpoints with their network scope, transport, port, credential and
reachability evidence; do not assume an advertised Internet port is reachable.
Select responses appropriate to the requester so Internet-only clients are not
sent inaccessible overlay addresses. Handle duplicate paths to the same peer.
Linked WireGuard credentials and companion discovery are implemented; future
transport credentials, comprehensive reachability selection and deduplication
remain design work.
