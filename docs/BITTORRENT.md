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
Linked credentials count as one logical peer per application ID; a peer counts
as a seeder if any of its matching live memberships reports completion. At most
one credential per logical peer and application appears in the peer list.
Memberships themselves remain per credential. The optional `application_id` is a
40-character hexadecimal BitTorrent peer ID; omitting it retains legacy behavior.
Peers with expired published endpoints are omitted from the peer list; counts
still include live swarm memberships while their credential remains valid.
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

## Standard HTTP listener (in progress)

With the `bittorrent` feature, `--tracker-http-listen ADDRESS` explicitly
starts a separate plaintext HTTP listener for standard `/announce` and `/scrape`
requests. It uses the socket's observed source address, not forwarded IP
headers or client-supplied IP parameters. State is bounded and in memory, and
is separate from authenticated overlay swarm state. A UDP listener is under
development behind `--tracker-udp-listen ADDRESS` and shares ordinary swarm
state with HTTP. Neither listener has overlay peer discovery. Do not assume a published address or port is
reachable through a host firewall or NAT. The existing JSON overlay API remains
separate.

The listener integration test verifies that HTTP and UDP announces share swarm
membership, return peers across protocols, and reflect UDP stops in HTTP results.
An IPv6 loopback integration test verifies HTTP `peers6` encoding and confirms
that IPv6 UDP announces return IPv6 peers rather than IPv4 entries. This is not
evidence of public IPv6 reachability or IPv6 overlay peer transport.

An experimental companion adapter is enabled by `--tracker-bridge-listen`
with a loopback-only address. Configure the torrent client to use that local
`/announce` URL. The adapter uses the companion's authenticated overlay
identity; optionally `--tracker-upstream` points to an ordinary HTTP(S)
announce URL or a UDP tracker URL with an explicit port, and the adapter
combines Internet and overlay responses. Counts
from the two paths are added and can count a peer twice. If the upstream fails
or times out and no usable cached result is available, the adapter returns available overlay results with an upstream
unavailable warning; counts then cover only the overlay. Local applications
able to reach the listener can announce using the companion's identity, so do
not expose it beyond loopback. The adapter and standard listeners are in progress.
Scrape requests accept up to 32 hashes; duplicate hashes are queried once and
coordinator lookups run with bounded concurrency. A failed required coordinator
lookup fails the scrape rather than returning incomplete overlay counts.
In local checks, Transmission 4.1.3 announced a seed and leecher over both HTTP
and UDP; shared HTTP scrape reported both. Using the machine's LAN address, two
Transmission processes also transferred and verified a private torrent for each
protocol. A Transmission seeder and aria2 1.37.0 downloader also transferred a
private torrent using HTTP tracker discovery. That aria2 build reported UDP
tracker URLs unsupported, so it is not evidence for UDP compatibility.
Transmission rejects tracker-supplied loopback peers, so the equivalent
loopback-only transfer did not work. These checks do not establish cross-machine
NAT traversal or companion-interface interoperability.

With Transmission, aria2 and `mktorrent` available, the cross-client HTTP
check can be repeated using:

```sh
python3 scripts/check_tracker_aria2.py --transmission /path/to/transmission-cli --aria2 /path/to/aria2c
```

It temporarily binds the test tracker to the machine's LAN address and retains
the generated test files and logs in the printed temporary directory.

A separate local process check ran two Transmission 4.1.3 clients through two
companion tracker bridges and verified overlay plus upstream peers and scrape
counts. The companions used the unprivileged packet adapter; this verifies
discovery, not packet delivery through a native interface. With Transmission,
`mktorrent`, and server and companion binaries built with the `bittorrent`
feature, rerun it using:

```sh
python3 scripts/check_tracker_bridge_transmission.py --client /path/to/transmission-cli
```

Add `--upstream-protocol udp` to exercise the UDP upstream path. Both HTTP and
UDP upstream variants passed with Transmission 4.1.3 using the packet adapter;
they checked announces, scrape counts and returned peer addresses, not torrent
payload transfer through the native interface or cross-machine traversal.

For a separate native-interface UDP smoke check on macOS, an administrator can
run the following from the repository root (use the actual checkout path):

```sh
cd /path/to/supertrackr
sudo python3 scripts/check_native_companion_udp.py --bin-dir "$PWD/target/debug"
```

The script temporarily creates
an utun interface and overlay route, checks a UDP round trip to a packet-adapter
peer, and verifies route cleanup. It leaves root-owned logs and temporary keys
in the printed `/tmp` directory. On macOS, the check passed a host UDP round
trip through utun and WireGuard with a packet-adapter remote endpoint and
verified route cleanup. It does not validate TCP, a torrent client through
utun, or cross-machine NAT traversal.

The HTTP(S) upstream URL may include tracker-specific query credentials, which
are retained for both announce and scrape requests. UDP announces include the
configured path and query using BEP 41. BEP 15 has no corresponding scrape
extension, so UDP scrape is unavailable when the URL contains a query or a
nonstandard path that might carry credentials; the bridge returns overlay counts
with an upstream warning. UDP requests wait briefly for an immediate response,
then retry in the background for at most five minutes after acquiring a worker;
queued work is bounded, and stops have a separate worker. A recent successful
announce may be used while a refresh is pending. UDP scrape results are refreshed
on a request after 30 seconds and can be used as fallback for up to five minutes.
Loopback integration tests exercise UDP bridge announce and scrape, IPv6,
retry and stop handling. The Transmission check above also exercised UDP
upstream discovery through the packet adapter.
As with other command-line arguments, credentials may be
visible to local process inspection. The bridge removes client-supplied
IP address overrides and relies on the upstream tracker observing the actual
source address. An upstream tracker seeing that address does not guarantee the
client's advertised listening port is reachable through a firewall or NAT.
