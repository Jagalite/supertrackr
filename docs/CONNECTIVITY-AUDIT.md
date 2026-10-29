# Connectivity audit against Tailscale

2026-10-29. **Not a parity or production-qualification claim.** Reference source:
Tailscale commit `f7c1b8e52600c1926623b29c91972a5ea1364d2f`, fetched from the official
repository. This review covers direct connectivity while preserving both of our
introduction choices and the user's decision to exclude data relay.

## Reference mechanisms and findings

Tailscale's [endpoint implementation](https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/wgengine/magicsock/endpoint.go)
correlates Pongs to pending transaction IDs, records latency, expires path trust,
and scores alternatives with preferences and hysteresis. Its policy also considers
MTU and address characteristics. Our previous engine selected the last authenticated
packet's source, and generated a new nonce in replies instead of echoing the request.
That provided no correlated round-trip measurement.

**Implemented:** probe replies now echo their nonce inside authenticated WireGuard
packets. A path is selectable only after a matching nonce, endpoint and two-second
response window. Each challenge is consumed once. Path state is capped at 16
endpoints per peer, with eight advertised candidates and bounded learned endpoints.
Measurements expire after five seconds; learned endpoints age out after ten seconds.
An exponentially smoothed RTT and 25% improvement threshold stabilize selection.
Withdrawn advertised paths lose their measurements and challenges. Authenticated
incoming data can teach an endpoint but cannot by itself select that path.
This is our own simpler policy, not Tailscale's full path-scoring or MTU algorithm.

Tailscale's [netcheck](https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/net/netcheck/netcheck.go)
collects IPv4/IPv6 reachability, mapped-address observations, destination-dependent
mapping evidence and router-mapping availability. Our STUN parser already checks
transaction/source/length, supports IPv4/IPv6 responses, and expires observations.
**Implemented:** compare fresh same-family mappings from distinct server IPs and
report `mapping_varies_by_destination` as true, false, or unknown. Equal samples
only describe those sampled destinations. One STUN server cannot classify this;
the integration simulator's single-server runs correctly report unknown.
We still lack netcheck's broader probe scheduling and network diagnostics.

Tailscale's [disco protocol](https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/disco/disco.go)
uses encrypted discovery messages and a CallMeMaybe request for reciprocal
connection attempts. Our authenticated HTTPS rendezvous provides reciprocal endpoint
hints, optionally carrying the server-owned key/IP binding. Direct introductions
instead use a bounded plaintext return-address challenge followed by tracker
verification and WireGuard authentication. That bootstrap exposes public keys and
an authority identifier; it does not have disco's metadata confidentiality. No
homegrown encryption was added to disguise that difference. Our authenticated
path probes run inside WireGuard, so their protection begins after its handshake.

Tailscale's [portmapper](https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/net/portmapper/portmapper.go)
supports PCP, NAT-PMP and UPnP with mapping lifecycle management. **Implemented:**
the companion now uses our existing optional Rust portmapper adapter, including
renewal requests, publication/withdrawal of mapping hints and best-effort shutdown.
It requires the `router-mapping` build feature, `--portmap`, `--allow-network`, and
a non-loopback IPv4 bind. Disabled behavior is tested; real router acquisition,
renewal, and removal have not been exercised.

Tailscale's [magicsock](https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/wgengine/magicsock/magicsock.go)
maintains separate IPv4/IPv6 sockets and handles network changes and socket rebinding.
Our companion has one concrete bind and periodically refreshed endpoint metadata.
It recovered from simulated public NAT mapping changes, but this does not establish
OS interface/address-change handling or Wi-Fi-to-cellular handoff. Those remain gaps.

## Executed evidence

47 Rust tests passed, including nonce/source/timeout/replay rejection, path expiry,
latency hysteresis, bounded path state, STUN observation classification, identity
and inner-address checks, and both introduction modes. All-target/all-feature
Clippy passed after a style-only correction.

The expanded userspace NAT/filter harness uses real companion processes, real
WireGuard encryption, and synthetic inner IP packets. Its private-address
advertisement filter prevents accidental direct loopback bypass.

- Mixed introduction preferences completed all 12 directed protocol checks and
  validated encrypted probe replies. Delivery recovered after a three-second
  peer-UDP outage and after all simulated public mappings were replaced.
- Endpoint-dependent mappings with endpoint-dependent filtering remained blocked:
  no WireGuard forwarding, introduction completion or application delivery.
- Blocked peer UDP remained blocked despite successful STUN and rendezvous.
- Legacy key-introduction/event/relay endpoints were rejected by the test proxy.

These negative outcomes are expected without relay. The hard-NAT model is one
specific combination, not a claim that every destination-dependent NAT is impossible.
The outage/rebinding run is not an OS network-change test. The TCP-shaped payloads
are not real TCP socket connections, and counters are not throughput qualification.
Receipts: `bench/results/tailscale-audit-20261029/`.

## Remaining acceptance gates

No-relay operation cannot match Tailscale's overall availability when direct UDP
is impossible. Within direct connectivity, further work includes dual-stack socket
racing, automatic local-interface changes, adaptive idle probing, packet-size/path
MTU discovery, stronger pre-handshake abuse qualification, scalable packet demux,
and replacing 100 ms HTTP polling before high-population qualification. Router
mapping, real LAN/WAN/CGNAT combinations, mobility, and privileged macOS utun
TCP/UDP application tests still need runtime evidence. Direct-mode bootstrap
confidentiality is an explicit security difference requiring a separate reviewed
protocol decision. Its strict reply-source matching can also constrain which NAT
behaviors work before WireGuard authentication; loosening that without an
authenticated discovery protocol would not establish equivalent security. Open-source reference access is useful evidence, not proof
that this implementation has equivalent reliability, privacy, or performance.
