# Companion exit modes

The interface companion supports three startup modes. Existing server, identity,
bind, and enrollment arguments still apply.

* `--exit-mode overlay-only` (default): only IPv4 overlay peers are reachable.
* `--exit-mode local`: ordinary IPv4/IPv6 TCP/UDP destinations use host sockets.
  Internet peers see this host's normal public address.
* `--exit-mode remote --exit-gateway 10.203.0.3 --exit-gateway-key <public-key>`:
  ordinary IPv4/IPv6 packets travel inside WireGuard to the pinned gateway.
  Internet peers see the gateway's address. Missing, expired or mismatched gateways
  never trigger local forwarding.

On the gateway, add `--serve-exit-for <client-public-key>` per allowed client
(maximum eight). Both peers must enroll with the same coordinator and publish
candidates. Keys must be lowercase hex. Restart to change configuration.
Configured gateway/client identities are proactively resolved and refreshed, so
inbound access does not depend on the torrent client first sending traffic.

Gateway requests/responses use protocol-252 IPv4 envelopes inside authenticated
WireGuard packets. Inner packets may be IPv4 or IPv6. IPv6 interface identities
use `fdcb::/96` with the authenticated overlay IPv4 address in the final 32 bits;
for example, `10.203.0.2` maps to `fdcb::acb:2`. The gateway checks inner source
ownership against the authenticated outer source and the explicit key allowlist.
Binding expiry removes the peer's flows and listeners.

## Explicit inbound mappings

Nothing listens for Internet peers by default. Local exit can expose a particular
TCP or UDP port and forward new connections/datagrams to an application bound to
the companion interface:

```text
--exit-mode local --exit-forward 'tcp,0.0.0.0:6881,6881'
--exit-mode local --exit-forward 'udp,[::]:6881,6881'
```

Repeat `--exit-forward` for both protocols or families. The fields are protocol,
host listening address/port and application port. Use a concrete host address to
limit exposure; wildcard addresses intentionally listen on host interfaces.
Use separate IPv4 and IPv6 mappings. Address-family translation is not supported.

For remote exit, configure listeners on the gateway:

```text
--serve-exit-for <client-key> \
--exit-forward-for '<client-key>,tcp,0.0.0.0:6881,6881' \
--exit-forward-for '<client-key>,udp,[::]:6881,6881'
```

The client uses `--exit-mode remote` with the gateway's key and overlay IP. A gateway
listener opens only after that client's live binding is installed. Unknown keys
cannot request listeners. Up to 16 mappings per client are allowed. Bind conflicts
are reported and that client's engine is not installed; already-opened listeners
in a failed setup are closed. Lease expiry closes active flows and listeners.
The application receives the Internet peer's source IP and port. Replies use the
same host-side connection/socket, preserving the external listening port for UDP.
Outbound-first UDP uses the first configured mapping matching its application port
and address family, so peers see the advertised listening port from the start.

These options open host sockets, not router ports. External reachability still
requires the host firewall and any upstream NAT/router to allow the configured
listening ports. The existing `--portmap` flag concerns the WireGuard outer UDP
port; it does not automatically publish application forwarding ports. The torrent
client must advertise the reachable exit address and listening port appropriately.

## Destination policy

Private, loopback, link-local and other non-public outbound destinations are
rejected by default. `--exit-allow-private` explicitly permits private/local
outbound services, including test echo servers. Replies on explicit inbound flows
are permitted even when the remote address is private. Multicast, unspecified,
IPv4 broadcast, IPv4-mapped IPv6, scoped/link-local IPv6 and overlay destinations
are excluded from exit forwarding. Regular IPv4 overlay traffic retains its
existing path. Native IPv6 overlay peer-to-peer transport is not implemented.

## Interface routing and validation boundary

Exit modes use MTU 1280, configure the derived IPv6 address on macOS utun, and
install interface-scoped IPv4 and IPv6 default routes. Host unscoped defaults are
unchanged, so host-side sockets and WireGuard outer UDP use normal routing. Scoped
routes are removed when the adapter drops. IPv6 exit envelopes can be 1304 bytes;
that narrowly scoped exception does not raise the ordinary overlay MTU.

Applications must bind to the interface; selecting only its source address can
behave differently. Native utun creation, scoped routes, IPv6 address assignment,
and real torrent-client binding require privileged macOS testing. Packet-adapter
and in-memory WireGuard tests bypass those facilities. No global packet filter or
kernel forwarding settings are changed. DNS settings are unchanged; resolver
requests sent outside the bound interface remain outside this path. No system-wide
kill switch prevents applications from unbinding after the companion exits.

## Transport bounds

TCP is proxied through smoltcp and host sockets with bounded buffering and
half-close handling. UDP uses connected outbound sockets or explicit mapped
listeners with per-peer flow state. IPv6 UDP checksums are mandatory and validated.
ICMP, fragmented IP packets, IPv4 options, IPv6 extension headers and jumbograms
are unsupported. This is not a general-purpose full-IP VPN exit.

Each source has at most 64 flows, 16 KiB TCP buffers, a 10-second outbound TCP
connect timeout and 120-second idle timeout. A gateway has at most eight active
client engines. Interface delivery uses a 128-packet queue serviced independently
from peer/control events. Packets expire after at most 20 ms, capped by their
authenticated lease deadline; overflow and expired packets are dropped. UDP payload
limits are 1252 bytes for IPv4 and 1232 for IPv6. Oversized datagrams are dropped,
not truncated. A native IPv6 route on the exit host is required to reach public
IPv6 destinations. No throughput or real-NAT qualification is implied.
