# Userspace connection API

`supertrackr::userspace::Network` provides IPv4 TCP streams/listeners and UDP
sockets over the existing WireGuard peer manager. It uses smoltcp 0.14 for TCP/IP.
No virtual interface, host route, administrator permission, or kernel TCP socket
is needed for the inner connection. The outer WireGuard datagrams still use UDP.

Applications can use `async_userspace::Client`, which puts the engine and an outer
Tokio UDP socket in one background task. TCP streams implement Tokio
`AsyncRead`/`AsyncWrite`; applications await connection and socket operations.
The lower-level `userspace::Network` remains available for custom runtimes.
Existing unmodified applications still use the companion's interface. Neither
API is a SOCKS proxy.

## Tokio application API

```rust,no_run
use tokio::io::{AsyncReadExt, AsyncWriteExt};
// After enrollment, create Network with its assigned address and lease, then:
let (client, mut resolutions) = Client::spawn(network, wireguard_udp_socket);
// Trusted control code installs verified peers and handles resolution requests.
let mut stream = client.connect("10.203.0.2:8080".parse()?).await?;
stream.write_all(b"hello").await?;
stream.shutdown().await?; // half-close; receiving can continue
let mut response = Vec::new();
stream.read_to_end(&mut response).await?;
```

`Client::spawn` requires an active Tokio runtime. It takes ownership of the supplied
UDP socket. `connect(remote)` assigns a free local ephemeral port and waits up to
10 seconds; `connect_with_timeout` accepts a timeout greater than zero and at most
300 seconds. `listen_tcp(port).await` returns an async listener; `accept().await`
returns a stream and its peer address. `bind_udp(port).await` returns an async
socket with `send_to(data, remote).await` and `recv_from(buffer).await`. UDP receive
and listener accept require mutable access to their respective handle.

The owner task polls internally every 10 ms and on network/control activity.
Applications do not poll. It owns all Network mutations; Tokio channels and Duplex
buffers provide synchronization at the API boundary. It does not make the whole
wrapper lock-free. Each stream has a bounded 16 KiB duplex buffer per direction
and at most 8 KiB of staged bridging data per direction, in addition to stack
buffers. UDP queues hold 16 datagrams per direction. The command and resolution
queues hold 64 items; each listener queues one accepted stream. Full accept or
application buffers do not block the owner task. Resolution events are best-effort
when their queue is full; pending connections can retry resolution or time out.
The encrypted output queue holds at most 2,048 packets; exhausting it terminates
the runtime with an error rather than growing memory indefinitely. Unsupported
outer address families and per-path send failures discard that encrypted packet
and let other paths/retransmissions proceed; `client.stats().await` reports path
send errors and dropped resolution notifications.

Cancelling connect releases its pending socket. Cancelling UDP receive or listener
accept leaves the next item available. Async TCP reads and writes use Tokio duplex
semantics: partial writes are possible, and `write_all` is not cancellation-safe.
`flush` acknowledges local buffering, not remote delivery. `shutdown` half-closes
after queued writes drain. Dropping a delivered TCP stream lets its queued output
and FIN drain for up to 30 seconds; explicit runtime shutdown or lease expiry can
interrupt this. Dropped listeners and UDP sockets release their allocations on the
next owner pass. TCP and UDP handles keep the runtime alive even if the Client
handle is dropped. After the final handle drops, the task drains outstanding TCP
closes (bounded by that deadline), then releases its outer UDP socket.

`Client::shutdown().await` explicitly stops all sockets and returns after releasing
the transport; it is an abort, not a wait for delivery. The stop command remains
effective if the caller cancels after enqueueing it. Lease expiry, owner failure,
and explicit shutdown wake blocked operations with errors. Already buffered
plaintext is not returned after terminal failure is observed. Local renewal and
peer installation remain explicit async control operations; they do not contact
the tracker themselves. Existing stack limits and reset/EOF distinctions below
still apply.

The wrapper consumes WireGuard traffic on its transport socket. It does not yet
multiplex STUN or direct-introduction packets, or run tracker refresh, rendezvous
or port-mapping tasks. Use authenticated reciprocal bindings supplied by control
code; these features remain in the companion and the lower-level integration.

## Lower-level application operations

- `connect_tcp(remote, local_port)` starts a connection; use `tcp_state` to await
  `TcpState::Established`. Explicit nonzero local ports are required.
- `listen_tcp(port)` creates a listener with one pending connection.
  `accept_tcp(listener)` returns a stream ID and remote address, replenishing the
  listener. A closed pending connection is re-armed in place on the next accept
  attempt, even at full socket capacity. Accepting a live connection still requires
  one free slot; lack of capacity preserves its state and buffered data. Accept
  promptly; there is no multi-connection pending backlog.
- `write_tcp` supports partial writes; `read_tcp` supports partial reads.
  `WouldBlock` means drive the network and retry. Zero-byte reads with a nonempty
  buffer mean the receive side is closed; this version does not distinguish every
  reset/timeout reason from EOF. Writes before connection return `NotConnected`.
- `shutdown_tcp` closes the send side; continue polling/reading for half-close.
  `remove_tcp` releases the socket immediately; it does not perform graceful FIN
  exchange. Closed sockets keep their allocation until explicitly removed.
- `bind_udp`, `send_udp`, `recv_udp`, and `remove_udp` manage datagrams. A short
  receive buffer discards that datagram and returns `InvalidInput`.

IDs are opaque and scoped to their network instance. Removed IDs do not alias a
replacement socket. The prototype allows 64 total sockets, 16 KiB per socket per
direction, and 16 queued datagrams per UDP direction. Packet queues hold 64 packets.
Queue overflow on authenticated input increments `dropped_packets`. UDP payloads
are limited to 1,252 bytes (IPv4/UDP within the 1,280-byte tunnel MTU). TCP segments
larger streams automatically. IPv6, DNS, multicast, IP fragmentation, ephemeral
port allocation, and self-connections are not supported application features.
TCP has a 30-second timeout for setup or unacknowledged transmit data; a fully
idle established socket without keepalive can remain open.

## Runtime responsibilities

Create `Network` with the WireGuard secret, tracker-assigned overlay IPv4 address,
and a conservative local registration expiry. Feed each received outer UDP
packet to `receive(data, source, now)` using the actual sender address. Call `poll`
regularly (for example every 10 ms), after received traffic and after writes.
Dispatch actions returned by `poll`, `receive`, and `install_peer`:

- `Effect::Network { to: Some(endpoint), data, .. }`: send the encrypted datagram
  through the same outer UDP socket used for endpoint discovery and punching.
- `Effect::Resolve(ip)`: resolve/authorize this destination through trusted tracker
  control, arrange the reciprocal introduction, and install the validated binding.

The API consumes decrypted delivery actions internally. It emits no plaintext or
relay actions and has no host-network fallback. Only overlay destinations are
accepted. An unresolved destination triggers peer-manager resolution; packets are
briefly bounded/buffered there. TCP can retry, while UDP may be lost during setup.

`install_peer` is a trusted control-plane boundary: pass only a tracker-authenticated
binding, with a deadline conservatively calculated from the response lifetime.
It does not authenticate arbitrary caller-supplied metadata. Each receiver needs
the sender's authorized binding before WireGuard can admit it. Existing companion
introduction, STUN and rendezvous logic remain outside this stack; this API is not
a new automatic NAT traversal service.

Refresh tracker credentials and call `renew` before local lease expiry; refresh
peer bindings separately. Local expiry stops all socket I/O and cannot be undone
with `renew`; create a fresh Network after re-enrollment. On tracker restart or
identity/address reassignment, discard the old Network and its sockets. Never
reuse old TCP sessions across a new authority session or changed peer identity.

## Runnable example

Build through Kyoto, then execute:

```sh
python3 /path/to/kyoto/kyoto.py submit -- cargo build --example userspace_echo
# After the build succeeds:
target/debug/examples/userspace_echo
```

The example starts a loopback HTTP tracker, enrolls two fresh key holders with
proof of possession, publishes candidates, obtains assigned IPs and authenticated
peer bindings, then echoes TCP and UDP over real userspace WireGuard/UDP sockets using awaitable
streams and datagrams, without any application polling loop.
It is a short-lived local example; long-lived applications must add refresh and
control-plane recovery. No OS interface or routes are created.

The integration tests exercise a 64 KiB TCP stream with an intentionally dropped
encrypted data packet, half-close, listener reuse, UDP payload boundaries, socket
limits and stale/cross-instance handles, unknown-peer resolution, untrusted input,
and local lease expiry. Local transport tests are not Internet NAT or production
performance qualification.

Stack reference: https://docs.rs/smoltcp/0.14.0/smoltcp/
