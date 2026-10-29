//! Poll-driven, interface-free TCP/UDP over the existing WireGuard peer manager.
//! The embedding runtime owns UDP I/O and authenticated tracker control.
use crate::{
    CandidatePeer,
    peer_manager::{Effect, MTU, Manager, overlay},
};
use boringtun::x25519::StaticSecret;
pub use smoltcp::socket::tcp::State as TcpState;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, udp},
    time::Instant as StackInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Instant,
};
const MAX_SOCKETS: usize = 64;
const BUFFER: usize = 16 * 1024;
const PACKETS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TcpId(u128);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UdpId(u128);
#[derive(Default)]
struct Packets {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}
struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);
impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}
impl Device for Packets {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: StackInstant) -> Option<(Rx, Tx<'_>)> {
        if self.tx.len() >= PACKETS {
            return None;
        }
        self.rx.pop_front().map(|p| (Rx(p), Tx(&mut self.tx)))
    }
    fn transmit(&mut self, _: StackInstant) -> Option<Tx<'_>> {
        (self.tx.len() < PACKETS).then_some(Tx(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}
fn error(kind: io::ErrorKind, message: &str) -> io::Error {
    io::Error::new(kind, message)
}
fn endpoint(addr: SocketAddrV4) -> io::Result<IpEndpoint> {
    if !overlay(*addr.ip()) || addr.port() == 0 {
        return Err(error(
            io::ErrorKind::InvalidInput,
            "overlay address and nonzero port required",
        ));
    }
    Ok(IpEndpoint::new(IpAddress::Ipv4(*addr.ip()), addr.port()))
}

/// A single owner TCP/IP stack. No OS interface, routes, hidden tasks or locks.
/// Bindings must come from authenticated tracker control, never untrusted packets.
pub struct Network {
    manager: Manager,
    interface: Interface,
    packets: Packets,
    sockets: SocketSet<'static>,
    tcp: HashMap<TcpId, SocketHandle>,
    udp: HashMap<UdpId, SocketHandle>,
    next: u64,
    namespace: u64,
    listeners: HashMap<TcpId, u16>,
    local: Ipv4Addr,
    started: Instant,
    last: Instant,
    lease: Instant,
    pub dropped_packets: u64,
}
impl Network {
    pub fn new(secret: StaticSecret, local: Ipv4Addr, lease: Instant) -> io::Result<Self> {
        let now = Instant::now();
        if !overlay(local) || lease <= now {
            return Err(error(
                io::ErrorKind::InvalidInput,
                "valid overlay address and live lease required",
            ));
        }
        let mut packets = Packets::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut interface = Interface::new(config, &mut packets, StackInstant::ZERO);
        interface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(IpAddress::Ipv4(local), 16)).unwrap();
        });
        Ok(Self {
            manager: Manager::new(secret, local),
            interface,
            packets,
            sockets: SocketSet::new(vec![]),
            tcp: HashMap::new(),
            udp: HashMap::new(),
            next: 0,
            namespace: rand::random(),
            listeners: HashMap::new(),
            local,
            started: now,
            last: now,
            lease,
            dropped_packets: 0,
        })
    }
    fn live(&self) -> io::Result<()> {
        if self.lease <= self.last.max(Instant::now()) {
            Err(error(
                io::ErrorKind::PermissionDenied,
                "local registration expired; create a new network",
            ))
        } else {
            Ok(())
        }
    }
    /// Refresh only an unexpired local registration. Expiry cannot resurrect sockets.
    pub fn renew(&mut self, lease: Instant) -> io::Result<()> {
        self.live()?;
        if lease <= self.last.max(Instant::now()) {
            return Err(error(io::ErrorKind::InvalidInput, "expired lease"));
        }
        self.lease = lease;
        Ok(())
    }
    fn room(&self) -> io::Result<()> {
        self.live()?;
        if self.tcp.len() + self.udp.len() >= MAX_SOCKETS {
            Err(error(io::ErrorKind::OutOfMemory, "socket limit reached"))
        } else {
            Ok(())
        }
    }
    fn tcp_socket() -> tcp::Socket<'static> {
        let mut s = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; BUFFER]),
            tcp::SocketBuffer::new(vec![0; BUFFER]),
        );
        s.set_timeout(Some(smoltcp::time::Duration::from_secs(30)));
        s
    }
    fn add_tcp(&mut self, socket: tcp::Socket<'static>) -> TcpId {
        self.next += 1;
        let id = TcpId(((self.namespace as u128) << 64) | self.next as u128);
        self.tcp.insert(id, self.sockets.add(socket));
        id
    }
    fn port_free(&self, port: u16, tcp: bool) -> io::Result<()> {
        if port == 0 {
            return Err(error(
                io::ErrorKind::InvalidInput,
                "explicit nonzero local port required",
            ));
        }
        let used = if tcp {
            self.listeners.values().any(|p| *p == port)
                || self.tcp.values().any(|h| {
                    self.sockets
                        .get::<tcp::Socket>(*h)
                        .local_endpoint()
                        .is_some_and(|ep| ep.port == port)
                })
        } else {
            self.udp
                .values()
                .any(|h| self.sockets.get::<udp::Socket>(*h).endpoint().port == port)
        };
        if used {
            Err(error(io::ErrorKind::AddrInUse, "local port already in use"))
        } else {
            Ok(())
        }
    }
    /// Starts a nonblocking connection. Poll until `tcp_state` is Established.
    pub fn connect_tcp(&mut self, remote: SocketAddrV4, local_port: u16) -> io::Result<TcpId> {
        self.room()?;
        self.port_free(local_port, true)?;
        let remote = endpoint(remote)?;
        if remote.addr == IpAddress::Ipv4(self.local) {
            return Err(error(
                io::ErrorKind::InvalidInput,
                "self connection unsupported",
            ));
        }
        let mut socket = Self::tcp_socket();
        socket
            .connect(self.interface.context(), remote, (self.local, local_port))
            .map_err(|_| error(io::ErrorKind::InvalidInput, "invalid TCP endpoint"))?;
        Ok(self.add_tcp(socket))
    }
    /// Listen with one pending connection. Call `accept_tcp` promptly to replenish it.
    pub fn listen_tcp(&mut self, port: u16) -> io::Result<TcpId> {
        self.room()?;
        self.port_free(port, true)?;
        let mut s = Self::tcp_socket();
        s.listen((self.local, port))
            .map_err(|_| error(io::ErrorKind::InvalidInput, "invalid listen endpoint"))?;
        let id = self.add_tcp(s);
        self.listeners.insert(id, port);
        Ok(id)
    }
    /// Accept an established stream and replenish this listener. WouldBlock until ready.
    /// Failed pending handshakes are re-armed in place, preserving this ID and port.
    pub fn accept_tcp(&mut self, id: TcpId) -> io::Result<(TcpId, SocketAddrV4)> {
        self.live()?;
        let port = *self
            .listeners
            .get(&id)
            .ok_or_else(|| error(io::ErrorKind::InvalidInput, "not a TCP listener"))?;
        let local = self.local;
        let socket = self.tcp_mut(id)?;
        if socket.state() == tcp::State::Closed {
            // SYN-ACK timeout or a reset before accept can close a passive socket.
            // Reusing it needs no extra slot, even when the socket table is full.
            socket
                .listen((local, port))
                .map_err(|_| error(io::ErrorKind::InvalidInput, "could not re-arm TCP listener"))?;
            return Err(error(io::ErrorKind::WouldBlock, "no pending connection"));
        }
        if !matches!(
            socket.state(),
            tcp::State::Established | tcp::State::CloseWait
        ) {
            return Err(error(io::ErrorKind::WouldBlock, "no pending connection"));
        }
        let remote = socket
            .remote_endpoint()
            .ok_or_else(|| error(io::ErrorKind::NotConnected, "missing remote endpoint"))?;
        let IpAddress::Ipv4(ip) = remote.addr;
        self.room()?;
        let mut replacement = Self::tcp_socket();
        replacement
            .listen((self.local, port))
            .map_err(|_| error(io::ErrorKind::InvalidInput, "invalid listen endpoint"))?;
        let old = self.tcp.insert(id, self.sockets.add(replacement)).unwrap();
        self.next += 1;
        let accepted = TcpId(((self.namespace as u128) << 64) | self.next as u128);
        self.tcp.insert(accepted, old);
        Ok((accepted, SocketAddrV4::new(ip, remote.port)))
    }
    fn tcp_mut(&mut self, id: TcpId) -> io::Result<&mut tcp::Socket<'static>> {
        self.live()?;
        let h = *self
            .tcp
            .get(&id)
            .ok_or_else(|| error(io::ErrorKind::NotFound, "unknown TCP socket"))?;
        Ok(self.sockets.get_mut(h))
    }
    pub fn tcp_state(&mut self, id: TcpId) -> io::Result<TcpState> {
        Ok(self.tcp_mut(id)?.state())
    }
    pub fn write_tcp(&mut self, id: TcpId, data: &[u8]) -> io::Result<usize> {
        let s = self.tcp_mut(id)?;
        if !s.may_send() {
            return Err(error(io::ErrorKind::NotConnected, "TCP not connected"));
        }
        if data.is_empty() {
            return Ok(0);
        }
        if !s.can_send() {
            return Err(error(io::ErrorKind::WouldBlock, "TCP send buffer full"));
        }
        s.send_slice(data)
            .map_err(|_| error(io::ErrorKind::NotConnected, "TCP send closed"))
    }
    pub fn read_tcp(&mut self, id: TcpId, data: &mut [u8]) -> io::Result<usize> {
        let s = self.tcp_mut(id)?;
        if data.is_empty() {
            return Ok(0);
        }
        if s.can_recv() {
            return s
                .recv_slice(data)
                .map_err(|_| error(io::ErrorKind::ConnectionReset, "TCP receive closed"));
        }
        if matches!(
            s.state(),
            tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived
        ) || s.may_recv()
        {
            return Err(error(io::ErrorKind::WouldBlock, "no TCP data"));
        }
        Ok(0)
    }
    /// Half-close the send side; continue polling and reading for graceful shutdown.
    pub fn shutdown_tcp(&mut self, id: TcpId) -> io::Result<()> {
        self.tcp_mut(id)?.close();
        Ok(())
    }
    pub fn remove_tcp(&mut self, id: TcpId) -> io::Result<()> {
        self.listeners.remove(&id);
        let h = self
            .tcp
            .remove(&id)
            .ok_or_else(|| error(io::ErrorKind::NotFound, "unknown TCP socket"))?;
        self.sockets.remove(h);
        Ok(())
    }
    pub fn bind_udp(&mut self, port: u16) -> io::Result<UdpId> {
        self.room()?;
        self.port_free(port, false)?;
        let buffer =
            || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; BUFFER]);
        let mut s = udp::Socket::new(buffer(), buffer());
        s.bind((self.local, port))
            .map_err(|_| error(io::ErrorKind::InvalidInput, "invalid UDP endpoint"))?;
        self.next += 1;
        let id = UdpId(((self.namespace as u128) << 64) | self.next as u128);
        self.udp.insert(id, self.sockets.add(s));
        Ok(id)
    }
    fn udp_mut(&mut self, id: UdpId) -> io::Result<&mut udp::Socket<'static>> {
        self.live()?;
        let h = *self
            .udp
            .get(&id)
            .ok_or_else(|| error(io::ErrorKind::NotFound, "unknown UDP socket"))?;
        Ok(self.sockets.get_mut(h))
    }
    pub fn send_udp(&mut self, id: UdpId, remote: SocketAddrV4, data: &[u8]) -> io::Result<()> {
        let remote = endpoint(remote)?;
        if data.len() > MTU - 28 {
            return Err(error(
                io::ErrorKind::InvalidInput,
                "UDP payload exceeds tunnel MTU",
            ));
        }
        self.udp_mut(id)?
            .send_slice(data, remote)
            .map_err(|_| error(io::ErrorKind::WouldBlock, "UDP send buffer full"))
    }
    /// Receives one whole datagram. A short output buffer consumes that datagram and errors.
    pub fn recv_udp(&mut self, id: UdpId, data: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        let s = self.udp_mut(id)?;
        if !s.can_recv() {
            return Err(error(io::ErrorKind::WouldBlock, "no UDP datagram"));
        }
        let (n, meta) = s
            .recv_slice(data)
            .map_err(|_| error(io::ErrorKind::InvalidInput, "UDP receive buffer too short"))?;
        let IpAddress::Ipv4(ip) = meta.endpoint.addr;
        Ok((n, SocketAddrV4::new(ip, meta.endpoint.port)))
    }
    pub fn remove_udp(&mut self, id: UdpId) -> io::Result<()> {
        let h = self
            .udp
            .remove(&id)
            .ok_or_else(|| error(io::ErrorKind::NotFound, "unknown UDP socket"))?;
        self.sockets.remove(h);
        Ok(())
    }
    /// Install only a tracker-authenticated binding with its conservative deadline.
    pub fn install_peer(
        &mut self,
        binding: CandidatePeer,
        until: Instant,
        now: Instant,
    ) -> io::Result<Vec<Effect>> {
        self.last = self.last.max(now);
        self.live()?;
        let effects = self
            .manager
            .install(binding, until.min(self.lease), self.last)
            .map_err(|e| error(io::ErrorKind::InvalidInput, e))?;
        Ok(self.effects(effects))
    }
    fn effects(&mut self, effects: Vec<Effect>) -> Vec<Effect> {
        let mut out = Vec::new();
        for effect in effects {
            match effect {
                Effect::Deliver(p) => {
                    if self.packets.rx.len() < PACKETS {
                        self.packets.rx.push_back(p);
                    } else {
                        self.dropped_packets += 1;
                    }
                }
                Effect::Network { to: None, .. } => {} // No relay or host-network plaintext fallback.
                other => out.push(other),
            }
        }
        out
    }
    /// Feed a UDP datagram from the WireGuard socket. Plaintext never enters the stack.
    pub fn receive(
        &mut self,
        data: &[u8],
        source: SocketAddr,
        now: Instant,
    ) -> io::Result<Vec<Effect>> {
        self.last = self.last.max(now);
        self.live()?;
        let effects = self.manager.receive(data, Some(source), None, self.last);
        Ok(self.effects(effects))
    }
    /// Drive TCP/IP and WireGuard timers, then dispatch returned Network/Resolve actions.
    /// Call regularly (e.g. every 10 ms), after input, and after application writes.
    pub fn poll(&mut self, now: Instant) -> io::Result<Vec<Effect>> {
        self.last = self.last.max(now);
        self.live()?;
        let timestamp = StackInstant::from_millis(
            self.last
                .duration_since(self.started)
                .as_millis()
                .min(i64::MAX as u128) as i64,
        );
        self.interface
            .poll(timestamp, &mut self.packets, &mut self.sockets);
        let effects = self.manager.tick(self.last);
        let mut out = self.effects(effects);
        while let Some(packet) = self.packets.tx.pop_front() {
            let effects = self.manager.send(packet, self.last);
            out.extend(self.effects(effects));
        }
        Ok(out)
    }
}
