//! Bounded dual-stack TCP/UDP egress proxy for explicitly enabled companion exits.
//! This does not change host routes or enable kernel forwarding.
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant as Time,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, task::JoinHandle};
const MAX_FLOWS: usize = 64;
const BUFFER: usize = 16384;
pub const MTU: usize = 1280;
const PACKETS: usize = 128;
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
        let mut b = vec![0; len];
        let r = f(&mut b);
        self.0.push_back(b);
        r
    }
}
impl Device for Packets {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: Time) -> Option<(Rx, Tx<'_>)> {
        if self.tx.len() >= PACKETS {
            return None;
        }
        self.rx.pop_front().map(|p| (Rx(p), Tx(&mut self.tx)))
    }
    fn transmit(&mut self, _: Time) -> Option<Tx<'_>> {
        (self.tx.len() < PACKETS).then_some(Tx(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = MTU;
        c
    }
}
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct FlowKey {
    src: SocketAddr,
    dst: SocketAddr,
    protocol: u8,
}
enum Transport {
    Tcp {
        pending: Option<JoinHandle<io::Result<TcpStream>>>,
        stream: Option<TcpStream>,
        read_closed: bool,
        write_closed: bool,
    },
    Udp(std::net::UdpSocket),
    MappedUdp {
        socket: Arc<std::net::UdpSocket>,
        peer: SocketAddr,
    },
}
struct Flow {
    handle: Option<SocketHandle>,
    transport: Transport,
    touched: Instant,
}
impl Drop for Flow {
    fn drop(&mut self) {
        if let Transport::Tcp {
            pending: Some(task),
            ..
        } = &self.transport
        {
            task.abort();
        }
    }
}

/// Explicit listener configuration: `tcp,127.0.0.1:6881,6881` or `udp,[::]:6881,6881`.
#[derive(Clone, Debug)]
pub struct Forward {
    pub listen: SocketAddr,
    pub target_port: u16,
    pub tcp: bool,
}
impl std::str::FromStr for Forward {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split(',').collect();
        if parts.len() != 3 {
            return Err("expected tcp|udp,listen-address:port,target-port".into());
        }
        let tcp = match parts[0] {
            "tcp" => true,
            "udp" => false,
            _ => return Err("expected tcp or udp".into()),
        };
        let listen: SocketAddr = parts[1].parse().map_err(|_| "invalid listener address")?;
        let target_port = parts[2].parse().map_err(|_| "invalid target port")?;
        if listen.port() == 0
            || target_port == 0
            || listen.ip().is_multicast()
            || is_overlay(listen.ip())
            || matches!(listen,SocketAddr::V6(v) if v.scope_id()!=0||v.ip().to_ipv4_mapped().is_some())
        {
            return Err("nonzero ports and non-overlay listener required".into());
        }
        Ok(Self {
            listen,
            target_port,
            tcp,
        })
    }
}
enum ListenerSocket {
    Tcp(std::net::TcpListener),
    Udp(Arc<std::net::UdpSocket>),
}
struct Listener {
    socket: ListenerSocket,
    port: u16,
}
/// One owner per authorized source address; each has at most 64 flows.
pub struct Engine {
    source: Ipv4Addr,
    packets: Packets,
    interface: Interface,
    sockets: SocketSet<'static>,
    flows: HashMap<FlowKey, Flow>,
    start: Instant,
    allow_private: bool,
    listeners: Vec<Listener>,
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid exit packet")
}
/// Validate the entire IPv4 header. Fragmentation and options are unsupported.
pub fn addresses(p: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if p.len() < 20
        || p[0] != 0x45
        || usize::from(u16::from_be_bytes([p[2], p[3]])) != p.len()
        || p[6] & 0x3f != 0
        || p[7] != 0
        || checksum(&p[..20]) != 0
    {
        return None;
    }
    Some((
        Ipv4Addr::new(p[12], p[13], p[14], p[15]),
        Ipv4Addr::new(p[16], p[17], p[18], p[19]),
    ))
}
fn checksum(b: &[u8]) -> u16 {
    let mut s = 0u32;
    for c in b.chunks(2) {
        s += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while s > 65535 {
        s = (s & 65535) + (s >> 16);
    }
    !(s as u16)
}
fn public(ip: Ipv4Addr) -> bool {
    let a = ip.octets();
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_documentation()
        && a[0] != 0
        && a[0] < 224
        && !(a[0] == 100 && (64..=127).contains(&a[1]))
        && !(a[0] == 198 && (a[1] == 18 || a[1] == 19))
}
pub fn overlay_subnet(ip: Ipv4Addr) -> bool {
    ip.octets()[..2] == [10, 203]
}

/// Stable interface IPv6 identity tied to the authenticated overlay IPv4 address.
pub fn ipv6(ip: Ipv4Addr) -> Ipv6Addr {
    let b = ip.octets();
    Ipv6Addr::new(
        0xfdcb,
        0,
        0,
        0,
        0,
        0,
        u16::from_be_bytes([b[0], b[1]]),
        u16::from_be_bytes([b[2], b[3]]),
    )
}
pub fn owns(owner: Ipv4Addr, ip: IpAddr) -> bool {
    ip == IpAddr::V4(owner) || ip == IpAddr::V6(ipv6(owner))
}
pub fn is_overlay(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => overlay_subnet(v),
        IpAddr::V6(v) => v.octets()[..12] == ipv6(Ipv4Addr::UNSPECIFIED).octets()[..12],
    }
}
pub fn packet_addresses(p: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match p.first()? >> 4 {
        4 => addresses(p).map(|(a, b)| (a.into(), b.into())),
        6 => {
            if p.len() < 40 || p.len() != 40 + usize::from(u16::from_be_bytes([p[4], p[5]])) {
                return None;
            }
            Some((
                Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).ok()?).into(),
                Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).ok()?).into(),
            ))
        }
        _ => None,
    }
}
fn ip_header(p: &[u8]) -> usize {
    if p[0] >> 4 == 6 { 40 } else { 20 }
}
fn protocol(p: &[u8]) -> u8 {
    if p[0] >> 4 == 6 { p[6] } else { p[9] }
}
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => public(v),
        IpAddr::V6(v) => {
            let s = v.segments();
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] == 0xdb8 || s[1] < 0x200))
                && s[0] != 0x2002
        }
    }
}
fn unicast(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip,IpAddr::V4(v) if v.is_broadcast())
        && !matches!(ip,IpAddr::V6(v) if v.to_ipv4_mapped().is_some() || v.is_unicast_link_local())
}
fn pseudo(p: &[u8]) -> Vec<u8> {
    let h = ip_header(p);
    let n = p.len() - h;
    let mut out = vec![];
    if h == 20 {
        out.extend_from_slice(&p[12..20]);
        out.extend_from_slice(&[0, p[9]]);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.extend_from_slice(&p[8..40]);
        out.extend_from_slice(&(n as u32).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, p[6]]);
    }
    out.extend_from_slice(&p[h..]);
    out
}
impl Engine {
    pub fn new(source: Ipv4Addr, allow_private: bool) -> Self {
        let mut packets = Packets::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut interface = Interface::new(config, &mut packets, Time::ZERO);
        interface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(IpAddress::Ipv4(source), 32)).unwrap();
            ips.push(IpCidr::new(IpAddress::Ipv6(ipv6(source)), 128))
                .unwrap();
        });
        interface.set_any_ip(true);
        interface
            .routes_mut()
            .add_default_ipv4_route(source)
            .unwrap();
        interface
            .routes_mut()
            .add_default_ipv6_route(ipv6(source))
            .unwrap();
        Self {
            source,
            packets,
            interface,
            sockets: SocketSet::new(vec![]),
            flows: HashMap::new(),
            start: Instant::now(),
            allow_private,
            listeners: vec![],
        }
    }
    /// Opens only the requested host listener; dropping this engine closes it.
    pub fn add_forward(&mut self, config: &Forward) -> io::Result<SocketAddr> {
        if self.listeners.len() >= 16 || config.target_port == 0 {
            return Err(invalid());
        }
        let raw = socket2::Socket::new(
            socket2::Domain::for_address(config.listen),
            if config.tcp {
                socket2::Type::STREAM
            } else {
                socket2::Type::DGRAM
            },
            None,
        )?;
        if config.listen.is_ipv6() {
            raw.set_only_v6(true)?;
        }
        raw.set_nonblocking(true)?;
        raw.bind(&config.listen.into())?;
        let address = raw.local_addr()?.as_socket().ok_or_else(invalid)?;
        let socket = if config.tcp {
            raw.listen(64)?;
            ListenerSocket::Tcp(raw.into())
        } else {
            ListenerSocket::Udp(Arc::new(raw.into()))
        };
        self.listeners.push(Listener {
            socket,
            port: config.target_port,
        });
        Ok(address)
    }
    fn receive_inbound(&mut self, now: Instant) {
        for listener in &self.listeners {
            for _ in 0..16 {
                if self.packets.tx.len() >= PACKETS {
                    break;
                }
                match &listener.socket {
                    ListenerSocket::Tcp(listener_socket) => {
                        let Ok((os, peer)) = listener_socket.accept() else {
                            break;
                        };
                        if self.flows.len() >= MAX_FLOWS || !unicast(peer.ip()) {
                            continue;
                        }
                        let app = SocketAddr::new(
                            if peer.is_ipv4() {
                                self.source.into()
                            } else {
                                ipv6(self.source).into()
                            },
                            listener.port,
                        );
                        let key = FlowKey {
                            src: app,
                            dst: peer,
                            protocol: 6,
                        };
                        if self.flows.contains_key(&key) {
                            continue;
                        }
                        if os.set_nonblocking(true).is_err() {
                            continue;
                        }
                        let Ok(os) = TcpStream::from_std(os) else {
                            continue;
                        };
                        let mut s = tcp::Socket::new(
                            tcp::SocketBuffer::new(vec![0; BUFFER]),
                            tcp::SocketBuffer::new(vec![0; BUFFER]),
                        );
                        s.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));
                        if s.connect(
                            self.interface.context(),
                            IpEndpoint::new(app.ip().into(), app.port()),
                            IpEndpoint::new(peer.ip().into(), peer.port()),
                        )
                        .is_err()
                        {
                            continue;
                        }
                        self.flows.insert(
                            key,
                            Flow {
                                handle: Some(self.sockets.add(s)),
                                transport: Transport::Tcp {
                                    pending: None,
                                    stream: Some(os),
                                    read_closed: false,
                                    write_closed: false,
                                },
                                touched: now,
                            },
                        );
                    }
                    ListenerSocket::Udp(os) => {
                        let mut b = [0; 65536];
                        let Ok((n, peer)) = os.recv_from(&mut b) else {
                            break;
                        };
                        if !unicast(peer.ip()) || n > MTU - if peer.is_ipv4() { 28 } else { 48 } {
                            continue;
                        }
                        let app = SocketAddr::new(
                            if peer.is_ipv4() {
                                self.source.into()
                            } else {
                                ipv6(self.source).into()
                            },
                            listener.port,
                        );
                        let key = FlowKey {
                            src: app,
                            dst: peer,
                            protocol: 17,
                        };
                        if let Some(flow) = self.flows.get(&key) {
                            if !matches!(&flow.transport,Transport::MappedUdp{socket,..} if Arc::ptr_eq(socket,os))
                            {
                                continue;
                            }
                        } else {
                            if self.flows.len() >= MAX_FLOWS {
                                continue;
                            }
                            self.flows.insert(
                                key,
                                Flow {
                                    handle: None,
                                    transport: Transport::MappedUdp {
                                        socket: os.clone(),
                                        peer,
                                    },
                                    touched: now,
                                },
                            );
                        }
                        self.flows.get_mut(&key).unwrap().touched = now;
                        self.packets.tx.push_back(udp_packet(peer, app, &b[..n]));
                    }
                }
            }
        }
    }
    pub fn ingest(&mut self, p: Vec<u8>, now: Instant) -> io::Result<()> {
        let (src, dst) = packet_addresses(&p).ok_or_else(invalid)?;
        let h = ip_header(&p);
        let proto = protocol(&p);
        if !owns(self.source, src)
            || !unicast(dst)
            || is_overlay(dst)
            || p.len() > MTU
            || p.len() < h + 8
            || ![6, 17].contains(&proto)
        {
            return Err(invalid());
        }
        let key = FlowKey {
            src: SocketAddr::new(src, u16::from_be_bytes([p[h], p[h + 1]])),
            dst: SocketAddr::new(dst, u16::from_be_bytes([p[h + 2], p[h + 3]])),
            protocol: proto,
        };
        if key.src.port() == 0
            || key.dst.port() == 0
            || self.packets.rx.len() >= PACKETS
            || self.packets.tx.len() >= PACKETS
        {
            return Err(invalid());
        }
        let transport = &p[h..];
        if proto == 6 {
            if transport.len() < 20
                || transport[12] >> 4 < 5
                || usize::from(transport[12] >> 4) * 4 > transport.len()
                || checksum(&pseudo(&p)) != 0
            {
                return Err(invalid());
            }
        } else if usize::from(u16::from_be_bytes([transport[4], transport[5]])) != transport.len()
            || ((h == 40 || transport[6..8] != [0, 0]) && checksum(&pseudo(&p)) != 0)
            || (h == 40 && transport[6..8] == [0, 0])
        {
            return Err(invalid());
        }
        if !self.flows.contains_key(&key) && !self.allow_private && !public_ip(dst) {
            return Err(invalid());
        }
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= MAX_FLOWS {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "exit capacity"));
            }
            let (handle, transport) = if key.protocol == 6 {
                if p[h + 13] & 0x12 != 0x02 {
                    return Err(invalid());
                }
                let mut socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; BUFFER]),
                    tcp::SocketBuffer::new(vec![0; BUFFER]),
                );
                socket
                    .listen(IpEndpoint::new(dst.into(), key.dst.port()))
                    .map_err(|_| invalid())?;
                socket.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));
                let target = key.dst;
                let pending = tokio::spawn(async move {
                    tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(target))
                        .await
                        .map_err(io::Error::other)?
                });
                (
                    Some(self.sockets.add(socket)),
                    Transport::Tcp {
                        pending: Some(pending),
                        stream: None,
                        read_closed: false,
                        write_closed: false,
                    },
                )
            } else if let Some(socket) = self.listeners.iter().find_map(|listener| {
                if listener.port != key.src.port() {
                    return None;
                }
                match &listener.socket {
                    ListenerSocket::Udp(socket)
                        if socket
                            .local_addr()
                            .is_ok_and(|addr| addr.is_ipv4() == key.src.is_ipv4()) =>
                    {
                        Some(socket.clone())
                    }
                    _ => None,
                }
            }) {
                (
                    None,
                    Transport::MappedUdp {
                        socket,
                        peer: key.dst,
                    },
                )
            } else {
                let os =
                    std::net::UdpSocket::bind(if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
                os.set_nonblocking(true)?;
                os.connect(key.dst)?;
                (None, Transport::Udp(os))
            };
            self.flows.insert(
                key,
                Flow {
                    handle,
                    transport,
                    touched: now,
                },
            );
        }
        self.flows.get_mut(&key).unwrap().touched = now;
        match &self.flows[&key].transport {
            Transport::Udp(os) => {
                os.send(&p[h + 8..])?;
            }
            Transport::MappedUdp { socket, peer } => {
                socket.send_to(&p[h + 8..], peer)?;
            }
            Transport::Tcp { .. } => {
                self.packets.rx.push_back(p);
                self.interface.poll(
                    Time::from_millis(now.saturating_duration_since(self.start).as_millis() as i64),
                    &mut self.packets,
                    &mut self.sockets,
                );
            }
        }
        Ok(())
    }
    pub async fn poll(&mut self, now: Instant) -> Vec<Vec<u8>> {
        self.receive_inbound(now);
        let time = Time::from_millis(
            now.saturating_duration_since(self.start)
                .as_millis()
                .min(i64::MAX as u128) as i64,
        );
        self.interface
            .poll(time, &mut self.packets, &mut self.sockets);
        let mut remove = vec![];
        for (key, flow) in &mut self.flows {
            if now.saturating_duration_since(flow.touched) > Duration::from_secs(120) {
                remove.push(*key);
                continue;
            }
            match &mut flow.transport {
                Transport::Tcp {
                    pending,
                    stream,
                    read_closed,
                    write_closed,
                } => {
                    let s = self.sockets.get_mut::<tcp::Socket>(flow.handle.unwrap());
                    if pending.as_ref().is_some_and(|p| p.is_finished()) {
                        match pending.take().unwrap().await {
                            Ok(Ok(os)) => *stream = Some(os),
                            _ => {
                                s.abort();
                                remove.push(*key);
                                continue;
                            }
                        }
                    }
                    if s.state() == tcp::State::Closed {
                        remove.push(*key);
                        continue;
                    }
                    if matches!(
                        s.state(),
                        tcp::State::Listen | tcp::State::SynReceived | tcp::State::SynSent
                    ) {
                        continue;
                    }
                    if let Some(os) = stream {
                        if s.can_recv() {
                            let result = s.recv(|b| match os.try_write(b) {
                                Ok(n) => (n, Ok(n)),
                                Err(e) => (0, Err(e)),
                            });
                            if let Ok(Err(e)) = result
                                && e.kind() != io::ErrorKind::WouldBlock
                            {
                                s.abort();
                                remove.push(*key);
                                continue;
                            }
                        }
                        if !s.may_recv() && !s.can_recv() && !*write_closed {
                            // Preserve TCP half-close.
                            use tokio::io::AsyncWriteExt;
                            if os.shutdown().await.is_err() {
                                s.abort();
                                remove.push(*key);
                                continue;
                            }
                            *write_closed = true;
                        }
                        if s.can_send() && !*read_closed {
                            let mut b = [0; BUFFER];
                            let space = s.send_capacity() - s.send_queue();
                            match os.try_read(&mut b[..space.min(BUFFER)]) {
                                Ok(0) => {
                                    *read_closed = true;
                                    s.close();
                                }
                                Ok(n) => {
                                    let _ = s.send_slice(&b[..n]);
                                    flow.touched = now;
                                }
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                                Err(_) => {
                                    s.abort();
                                    remove.push(*key);
                                }
                            }
                        }
                    }
                }
                Transport::MappedUdp { .. } => {}
                Transport::Udp(os) => {
                    for _ in 0..16 {
                        if self.packets.tx.len() >= PACKETS {
                            break;
                        }
                        let mut b = [0; 65536];
                        match os.recv(&mut b) {
                            Ok(n) if n <= MTU - if key.dst.is_ipv4() { 28 } else { 48 } => {
                                self.packets
                                    .tx
                                    .push_back(udp_packet(key.dst, key.src, &b[..n]));
                                flow.touched = now;
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                }
            }
        }
        self.interface
            .poll(time, &mut self.packets, &mut self.sockets);
        for key in remove {
            if let Some(flow) = self.flows.remove(&key)
                && let Some(handle) = flow.handle
            {
                self.sockets.remove(handle);
            }
        }
        self.packets.tx.drain(..).collect()
    }
}
/// Exit envelopes remain ordinary authenticated overlay packets to the peer manager.
/// Protocol 252 is reserved by the companion; request/response directions are explicit.
pub fn wrap(src: Ipv4Addr, dst: Ipv4Addr, response: bool, inner: &[u8]) -> Option<Vec<u8>> {
    if inner.len() > MTU || packet_addresses(inner).is_none() {
        return None;
    }
    let mut p = vec![0; 24 + inner.len()];
    p[0] = 0x45;
    let len = p.len() as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p[8] = 64;
    p[9] = 252;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..23].copy_from_slice(b"EX1");
    p[23] = u8::from(response);
    p[24..].copy_from_slice(inner);
    let sum = checksum(&p[..20]);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    Some(p)
}
pub fn unwrap(p: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, bool, Vec<u8>)> {
    let (src, dst) = addresses(p)?;
    if p.len() < 44 || p[9] != 252 || &p[20..23] != b"EX1" || p[23] > 1 || p.len() > MTU + 24 {
        return None;
    }
    packet_addresses(&p[24..])?;
    Some((src, dst, p[23] == 1, p[24..].to_vec()))
}

fn udp_packet(src: impl Into<SocketAddr>, dst: impl Into<SocketAddr>, data: &[u8]) -> Vec<u8> {
    let src = src.into();
    let dst = dst.into();
    let h = if src.is_ipv4() { 20 } else { 40 };
    let mut p = vec![0; h + 8 + data.len()];
    let n = p.len() as u16;
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            p[0] = 0x45;
            p[2..4].copy_from_slice(&n.to_be_bytes());
            p[8] = 64;
            p[9] = 17;
            p[12..16].copy_from_slice(&a.octets());
            p[16..20].copy_from_slice(&b.octets());
            let sum = checksum(&p[..20]);
            p[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            p[0] = 0x60;
            p[4..6].copy_from_slice(&(n - 40).to_be_bytes());
            p[6] = 17;
            p[7] = 64;
            p[8..24].copy_from_slice(&a.octets());
            p[24..40].copy_from_slice(&b.octets());
        }
        _ => unreachable!("same family flow"),
    }
    p[h..h + 2].copy_from_slice(&src.port().to_be_bytes());
    p[h + 2..h + 4].copy_from_slice(&dst.port().to_be_bytes());
    p[h + 4..h + 6].copy_from_slice(&(n - h as u16).to_be_bytes());
    p[h + 8..].copy_from_slice(data);
    let sum = checksum(&pseudo(&p));
    p[h + 6..h + 8].copy_from_slice(&(if sum == 0 { 65535 } else { sum }).to_be_bytes());
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;
    #[tokio::test]
    async fn udp_flow_isolation_expiry_and_destination_policy() {
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = match echo.local_addr().unwrap() {
            std::net::SocketAddr::V4(v) => v,
            _ => unreachable!(),
        };
        let source = Ipv4Addr::new(10, 203, 0, 2);
        let now = Instant::now();
        let p = udp_packet(SocketAddrV4::new(source, 4000), target, b"first");
        assert!(Engine::new(source, false).ingest(p.clone(), now).is_err());
        let mut engine = Engine::new(source, true);
        engine.ingest(p, now).unwrap();
        engine
            .ingest(
                udp_packet(SocketAddrV4::new(source, 4001), target, b"second"),
                now,
            )
            .unwrap();
        for _ in 0..2 {
            let mut b = [0; 64];
            let (n, from) = tokio::time::timeout(Duration::from_secs(2), echo.recv_from(&mut b))
                .await
                .unwrap()
                .unwrap();
            echo.send_to(&b[..n], from).await.unwrap();
        }
        let mut replies = vec![];
        for _ in 0..100 {
            replies.extend(engine.poll(Instant::now()).await);
            if replies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(replies.len(), 2);
        for p in replies {
            let port = u16::from_be_bytes([p[22], p[23]]);
            assert_eq!(
                &p[28..],
                if port == 4000 {
                    b"first".as_slice()
                } else {
                    assert_eq!(port, 4001);
                    b"second".as_slice()
                }
            );
        }
        engine.poll(now + Duration::from_secs(121)).await;
        assert!(engine.flows.is_empty());
        let mut bad = udp_packet(SocketAddrV4::new(source, 4000), target, b"x");
        bad[12] ^= 1;
        assert!(engine.ingest(bad, now).is_err());
    }
    #[tokio::test]
    async fn tcp_proxy_transfers_and_preserves_half_close() {
        tcp_transfer(false).await;
        tcp_transfer(true).await;
    }
    async fn tcp_transfer(v6: bool) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind(if v6 { "[::1]:0" } else { "127.0.0.1:0" })
            .await
            .unwrap();
        let target = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut b = vec![];
            s.read_to_end(&mut b).await.unwrap();
            assert_eq!(b, vec![42; 32768]);
            s.write_all(&b).await.unwrap();
            s.shutdown().await.unwrap();
        });
        let source = Ipv4Addr::new(10, 203, 0, 2);
        let mut engine = Engine::new(source, true);
        let mut packets = Packets::default();
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut packets, Time::ZERO);
        iface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(IpAddress::Ipv4(source), 32)).unwrap();
        });
        iface.routes_mut().add_default_ipv4_route(source).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; BUFFER]),
            tcp::SocketBuffer::new(vec![0; BUFFER]),
        );
        let app_ip: IpAddr = if v6 {
            ipv6(source).into()
        } else {
            source.into()
        };
        iface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(IpAddress::Ipv6(ipv6(source)), 128))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv6_route(ipv6(source))
            .unwrap();
        socket
            .connect(
                iface.context(),
                IpEndpoint::new(target.ip().into(), target.port()),
                IpEndpoint::new(app_ip.into(), 4000),
            )
            .unwrap();
        let handle = sockets.add(socket);
        let start = Instant::now();
        let mut sent = 0;
        let mut received = vec![];
        let mut closed = false;
        while start.elapsed() < Duration::from_secs(10) {
            let now = Instant::now();
            let t = Time::from_millis(start.elapsed().as_millis() as i64);
            iface.poll(t, &mut packets, &mut sockets);
            for p in packets.tx.drain(..) {
                engine.ingest(p, now).unwrap();
            }
            packets.rx.extend(engine.poll(now).await);
            let s = sockets.get_mut::<tcp::Socket>(handle);
            if s.can_send() && sent < 32768 {
                sent += s.send_slice(&vec![42; 32768 - sent]).unwrap();
            }
            if sent == 32768 && !closed {
                s.close();
                closed = true;
            }
            if s.can_recv() {
                s.recv(|b| {
                    received.extend_from_slice(b);
                    (b.len(), ())
                })
                .unwrap();
            }
            if received.len() == 32768 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(received, vec![42; 32768]);
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }
    #[test]
    fn envelopes_reject_corruption_and_oversize() {
        let a = Ipv4Addr::new(10, 203, 0, 2);
        let b = Ipv4Addr::new(10, 203, 0, 3);
        let p = udp_packet(
            SocketAddrV4::new(a, 1),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2),
            b"hello",
        );
        let mut wrapped = wrap(a, b, false, &p).unwrap();
        let (src, dst, response, inner) = unwrap(&wrapped).unwrap();
        assert_eq!((src, dst, response), (a, b, false));
        assert_eq!(inner, p);
        wrapped[12] ^= 1;
        assert!(unwrap(&wrapped).is_none());
        assert!(wrap(a, b, false, &vec![0; MTU + 1]).is_none());
    }
}

#[cfg(test)]
#[path = "exit_tests.rs"]
mod integration_tests;
