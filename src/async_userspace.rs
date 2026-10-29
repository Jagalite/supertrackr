//! Tokio-owned runtime for the userspace TCP/IP and WireGuard engine.
use crate::{
    CandidatePeer,
    peer_manager::{Effect, MTU, overlay},
    userspace::{Network, TcpId, TcpState, UdpId},
};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    net::UdpSocket as Transport,
    sync::{mpsc, oneshot, watch},
};
const BUFFER: usize = 16 * 1024;
const DATAGRAMS: usize = 16;
type Reply<T> = oneshot::Sender<io::Result<T>>;
#[derive(Clone)]
struct Failure {
    kind: io::ErrorKind,
    message: String,
}
impl Failure {
    fn error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}
type Status = watch::Receiver<Option<Failure>>;
fn stopped() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "userspace runtime stopped",
    )
}
fn status(s: &Status) -> io::Result<()> {
    if let Some(f) = s.borrow().as_ref() {
        return Err(f.error());
    }
    if s.has_changed().is_err() {
        return Err(stopped());
    }
    Ok(())
}
async fn checked<T>(s: &Status, f: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    status(s)?;
    let mut changes = s.clone();
    tokio::select! { biased;
        _=changes.changed()=>{status(&changes)?;Err(stopped())},
        result=f=>{status(s)?;result},
    }
}
struct Terminal(watch::Sender<Option<Failure>>);
impl Drop for Terminal {
    fn drop(&mut self) {
        if self.0.borrow().is_none() {
            let _ = self.0.send(Some(Failure {
                kind: io::ErrorKind::ConnectionAborted,
                message: "userspace owner task terminated".into(),
            }));
        }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub path_send_errors: u64,
    pub resolution_dropped: u64,
}
#[derive(Clone)]
pub struct Client {
    commands: Arc<mpsc::Sender<Command>>,
    status: Status,
}
impl Client {
    /// Starts one owner task. The transport must be the endpoint's WireGuard UDP socket.
    /// Resolve events require authenticated tracker lookup and reciprocal introduction.
    pub fn spawn(network: Network, transport: Transport) -> (Self, mpsc::Receiver<Ipv4Addr>) {
        let (tx, rx) = mpsc::channel(64);
        let commands = Arc::new(tx);
        let (state, status) = watch::channel(None);
        let (resolve, events) = mpsc::channel(64);
        let actor = Actor {
            network,
            transport,
            commands: rx,
            owner: Arc::downgrade(&commands),
            status: status.clone(),
            resolve,
            pending: HashMap::new(),
            streams: HashMap::new(),
            listeners: HashMap::new(),
            udp: HashMap::new(),
            egress: VecDeque::new(),
            port: 49152,
            stats: Stats::default(),
        };
        tokio::spawn(async move {
            let mut actor = actor;
            // Declared last so panic/abort publishes failure before bridge teardown.
            let terminal = Terminal(state);
            let result = actor.run().await;
            let failure = match &result {
                Ok(_) => Failure {
                    kind: io::ErrorKind::ConnectionAborted,
                    message: "userspace runtime shut down".into(),
                },
                Err(e) => Failure {
                    kind: e.kind(),
                    message: e.to_string(),
                },
            };
            let _ = terminal.0.send(Some(failure));
            drop(actor);
            if let Ok(Some(reply)) = result {
                let _ = reply.send(Ok(()));
            }
        });
        (Self { commands, status }, events)
    }
    async fn call<T>(&self, make: impl FnOnce(Reply<T>) -> Command) -> io::Result<T> {
        checked(&self.status, async {
            let (reply, response) = oneshot::channel();
            self.commands
                .send(make(reply))
                .await
                .map_err(|_| stopped())?;
            response.await.map_err(|_| stopped())?
        })
        .await
    }
    pub async fn connect(&self, remote: SocketAddrV4) -> io::Result<TcpStream> {
        self.connect_with_timeout(remote, Duration::from_secs(10))
            .await
    }
    pub async fn connect_with_timeout(
        &self,
        remote: SocketAddrV4,
        timeout: Duration,
    ) -> io::Result<TcpStream> {
        if timeout.is_zero() || timeout > Duration::from_secs(300) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "connect timeout must be >0 and <=300 seconds",
            ));
        }
        self.call(|reply| Command::Connect {
            remote,
            deadline: Instant::now() + timeout,
            reply,
        })
        .await
    }
    pub async fn listen_tcp(&self, port: u16) -> io::Result<TcpListener> {
        self.call(|reply| Command::Listen { port, reply }).await
    }
    pub async fn bind_udp(&self, port: u16) -> io::Result<UdpSocket> {
        self.call(|reply| Command::Bind { port, reply }).await
    }
    /// Trusted control-plane operation; never install unauthenticated peer claims.
    pub async fn install_peer(&self, binding: CandidatePeer, until: Instant) -> io::Result<()> {
        self.call(|reply| Command::Install {
            binding,
            until,
            reply,
        })
        .await
    }
    pub async fn renew(&self, until: Instant) -> io::Result<()> {
        self.call(|reply| Command::Renew { until, reply }).await
    }
    pub async fn stats(&self) -> io::Result<Stats> {
        self.call(Command::Stats).await
    }
    /// Stops this runtime and all handles; returns after the transport is released.
    pub async fn shutdown(&self) -> io::Result<()> {
        status(&self.status)?;
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Stop(reply))
            .await
            .map_err(|_| stopped())?;
        response.await.map_err(|_| stopped())?
    }
}
/// Async stream. Flush means acceptance by local buffering, not remote acknowledgement.
/// Shutdown half-closes after buffered writes drain. Drop drains/FINs for up to 30 seconds.
pub struct TcpStream {
    io: DuplexStream,
    client: Client,
    _alive: oneshot::Sender<()>,
}
impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(e) = status(&self.client.status) {
            return Poll::Ready(Err(e));
        }
        let filled = buf.filled().len();
        let result = Pin::new(&mut self.io).poll_read(cx, buf);
        if let Err(e) = status(&self.client.status) {
            buf.set_filled(filled);
            return Poll::Ready(Err(e));
        }
        result
    }
}
impl AsyncWrite for TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(e) = status(&self.client.status) {
            return Poll::Ready(Err(e));
        }
        let result = Pin::new(&mut self.io).poll_write(cx, buf);
        if let Err(e) = status(&self.client.status) {
            return Poll::Ready(Err(e));
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = status(&self.client.status) {
            return Poll::Ready(Err(e));
        }
        let result = Pin::new(&mut self.io).poll_flush(cx);
        if let Err(e) = status(&self.client.status) {
            return Poll::Ready(Err(e));
        }
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = status(&self.client.status) {
            return Poll::Ready(Err(e));
        }
        let result = Pin::new(&mut self.io).poll_shutdown(cx);
        if let Err(e) = status(&self.client.status) {
            return Poll::Ready(Err(e));
        }
        result
    }
}
pub struct TcpListener {
    accepted: mpsc::Receiver<(TcpStream, SocketAddrV4)>,
    client: Client,
}
impl TcpListener {
    pub async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddrV4)> {
        checked(&self.client.status, async {
            self.accepted.recv().await.ok_or_else(stopped)
        })
        .await
    }
}
struct Datagram {
    data: Vec<u8>,
    addr: SocketAddrV4,
}
pub struct UdpSocket {
    incoming: mpsc::Receiver<Datagram>,
    outgoing: mpsc::Sender<Datagram>,
    client: Client,
}
impl UdpSocket {
    /// Returns once queued locally. UDP delivery is not guaranteed.
    pub async fn send_to(&self, data: &[u8], remote: SocketAddrV4) -> io::Result<usize> {
        if !overlay(*remote.ip()) || remote.port() == 0 || data.len() > MTU - 28 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid overlay UDP destination or payload size",
            ));
        }
        checked(&self.client.status, async {
            let slot = self.outgoing.reserve().await.map_err(|_| stopped())?;
            slot.send(Datagram {
                data: data.to_vec(),
                addr: remote,
            });
            Ok(data.len())
        })
        .await
    }
    /// Cancellation-safe receive. A short buffer consumes the datagram and errors.
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        checked(&self.client.status, async {
            let datagram = self.incoming.recv().await.ok_or_else(stopped)?;
            if datagram.data.len() > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP receive buffer too short",
                ));
            }
            buf[..datagram.data.len()].copy_from_slice(&datagram.data);
            Ok((datagram.data.len(), datagram.addr))
        })
        .await
    }
}
enum Command {
    Connect {
        remote: SocketAddrV4,
        deadline: Instant,
        reply: Reply<TcpStream>,
    },
    Listen {
        port: u16,
        reply: Reply<TcpListener>,
    },
    Bind {
        port: u16,
        reply: Reply<UdpSocket>,
    },
    Install {
        binding: CandidatePeer,
        until: Instant,
        reply: Reply<()>,
    },
    Renew {
        until: Instant,
        reply: Reply<()>,
    },
    Stop(Reply<()>),
    Stats(Reply<Stats>),
}
struct Connecting {
    deadline: Instant,
    reply: Reply<TcpStream>,
}
struct Bridge {
    io: DuplexStream,
    alive: oneshot::Receiver<()>,
    tx: Vec<u8>,
    tx_pos: usize,
    rx: Vec<u8>,
    rx_pos: usize,
    fin: bool,
    eof: bool,
    drop_at: Option<Instant>,
}
struct UdpBridge {
    incoming: mpsc::Sender<Datagram>,
    outgoing: mpsc::Receiver<Datagram>,
    pending: Option<Datagram>,
}
struct Actor {
    network: Network,
    transport: Transport,
    commands: mpsc::Receiver<Command>,
    owner: Weak<mpsc::Sender<Command>>,
    status: Status,
    resolve: mpsc::Sender<Ipv4Addr>,
    pending: HashMap<TcpId, Connecting>,
    streams: HashMap<TcpId, Bridge>,
    listeners: HashMap<TcpId, mpsc::Sender<(TcpStream, SocketAddrV4)>>,
    udp: HashMap<UdpId, UdpBridge>,
    egress: VecDeque<(SocketAddr, Vec<u8>)>,
    port: u16,
    stats: Stats,
}
impl Actor {
    fn client(&self) -> io::Result<Client> {
        Ok(Client {
            commands: self.owner.upgrade().ok_or_else(stopped)?,
            status: self.status.clone(),
        })
    }
    fn stream(&mut self, id: TcpId) -> io::Result<TcpStream> {
        let client = self.client()?;
        let (app, io) = tokio::io::duplex(BUFFER);
        let (alive, watch) = oneshot::channel();
        self.streams.insert(
            id,
            Bridge {
                io,
                alive: watch,
                tx: Vec::new(),
                tx_pos: 0,
                rx: Vec::new(),
                rx_pos: 0,
                fin: false,
                eof: false,
                drop_at: None,
            },
        );
        Ok(TcpStream {
            io: app,
            client,
            _alive: alive,
        })
    }
    fn effects(&mut self, effects: Vec<Effect>) -> io::Result<()> {
        for effect in effects {
            match effect {
                Effect::Network {
                    to: Some(to), data, ..
                } => {
                    if self.egress.len() >= 2048 {
                        return Err(io::Error::new(
                            io::ErrorKind::OutOfMemory,
                            "WireGuard output queue exhausted",
                        ));
                    }
                    if self.transport.local_addr()?.is_ipv4() != to.is_ipv4() {
                        self.stats.path_send_errors += 1;
                        continue;
                    }
                    self.egress.push_back((to, data));
                }
                Effect::Resolve(ip) => {
                    if self.resolve.try_send(ip).is_err() {
                        self.stats.resolution_dropped += 1;
                    }
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected plaintext or relay action",
                    ));
                }
            }
        }
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        for _ in 0..64 {
            let Some((to, data)) = self.egress.front() else {
                break;
            };
            match self.transport.try_send_to(data, *to) {
                Ok(_) => {
                    self.egress.pop_front();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.stats.path_send_errors += 1;
                    self.egress.pop_front();
                }
            }
        }
        Ok(())
    }
    fn command(&mut self, command: Command) -> io::Result<Option<Reply<()>>> {
        match command {
            Command::Stop(reply) => return Ok(Some(reply)),
            Command::Stats(reply) => {
                let _ = reply.send(Ok(self.stats));
            }
            Command::Renew { until, reply } => {
                if !reply.is_closed() {
                    let _ = reply.send(self.network.renew(until));
                }
            }
            Command::Install {
                binding,
                until,
                reply,
            } => {
                if !reply.is_closed() {
                    let result = self.network.install_peer(binding, until, Instant::now());
                    match result {
                        Ok(e) => {
                            self.effects(e)?;
                            let _ = reply.send(Ok(()));
                        }
                        Err(e) => {
                            let _ = reply.send(Err(e));
                        }
                    }
                }
            }
            Command::Connect {
                remote,
                deadline,
                reply,
            } => {
                if reply.is_closed() {
                    return Ok(None);
                }
                let mut result = Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "no ephemeral TCP ports",
                ));
                for _ in 49152..=65535 {
                    let port = self.port;
                    self.port = if port == 65535 { 49152 } else { port + 1 };
                    result = self.network.connect_tcp(remote, port);
                    if !matches!(&result,Err(e) if e.kind()==io::ErrorKind::AddrInUse) {
                        break;
                    }
                }
                match result {
                    Ok(id) => {
                        self.pending.insert(id, Connecting { deadline, reply });
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }
            Command::Listen { port, reply } => {
                if reply.is_closed() {
                    return Ok(None);
                }
                let result = self.network.listen_tcp(port).and_then(|id| {
                    let (accepted, rx) = mpsc::channel(1);
                    let client = self.client()?;
                    self.listeners.insert(id, accepted);
                    Ok(TcpListener {
                        accepted: rx,
                        client,
                    })
                });
                let _ = reply.send(result);
            }
            Command::Bind { port, reply } => {
                if reply.is_closed() {
                    return Ok(None);
                }
                let result = self.network.bind_udp(port).and_then(|id| {
                    let (incoming, rx) = mpsc::channel(DATAGRAMS);
                    let (tx, outgoing) = mpsc::channel(DATAGRAMS);
                    let client = self.client()?;
                    self.udp.insert(
                        id,
                        UdpBridge {
                            incoming,
                            outgoing,
                            pending: None,
                        },
                    );
                    Ok(UdpSocket {
                        incoming: rx,
                        outgoing: tx,
                        client,
                    })
                });
                let _ = reply.send(result);
            }
        }
        Ok(None)
    }
    fn progress(&mut self) -> io::Result<()> {
        let effects = self.network.poll(Instant::now())?;
        self.effects(effects)?;
        let ids: Vec<_> = self.pending.keys().copied().collect();
        for id in ids {
            let p = &self.pending[&id];
            let state = self.network.tcp_state(id)?;
            let failed = if p.reply.is_closed() {
                Some(stopped())
            } else if Instant::now() >= p.deadline {
                Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP connect timed out",
                ))
            } else if state == TcpState::Closed {
                Some(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "TCP connection closed",
                ))
            } else {
                None
            };
            if let Some(e) = failed {
                let p = self.pending.remove(&id).unwrap();
                self.network.remove_tcp(id)?;
                let _ = p.reply.send(Err(e));
            } else if matches!(state, TcpState::Established | TcpState::CloseWait) {
                let p = self.pending.remove(&id).unwrap();
                let result = self.stream(id);
                if p.reply.send(result).is_err() {
                    self.streams.remove(&id);
                    self.network.remove_tcp(id)?;
                }
            }
        }
        let ids: Vec<_> = self.listeners.keys().copied().collect();
        for id in ids {
            let sender = self.listeners[&id].clone();
            if sender.is_closed() {
                self.listeners.remove(&id);
                self.network.remove_tcp(id)?;
                continue;
            }
            if let Ok(slot) = sender.try_reserve() {
                match self.network.accept_tcp(id) {
                    Ok((stream, remote)) => match self.stream(stream) {
                        Ok(handle) => slot.send((handle, remote)),
                        Err(e) => {
                            self.network.remove_tcp(stream)?;
                            return Err(e);
                        }
                    },
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
                        ) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        let mut cx = Context::from_waker(Waker::noop());
        let mut retired = Vec::new();
        for (&id, b) in &mut self.streams {
            if b.alive
                .try_recv()
                .is_err_and(|e| e == oneshot::error::TryRecvError::Closed)
            {
                b.drop_at.get_or_insert_with(Instant::now);
            }
            if b.drop_at
                .is_some_and(|at| at.elapsed() >= Duration::from_secs(30))
            {
                retired.push(id);
                continue;
            }
            if b.tx_pos == b.tx.len() && !b.fin {
                let mut bytes = [0; 8192];
                let mut read = ReadBuf::new(&mut bytes);
                match Pin::new(&mut b.io).poll_read(&mut cx, &mut read) {
                    Poll::Ready(Ok(())) if read.filled().is_empty() => {
                        self.network.shutdown_tcp(id)?;
                        b.fin = true;
                    }
                    Poll::Ready(Ok(())) => {
                        b.tx.clear();
                        b.tx.extend_from_slice(read.filled());
                        b.tx_pos = 0;
                    }
                    Poll::Ready(Err(_)) => {
                        self.network.shutdown_tcp(id)?;
                        b.fin = true;
                    }
                    Poll::Pending => {}
                }
            }
            if b.tx_pos < b.tx.len() {
                match self.network.write_tcp(id, &b.tx[b.tx_pos..]) {
                    Ok(n) => b.tx_pos += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        retired.push(id);
                        continue;
                    }
                }
            }
            if b.rx_pos == b.rx.len() && !b.eof {
                let mut bytes = [0; 8192];
                match self.network.read_tcp(id, &mut bytes) {
                    Ok(0) => {
                        b.eof = true;
                    }
                    Ok(n) => {
                        b.rx.clear();
                        b.rx.extend_from_slice(&bytes[..n]);
                        b.rx_pos = 0;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        retired.push(id);
                        continue;
                    }
                }
            }
            if b.drop_at.is_some() {
                b.rx_pos = b.rx.len();
            } else if b.rx_pos < b.rx.len() {
                match Pin::new(&mut b.io).poll_write(&mut cx, &b.rx[b.rx_pos..]) {
                    Poll::Ready(Ok(n)) => b.rx_pos += n,
                    Poll::Ready(Err(_)) => {
                        b.rx_pos = b.rx.len();
                    }
                    Poll::Pending => {}
                }
            }
            if b.eof && b.rx_pos == b.rx.len() {
                let _ = Pin::new(&mut b.io).poll_shutdown(&mut cx);
            }
            if b.drop_at.is_some()
                && matches!(
                    self.network.tcp_state(id)?,
                    TcpState::Closed | TcpState::TimeWait
                )
            {
                retired.push(id);
            }
        }
        for id in retired {
            self.streams.remove(&id);
            self.network.remove_tcp(id)?;
        }
        let mut retired = Vec::new();
        for (&id, b) in &mut self.udp {
            if b.incoming.is_closed() {
                retired.push(id);
                continue;
            }
            if b.pending.is_none() {
                b.pending = b.outgoing.try_recv().ok();
            }
            if let Some(d) = &b.pending {
                match self.network.send_udp(id, d.addr, &d.data) {
                    Ok(()) => b.pending = None,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
            if let Ok(slot) = b.incoming.try_reserve() {
                let mut buf = [0; MTU];
                match self.network.recv_udp(id, &mut buf) {
                    Ok((n, addr)) => slot.send(Datagram {
                        data: buf[..n].to_vec(),
                        addr,
                    }),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
        }
        for id in retired {
            self.udp.remove(&id);
            self.network.remove_udp(id)?;
        }
        let effects = self.network.poll(Instant::now())?;
        self.effects(effects)?;
        self.flush()
    }
    async fn run(&mut self) -> io::Result<Option<Reply<()>>> {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut buf = [0; 2048];
        let mut commands_open = true;
        loop {
            tokio::select! {
                command=self.commands.recv(),if commands_open=>{match command {Some(command)=>if let Some(stop)=self.command(command)?{return Ok(Some(stop));},None=>commands_open=false}},
                result=self.transport.recv_from(&mut buf)=>{let(n,source)=result?;let effects=self.network.receive(&buf[..n],source,Instant::now())?;self.effects(effects)?;},
                _=tick.tick()=>{},
                result=self.transport.writable(),if !self.egress.is_empty()=>{result?;},
            }
            self.progress()?;
            if !commands_open && self.streams.is_empty() {
                return Ok(None);
            }
        }
    }
}
