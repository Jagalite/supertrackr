use boringtun::x25519::{PublicKey, StaticSecret};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};
use supertrackr::{CandidatePeer, peer_manager::Effect, userspace::Network};
struct Node {
    net: Network,
    udp: UdpSocket,
    binding: CandidatePeer,
    drops: usize,
    drop_all_data: bool,
}
impl Node {
    fn new(n: u8) -> Self {
        let secret = StaticSecret::from([n; 32]);
        let ip = Ipv4Addr::new(10, 203, 0, n);
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_nonblocking(true).unwrap();
        let addr = udp.local_addr().unwrap();
        let binding = CandidatePeer {
            public_key: hex::encode(PublicKey::from(&secret).as_bytes()),
            endpoint: addr,
            candidates: vec![addr],
            virtual_ip: ip,
            remaining_seconds: 60,
        };
        Self {
            net: Network::new(secret, ip, Instant::now() + Duration::from_secs(60)).unwrap(),
            udp,
            binding,
            drops: 0,
            drop_all_data: false,
        }
    }
    fn dispatch(&mut self, effects: Vec<Effect>) {
        for e in effects {
            match e {
                Effect::Network {
                    to: Some(addr),
                    data,
                    ..
                } => {
                    if self.drop_all_data && data.starts_with(&[4, 0, 0, 0]) {
                        continue;
                    }
                    if self.drops > 0 && data.len() > 200 && data.starts_with(&[4, 0, 0, 0]) {
                        self.drops -= 1;
                        continue;
                    }
                    self.udp.send_to(&data, addr).unwrap();
                }
                Effect::Resolve(_) => {}
                _ => panic!("plaintext or relay escaped userspace API"),
            }
        }
    }
    fn step(&mut self) {
        let mut buf = [0; 2048];
        loop {
            match self.udp.recv_from(&mut buf) {
                Ok((n, source)) => {
                    let effects = self.net.receive(&buf[..n], source, Instant::now()).unwrap();
                    self.dispatch(effects);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("{e}"),
            }
        }
        let effects = self.net.poll(Instant::now()).unwrap();
        self.dispatch(effects);
    }
}
fn pump(a: &mut Node, b: &mut Node) {
    a.step();
    b.step();
    std::thread::sleep(Duration::from_millis(2));
}
fn pair() -> (Node, Node) {
    let mut a = Node::new(1);
    let mut b = Node::new(2);
    let now = Instant::now();
    let e = a
        .net
        .install_peer(b.binding.clone(), now + Duration::from_secs(60), now)
        .unwrap();
    a.dispatch(e);
    let e = b
        .net
        .install_peer(a.binding.clone(), now + Duration::from_secs(60), now)
        .unwrap();
    b.dispatch(e);
    (a, b)
}
#[test]
fn real_tcp_stream_retransmission_half_close_and_udp_over_wireguard() {
    let (mut a, mut b) = pair();
    let listener = b.net.listen_tcp(8080).unwrap();
    assert_eq!(
        b.net.listen_tcp(8080).unwrap_err().kind(),
        io::ErrorKind::AddrInUse
    );
    let client = a
        .net
        .connect_tcp(SocketAddrV4::new(b.binding.virtual_ip, 8080), 40000)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let (server, remote) = loop {
        pump(&mut a, &mut b);
        match b.net.accept_tcp(listener) {
            Ok(value) => break value,
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::WouldBlock),
        }
        assert!(Instant::now() < deadline, "TCP handshake timed out");
    };
    assert_eq!(remote, SocketAddrV4::new(a.binding.virtual_ip, 40000));
    let input: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
    let mut sent = 0;
    let mut received = Vec::new();
    let mut buf = [0; 8192];
    a.drops = 1;
    while received.len() < input.len() {
        if sent < input.len() {
            match a.net.write_tcp(client, &input[sent..]) {
                Ok(n) => sent += n,
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::WouldBlock),
            }
        }
        pump(&mut a, &mut b);
        match b.net.read_tcp(server, &mut buf) {
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::WouldBlock),
        }
        assert!(
            Instant::now() < deadline,
            "TCP payload timed out: {sent}/{}",
            received.len()
        );
    }
    assert_eq!(a.drops, 0);
    assert_eq!(input, received);
    a.net.shutdown_tcp(client).unwrap();
    loop {
        pump(&mut a, &mut b);
        match b.net.read_tcp(server, &mut buf) {
            Ok(0) => break,
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::WouldBlock),
            other => panic!("{other:?}"),
        };
        assert!(Instant::now() < deadline);
    }
    b.net.write_tcp(server, b"reply after FIN").unwrap();
    loop {
        pump(&mut a, &mut b);
        match a.net.read_tcp(client, &mut buf) {
            Ok(n) => {
                assert_eq!(&buf[..n], b"reply after FIN");
                break;
            }
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::WouldBlock),
        }
        assert!(Instant::now() < deadline);
    }
    // The original listener accepts another connection while the first still exists.
    let _second = a
        .net
        .connect_tcp(SocketAddrV4::new(b.binding.virtual_ip, 8080), 40001)
        .unwrap();
    loop {
        pump(&mut a, &mut b);
        if let Ok((_, addr)) = b.net.accept_tcp(listener) {
            assert_eq!(addr.port(), 40001);
            break;
        }
        assert!(Instant::now() < deadline);
    }
    let au = a.net.bind_udp(9000).unwrap();
    let bu = b.net.bind_udp(9000).unwrap();
    for data in [vec![], vec![7; 1252]] {
        a.net
            .send_udp(au, SocketAddrV4::new(b.binding.virtual_ip, 9000), &data)
            .unwrap();
        loop {
            pump(&mut a, &mut b);
            match b.net.recv_udp(bu, &mut buf) {
                Ok((n, addr)) => {
                    assert_eq!(&buf[..n], data);
                    assert_eq!(addr.ip(), &a.binding.virtual_ip);
                    break;
                }
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::WouldBlock),
            }
            assert!(Instant::now() < deadline);
        }
    }
    assert!(
        a.net
            .send_udp(
                au,
                SocketAddrV4::new(b.binding.virtual_ip, 9000),
                &[0; 1253]
            )
            .is_err()
    );
}
#[test]
fn limits_expiry_handles_and_overlay_only() {
    let mut a = Node::new(3);
    let mut b = Node::new(4);
    let u = a.net.bind_udp(9000).unwrap();
    let _ = b.net.bind_udp(9000).unwrap();
    assert_eq!(
        b.net.recv_udp(u, &mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert!(
        a.net
            .send_udp(u, "8.8.8.8:53".parse().unwrap(), b"no fallback")
            .is_err()
    );
    assert!(
        a.net
            .connect_tcp("127.0.0.1:80".parse().unwrap(), 30000)
            .is_err()
    );
    for p in 9001..9064 {
        a.net.bind_udp(p).unwrap();
    }
    assert_eq!(
        a.net.bind_udp(9064).unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    a.net.remove_udp(u).unwrap();
    let replacement = a.net.bind_udp(9000).unwrap();
    assert_ne!(replacement, u);
    assert!(a.net.recv_udp(u, &mut [0; 1]).is_err());
    assert!(
        a.net
            .poll(Instant::now() + Duration::from_secs(61))
            .is_err()
    );
    assert!(
        a.net
            .renew(Instant::now() + Duration::from_secs(120))
            .is_err()
    );
    assert!(
        a.net
            .send_udp(replacement, "10.203.0.4:9000".parse().unwrap(), b"expired")
            .is_err()
    );
}
#[test]
fn unknown_peer_requests_resolution_and_untrusted_plaintext_is_not_delivered() {
    let mut a = Node::new(5);
    let u = a.net.bind_udp(9000).unwrap();
    a.net
        .send_udp(u, "10.203.0.6:9000".parse().unwrap(), b"resolve me")
        .unwrap();
    let effects = a.net.poll(Instant::now()).unwrap();
    assert!(
        effects
            .iter()
            .any(|e| matches!(e,Effect::Resolve(ip) if *ip==Ipv4Addr::new(10,203,0,6)))
    );
    assert!(!effects.iter().any(|e| matches!(e, Effect::Network { .. })));
    let source: SocketAddr = "127.0.0.1:10000".parse().unwrap();
    assert!(
        a.net
            .receive(b"unauthenticated", source, Instant::now())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        a.net.recv_udp(u, &mut [0; 100]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn listener_recovers_from_handshake_timeout_even_at_capacity() {
    use supertrackr::userspace::TcpState;
    let (mut a, mut b) = pair();
    let listener = b.net.listen_tcp(8080).unwrap();
    // Deliver WireGuard's handshake but discard encrypted TCP SYN-ACK replies.
    b.drop_all_data = true;
    let abandoned = a
        .net
        .connect_tcp(SocketAddrV4::new(b.binding.virtual_ip, 8080), 40000)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while b.net.tcp_state(listener).unwrap() != TcpState::SynReceived {
        pump(&mut a, &mut b);
        assert!(Instant::now() < deadline, "no SYN received");
    }
    let future = Instant::now() + Duration::from_secs(31);
    b.net.poll(future).unwrap();
    assert_eq!(b.net.tcp_state(listener).unwrap(), TcpState::Closed);
    a.net.remove_tcp(abandoned).unwrap();
    // Re-arming is allocation-free and must work even with all 64 slots occupied.
    let sockets: Vec<_> = (10000..10063)
        .map(|port| b.net.bind_udp(port).unwrap())
        .collect();
    assert_eq!(
        b.net.bind_udp(11000).unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(
        b.net.accept_tcp(listener).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(b.net.tcp_state(listener).unwrap(), TcpState::Listen);
    b.drop_all_data = false;
    let client = a
        .net
        .connect_tcp(SocketAddrV4::new(b.binding.virtual_ip, 8080), 40001)
        .unwrap();
    while b.net.tcp_state(listener).unwrap() != TcpState::Established
        || a.net.tcp_state(client).unwrap() != TcpState::Established
    {
        pump(&mut a, &mut b);
        assert!(Instant::now() < deadline, "replacement handshake failed");
    }
    assert_eq!(a.net.write_tcp(client, b"recovered").unwrap(), 9);
    for _ in 0..5 {
        pump(&mut a, &mut b);
    }
    // A live pending connection must survive a full socket table with its data intact.
    assert_eq!(
        b.net.accept_tcp(listener).unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(b.net.tcp_state(listener).unwrap(), TcpState::Established);
    b.net.remove_udp(sockets[0]).unwrap();
    let (server, remote) = b.net.accept_tcp(listener).unwrap();
    assert_eq!(remote, SocketAddrV4::new(a.binding.virtual_ip, 40001));
    assert_eq!(b.net.tcp_state(listener).unwrap(), TcpState::Listen);
    let mut output = Vec::new();
    let mut buf = [0; 32];
    while output.len() < 9 {
        pump(&mut a, &mut b);
        match b.net.read_tcp(server, &mut buf) {
            Ok(n) => output.extend_from_slice(&buf[..n]),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::WouldBlock),
        }
        assert!(Instant::now() < deadline, "recovered stream stalled");
    }
    assert_eq!(output, b"recovered");
}
