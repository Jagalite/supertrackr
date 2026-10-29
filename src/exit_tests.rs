use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn ipv6_udp_checksum_and_full_mtu_envelope() {
    let source = Ipv4Addr::new(10, 203, 0, 2);
    let echo = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let src = SocketAddr::new(ipv6(source).into(), 4000);
    let mut engine = Engine::new(source, true);
    let p = udp_packet(src, echo.local_addr().unwrap(), &vec![7; MTU - 48]);
    assert_eq!(p.len(), 1280);
    assert!(
        crate::peer_manager::addresses(
            &wrap(source, Ipv4Addr::new(10, 203, 0, 3), false, &p).unwrap()
        )
        .is_some()
    );
    let mut bad = p.clone();
    bad[46..48].fill(0);
    assert!(engine.ingest(bad, Instant::now()).is_err());
    let mut bad = p.clone();
    bad[6] = 44;
    assert!(engine.ingest(bad, Instant::now()).is_err());
    engine.ingest(p, Instant::now()).unwrap();
    let mut data = [0; 1500];
    let (n, peer) = tokio::time::timeout(Duration::from_secs(2), echo.recv_from(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, MTU - 48);
    echo.send_to(&data[..n], peer).await.unwrap();
    let mut replies = vec![];
    for _ in 0..100 {
        replies.extend(engine.poll(Instant::now()).await);
        if !replies.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(replies.len(), 1);
    assert_eq!(checksum(&pseudo(&replies[0])), 0);
    assert_eq!(packet_addresses(&replies[0]).unwrap().1, src.ip());
}

#[tokio::test]
async fn inbound_udp_both_families_and_listener_cleanup() {
    for v6 in [false, true] {
        let source = Ipv4Addr::new(10, 203, 0, 2);
        let mut engine = Engine::new(source, false);
        let listener = engine
            .add_forward(&Forward {
                listen: if v6 { "[::1]:0" } else { "127.0.0.1:0" }.parse().unwrap(),
                target_port: 6881,
                tcp: false,
            })
            .unwrap();
        let host = tokio::net::UdpSocket::bind(if v6 { "[::1]:0" } else { "127.0.0.1:0" })
            .await
            .unwrap();
        host.send_to(b"unsolicited", listener).await.unwrap();
        let mut packets = vec![];
        for _ in 0..100 {
            packets.extend(engine.poll(Instant::now()).await);
            if !packets.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(packets.len(), 1);
        let p = &packets[0];
        let h = ip_header(p);
        assert_eq!(&p[h + 8..], b"unsolicited");
        let (src, dst) = packet_addresses(p).unwrap();
        assert!(owns(source, dst));
        let response = udp_packet(
            SocketAddr::new(dst, 6881),
            SocketAddr::new(src, host.local_addr().unwrap().port()),
            b"reply",
        );
        // Explicit inbound mapping permits its reply even though private outbound is disabled.
        engine.ingest(response, Instant::now()).unwrap();
        let mut b = [0; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), host.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b[..n], b"reply");
        assert_eq!(from, listener);
        drop(engine);
        assert!(std::net::UdpSocket::bind(listener).is_ok());
    }
}

#[tokio::test]
async fn inbound_tcp_both_families_transfer_and_half_close() {
    for v6 in [false, true] {
        let source = Ipv4Addr::new(10, 203, 0, 2);
        let mut engine = Engine::new(source, false);
        let listener = engine
            .add_forward(&Forward {
                listen: if v6 { "[::1]:0" } else { "127.0.0.1:0" }.parse().unwrap(),
                target_port: 6881,
                tcp: true,
            })
            .unwrap();
        let host = tokio::spawn(async move {
            let mut s = TcpStream::connect(listener).await.unwrap();
            s.write_all(&vec![31; 32768]).await.unwrap();
            s.shutdown().await.unwrap();
            let mut b = vec![];
            s.read_to_end(&mut b).await.unwrap();
            assert_eq!(b, vec![31; 32768]);
        });
        let mut packets = Packets::default();
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut packets, Time::ZERO);
        iface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(source.into(), 32)).unwrap();
            ips.push(IpCidr::new(ipv6(source).into(), 128)).unwrap();
        });
        iface.routes_mut().add_default_ipv4_route(source).unwrap();
        iface
            .routes_mut()
            .add_default_ipv6_route(ipv6(source))
            .unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let mut app = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 65536]),
            tcp::SocketBuffer::new(vec![0; 65536]),
        );
        let ip: IpAddr = if v6 {
            ipv6(source).into()
        } else {
            source.into()
        };
        app.listen(IpEndpoint::new(ip.into(), 6881)).unwrap();
        let handle = sockets.add(app);
        let start = Instant::now();
        let mut received = vec![];
        let mut sent = false;
        while start.elapsed() < Duration::from_secs(10) {
            let now = Instant::now();
            packets.rx.extend(engine.poll(now).await);
            iface.poll(
                Time::from_millis(start.elapsed().as_millis() as i64),
                &mut packets,
                &mut sockets,
            );
            for p in packets.tx.drain(..) {
                engine.ingest(p, now).unwrap();
            }
            let app = sockets.get_mut::<tcp::Socket>(handle);
            if app.can_recv() {
                app.recv(|b| {
                    received.extend_from_slice(b);
                    (b.len(), ())
                })
                .unwrap();
            }
            if received.len() == 32768 && !app.may_recv() && !sent {
                assert_eq!(app.send_slice(&received).unwrap(), 32768);
                app.close();
                sent = true;
            }
            if host.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(sent);
        tokio::time::timeout(Duration::from_secs(1), host)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn separate_family_listeners_can_share_a_port() {
    for tcp in [false, true] {
        let mut engine = Engine::new(Ipv4Addr::new(10, 203, 0, 2), false);
        let v4 = engine
            .add_forward(&Forward {
                listen: "0.0.0.0:0".parse().unwrap(),
                target_port: 6881,
                tcp,
            })
            .unwrap();
        engine
            .add_forward(&Forward {
                listen: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), v4.port()),
                target_port: 6881,
                tcp,
            })
            .unwrap();
    }
}

#[tokio::test]
async fn outbound_first_udp_uses_mapping_and_accepts_peer_replies() {
    for v6 in [false, true] {
        let source = Ipv4Addr::new(10, 203, 0, 2);
        let mut engine = Engine::new(source, true);
        let bind = if v6 { "[::1]:0" } else { "127.0.0.1:0" };
        let mapped = engine
            .add_forward(&Forward {
                listen: bind.parse().unwrap(),
                target_port: 6881,
                tcp: false,
            })
            .unwrap();
        let app = SocketAddr::new(
            if v6 {
                ipv6(source).into()
            } else {
                source.into()
            },
            6881,
        );
        for payload in [b"peer-one".as_slice(), b"peer-two".as_slice()] {
            let peer = tokio::net::UdpSocket::bind(bind).await.unwrap();
            engine
                .ingest(
                    udp_packet(app, peer.local_addr().unwrap(), payload),
                    Instant::now(),
                )
                .unwrap();
            let mut b = [0; 64];
            let (n, from) = tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut b))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&b[..n], payload);
            assert_eq!(
                from, mapped,
                "advertised port must be used for outbound packets too"
            );
            peer.send_to(payload, mapped).await.unwrap();
            let mut replies = vec![];
            for _ in 0..100 {
                replies.extend(engine.poll(Instant::now()).await);
                if !replies.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            assert_eq!(replies.len(), 1);
            let p = &replies[0];
            assert_eq!(&p[ip_header(p) + 8..], payload);
            assert_eq!(packet_addresses(p).unwrap().1, app.ip());
        }
    }
}
