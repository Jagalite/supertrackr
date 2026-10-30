//! Real outer UDP/WireGuard tests for the Tokio facade. No TUN or OS routes.
use boringtun::x25519::{PublicKey, StaticSecret};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::{Duration, Instant},
};
use supertrackr::{CandidatePeer, async_userspace::Client, userspace::Network};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::mpsc,
    time::{sleep, timeout},
};

struct Node {
    client: Client,
    resolutions: mpsc::Receiver<Ipv4Addr>,
    binding: CandidatePeer,
    outer: SocketAddr,
}
async fn node(n: u8) -> Node {
    let secret = StaticSecret::from([n; 32]);
    let ip = Ipv4Addr::new(10, 203, 0, n);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let outer = udp.local_addr().unwrap();
    let binding = CandidatePeer {
        public_key: hex::encode(PublicKey::from(&secret).as_bytes()),
        endpoint: outer,
        candidates: vec![outer],
        virtual_ip: ip,
        remaining_seconds: 60,
    };
    let network = Network::new(secret, ip, Instant::now() + Duration::from_secs(60)).unwrap();
    let (client, resolutions) = Client::spawn(network, udp);
    Node {
        client,
        resolutions,
        binding,
        outer,
    }
}
async fn pair() -> (Node, Node) {
    let a = node(1).await;
    let b = node(2).await;
    let until = Instant::now() + Duration::from_secs(60);
    a.client
        .install_peer(b.binding.clone(), until)
        .await
        .unwrap();
    b.client
        .install_peer(a.binding.clone(), until)
        .await
        .unwrap();
    (a, b)
}
fn err<T>(result: io::Result<T>) -> io::Error {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => error,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linked_wireguard_credentials_exchange_traffic_and_survive_peer_revocation() {
    use supertrackr::{Config, Coordinator, InterfaceInfo, enrollment, router};
    timeout(Duration::from_secs(20), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base: reqwest::Url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let state = Coordinator::with_audience(
            Config {
                open_registration: true,
                ..Config::default()
            },
            base.to_string(),
        );
        let server =
            tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let mut nodes = Vec::new();
        for n in [41u8, 42, 43] {
            let secret = StaticSecret::from([n; 32]);
            let key = hex::encode(PublicKey::from(&secret).as_bytes());
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let endpoint = udp.local_addr().unwrap();
            let registration = enrollment::register(&http, &base, &secret, endpoint)
                .await
                .unwrap();
            http.post(base.join("v1/candidates").unwrap())
                .header("x-peer-key", &key)
                .bearer_auth(&registration.token)
                .json(&serde_json::json!({"candidates":[endpoint]}))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
            let interface: InterfaceInfo = http
                .get(base.join("v1/interface").unwrap())
                .header("x-peer-key", &key)
                .bearer_auth(&registration.token)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            nodes.push((secret, key, registration.token, endpoint, udp, interface));
        }
        let linked = enrollment::link_registered_wireguard(
            &http,
            &base,
            &nodes[0].1,
            &nodes[0].2,
            &nodes[1].0,
            nodes[1].3,
        )
        .await
        .unwrap();
        assert_eq!(linked.wireguard_keys.len(), 2);
        let mut bindings = Vec::new();
        for (requester, target) in [(2, 0), (2, 1), (0, 2), (1, 2)] {
            let binding: CandidatePeer = http
                .post(base.join("v1/binding").unwrap())
                .header("x-peer-key", &nodes[requester].1)
                .bearer_auth(&nodes[requester].2)
                .json(&serde_json::json!({"public_key":nodes[target].1}))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            bindings.push(binding);
        }
        let until = Instant::now() + Duration::from_secs(30);
        let owner_key = nodes[0].1.clone();
        let added_key = nodes[1].1.clone();
        let added_token = nodes[1].2.clone();
        let remote_key = nodes[2].1.clone();
        let remote_token = nodes[2].2.clone();
        let mut clients = Vec::new();
        for (secret, _, _, _, udp, interface) in nodes.drain(..) {
            let network = Network::new(secret, interface.virtual_ip, until).unwrap();
            clients.push(Client::spawn(network, udp).0);
        }
        clients[2]
            .install_peer(bindings[0].clone(), until)
            .await
            .unwrap();
        clients[2]
            .install_peer(bindings[1].clone(), until)
            .await
            .unwrap();
        clients[0]
            .install_peer(bindings[2].clone(), until)
            .await
            .unwrap();
        clients[1]
            .install_peer(bindings[3].clone(), until)
            .await
            .unwrap();
        let sender = clients[2].bind_udp(9000).await.unwrap();
        let mut old = clients[0].bind_udp(9000).await.unwrap();
        let mut new = clients[1].bind_udp(9000).await.unwrap();
        for (binding, receiver) in [(&bindings[0], &mut old), (&bindings[1], &mut new)] {
            sender
                .send_to(b"linked", SocketAddrV4::new(binding.virtual_ip, 9000))
                .await
                .unwrap();
            let mut buffer = [0; 32];
            let (n, _) = receiver.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..n], b"linked");
        }
        assert_eq!(
            http.post(base.join("v1/identity/revoke").unwrap())
                .header("x-peer-key", &added_key)
                .bearer_auth(&added_token)
                .json(&serde_json::json!({"public_key":owner_key}))
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::NO_CONTENT
        );
        assert_eq!(
            http.post(base.join("v1/binding").unwrap())
                .header("x-peer-key", &remote_key)
                .bearer_auth(&remote_token)
                .json(&serde_json::json!({"public_key":owner_key}))
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::NOT_FOUND
        );
        sender
            .send_to(
                b"remaining",
                SocketAddrV4::new(bindings[1].virtual_ip, 9000),
            )
            .await
            .unwrap();
        let mut buffer = [0; 32];
        let (n, _) = new.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..n], b"remaining");
        for client in clients {
            client.shutdown().await.unwrap();
        }
        server.abort();
    })
    .await
    .expect("linked WireGuard exchange stalled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_tcp_large_transfer_half_close_and_drop_preserve_queued_bytes() {
    timeout(Duration::from_secs(15), async {
        let (a, b) = pair().await;
        let mut listener = b.client.listen_tcp(8080).await.unwrap();
        let remote = SocketAddrV4::new(b.binding.virtual_ip, 8080);
        let (outgoing, incoming) = tokio::join!(a.client.connect(remote), listener.accept());
        let mut outgoing = outgoing.unwrap();
        let (mut incoming, source) = incoming.unwrap();
        assert_eq!(*source.ip(), a.binding.virtual_ip);
        let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        let (received, ()) = tokio::join!(
            async {
                let mut received = Vec::new();
                incoming.read_to_end(&mut received).await.unwrap();
                incoming.write_all(b"reply after FIN").await.unwrap();
                incoming.shutdown().await.unwrap();
                received
            },
            async {
                outgoing.write_all(&payload).await.unwrap();
                outgoing.shutdown().await.unwrap();
                let mut reply = Vec::new();
                outgoing.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"reply after FIN");
            }
        );
        assert_eq!(received, payload);
        drop(outgoing);
        drop(incoming);

        // The sender disappears immediately after shutdown; the actor still owes
        // the remote all bytes accepted into Duplex and TCP send buffers.
        let (outgoing, incoming) = tokio::join!(a.client.connect(remote), listener.accept());
        let mut outgoing = outgoing.unwrap();
        let (mut incoming, _) = incoming.unwrap();
        let payload: Vec<u8> = (0..128 * 1024).map(|i| (i % 239) as u8).collect();
        let ((), received) = tokio::join!(
            async {
                outgoing.write_all(&payload).await.unwrap();
                outgoing.shutdown().await.unwrap();
                drop(outgoing);
            },
            async {
                let mut received = Vec::new();
                incoming.read_to_end(&mut received).await.unwrap();
                received
            }
        );
        assert_eq!(received, payload);
        a.client.shutdown().await.unwrap();
        b.client.shutdown().await.unwrap();
    })
    .await
    .expect("TCP transfer or half-close stalled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_udp_bounds_and_cancelled_receive_do_not_consume_next_datagram() {
    timeout(Duration::from_secs(8), async {
        let (a, b) = pair().await;
        let mut au = a.client.bind_udp(9000).await.unwrap();
        let mut bu = b.client.bind_udp(9000).await.unwrap();
        let remote = SocketAddrV4::new(b.binding.virtual_ip, 9000);
        let mut buffer = [0; 1252];
        assert!(
            timeout(Duration::from_millis(30), bu.recv_from(&mut buffer))
                .await
                .is_err()
        );
        for data in [Vec::new(), vec![7; 1252]] {
            assert_eq!(au.send_to(&data, remote).await.unwrap(), data.len());
            let (n, source) = bu.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..n], data);
            assert_eq!(source, SocketAddrV4::new(a.binding.virtual_ip, 9000));
            assert_eq!(bu.send_to(&buffer[..n], source).await.unwrap(), n);
            let (n, source) = au.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..n], data);
            assert_eq!(source, remote);
        }
        assert_eq!(
            err(au.send_to(&[0; 1253], remote).await).kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            err(au
                .send_to(b"no host fallback", "8.8.8.8:53".parse().unwrap())
                .await)
            .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            err(a.client.bind_udp(9000).await).kind(),
            io::ErrorKind::AddrInUse
        );
        a.client.shutdown().await.unwrap();
        b.client.shutdown().await.unwrap();
    })
    .await
    .expect("UDP exchange stalled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_connects_release_all_socket_slots() {
    timeout(Duration::from_secs(10), async {
        let a = node(3).await;
        let unknown = "10.203.0.250:8080".parse().unwrap();
        for _ in 0..80 {
            assert!(
                timeout(
                    Duration::from_millis(20),
                    a.client
                        .connect_with_timeout(unknown, Duration::from_secs(2))
                )
                .await
                .is_err(),
                "unknown peer unexpectedly completed a connection"
            );
        }
        // Allow the final cancellation to be observed by the 10ms driver tick.
        sleep(Duration::from_millis(30)).await;
        let mut sockets = Vec::new();
        for port in 10000..10064 {
            sockets.push(
                a.client
                    .bind_udp(port)
                    .await
                    .expect("cancelled connect leaked a TCP slot"),
            );
        }
        assert_eq!(
            err(a.client.bind_udp(10064).await).kind(),
            io::ErrorKind::OutOfMemory
        );
        drop(sockets);
        a.client.shutdown().await.unwrap();
    })
    .await
    .expect("connect cancellation cleanup stalled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_wakes_pending_stream_datagram_accept_and_connect() {
    timeout(Duration::from_secs(8), async {
        let (a, b) = pair().await;
        let mut listener = b.client.listen_tcp(8080).await.unwrap();
        let (outgoing, incoming) = tokio::join!(
            a.client
                .connect(SocketAddrV4::new(b.binding.virtual_ip, 8080)),
            listener.accept()
        );
        let mut outgoing = outgoing.unwrap();
        let (_incoming, _) = incoming.unwrap();
        let mut pending_listener = a.client.listen_tcp(8081).await.unwrap();
        let mut datagrams = a.client.bind_udp(9000).await.unwrap();
        let mut tcp_buffer = [0; 1];
        let mut udp_buffer = [0; 1];
        let (read, receive, accept, connect, ()) = tokio::join!(
            outgoing.read(&mut tcp_buffer),
            datagrams.recv_from(&mut udp_buffer),
            pending_listener.accept(),
            a.client.connect("10.203.0.250:8080".parse().unwrap()),
            async {
                sleep(Duration::from_millis(50)).await;
                a.client.shutdown().await.unwrap();
            }
        );
        assert!(read.is_err(), "shutdown looked like clean EOF");
        assert!(receive.is_err());
        assert!(accept.is_err());
        assert!(connect.is_err());
        assert!(a.client.bind_udp(9001).await.is_err());
        b.client.shutdown().await.unwrap();
    })
    .await
    .expect("shutdown failed to wake an operation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_lease_expiry_wakes_pending_operations_and_cannot_be_renewed() {
    timeout(Duration::from_secs(8), async {
        let (a, b) = pair().await;
        let mut listener = b.client.listen_tcp(8080).await.unwrap();
        let (outgoing, incoming) = tokio::join!(
            a.client
                .connect(SocketAddrV4::new(b.binding.virtual_ip, 8080)),
            listener.accept()
        );
        let mut outgoing = outgoing.unwrap();
        let (_incoming, _) = incoming.unwrap();
        let mut pending_listener = a.client.listen_tcp(8081).await.unwrap();
        let mut datagrams = a.client.bind_udp(9000).await.unwrap();
        a.client
            .renew(Instant::now() + Duration::from_millis(150))
            .await
            .unwrap();
        let mut tcp_buffer = [0; 1];
        let mut udp_buffer = [0; 1];
        let (read, receive, accept, connect) = tokio::join!(
            outgoing.read(&mut tcp_buffer),
            datagrams.recv_from(&mut udp_buffer),
            pending_listener.accept(),
            a.client.connect("10.203.0.250:8080".parse().unwrap()),
        );
        assert!(read.is_err(), "expired registration looked like clean EOF");
        assert!(receive.is_err());
        assert!(accept.is_err());
        assert!(connect.is_err());
        assert!(
            a.client
                .renew(Instant::now() + Duration::from_secs(60))
                .await
                .is_err()
        );
        assert!(
            datagrams
                .send_to(b"expired", SocketAddrV4::new(b.binding.virtual_ip, 9000))
                .await
                .is_err()
        );
        b.client.shutdown().await.unwrap();
    })
    .await
    .expect("expiry failed to wake an operation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_handle_drop_stops_actor_and_releases_outer_socket() {
    timeout(Duration::from_secs(3), async {
        let Node {
            client,
            mut resolutions,
            outer,
            ..
        } = node(4).await;
        let datagrams = client.bind_udp(9000).await.unwrap();
        drop(client);
        // A socket handle alone must keep the actor alive.
        datagrams
            .send_to(b"resolve", "10.203.0.250:9000".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            resolutions.recv().await,
            Some(Ipv4Addr::new(10, 203, 0, 250))
        );
        drop(datagrams);
        while resolutions.recv().await.is_some() {}
        // Event-channel closure precedes task-stack teardown by at most one scheduling turn.
        loop {
            match UdpSocket::bind(outer).await {
                Ok(socket) => {
                    drop(socket);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    tokio::task::yield_now().await
                }
                Err(error) => panic!("outer socket rebind failed: {error}"),
            }
        }
    })
    .await
    .expect("actor survived its final application handle");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_tcp_handle_drop_drains_data_before_actor_releases_transport() {
    timeout(Duration::from_secs(8), async {
        let (a, b) = pair().await;
        let mut listener = b.client.listen_tcp(8080).await.unwrap();
        let (outgoing, incoming) = tokio::join!(
            a.client
                .connect(SocketAddrV4::new(b.binding.virtual_ip, 8080)),
            listener.accept()
        );
        let mut outgoing = outgoing.unwrap();
        let (mut incoming, _) = incoming.unwrap();
        let Node {
            client,
            mut resolutions,
            outer,
            ..
        } = a;
        drop(client); // The TCP stream is now the final application owner.
        let payload: Vec<u8> = (0..128 * 1024).map(|i| (i % 241) as u8).collect();
        let ((), received) = tokio::join!(
            async {
                outgoing.write_all(&payload).await.unwrap();
                outgoing.shutdown().await.unwrap();
                drop(outgoing);
            },
            async {
                let mut received = Vec::new();
                incoming.read_to_end(&mut received).await.unwrap();
                incoming.shutdown().await.unwrap();
                received
            }
        );
        assert_eq!(
            received, payload,
            "last-handle drop discarded accepted bytes"
        );
        while resolutions.recv().await.is_some() {}
        loop {
            match UdpSocket::bind(outer).await {
                Ok(socket) => {
                    drop(socket);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    tokio::task::yield_now().await
                }
                Err(error) => panic!("outer socket rebind failed: {error}"),
            }
        }
        b.client.shutdown().await.unwrap();
    })
    .await
    .expect("final TCP handle did not drain and release its actor");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_tcp_writer_does_not_stall_independent_udp() {
    timeout(Duration::from_secs(12), async {
        let (a, b) = pair().await;
        let mut listener = b.client.listen_tcp(8080).await.unwrap();
        let (outgoing, incoming) = tokio::join!(
            a.client
                .connect(SocketAddrV4::new(b.binding.virtual_ip, 8080)),
            listener.accept()
        );
        let mut outgoing = outgoing.unwrap();
        let (mut incoming, _) = incoming.unwrap();
        let au = a.client.bind_udp(9000).await.unwrap();
        let mut bu = b.client.bind_udp(9000).await.unwrap();
        let payload: Vec<u8> = (0..512 * 1024).map(|i| (i % 233) as u8).collect();
        let expected = payload.clone();
        let sender = tokio::spawn(async move {
            outgoing.write_all(&payload).await.unwrap();
            outgoing.shutdown().await.unwrap();
        });
        // Do not consume TCP input yet: all bounded TCP/bridge buffers must fill.
        sleep(Duration::from_millis(200)).await;
        assert!(
            !sender.is_finished(),
            "writer did not encounter bounded backpressure"
        );
        timeout(Duration::from_secs(2), async {
            au.send_to(
                b"independent",
                SocketAddrV4::new(b.binding.virtual_ip, 9000),
            )
            .await
            .unwrap();
            let mut buffer = [0; 32];
            let (n, _) = bu.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..n], b"independent");
        })
        .await
        .expect("blocked TCP writer stalled UDP traffic");
        let mut received = Vec::new();
        incoming.read_to_end(&mut received).await.unwrap();
        sender.await.unwrap();
        assert_eq!(received, expected);
        a.client.shutdown().await.unwrap();
        b.client.shutdown().await.unwrap();
    })
    .await
    .expect("backpressure recovery stalled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_candidate_does_not_stop_valid_path() {
    timeout(Duration::from_secs(5), async {
        let (a, b) = pair().await;
        let mut binding = b.binding.clone();
        binding.candidates.push("[::1]:9".parse().unwrap());
        a.client
            .install_peer(binding, Instant::now() + Duration::from_secs(60))
            .await
            .unwrap();
        let sender = a.client.bind_udp(9000).await.unwrap();
        let mut receiver = b.client.bind_udp(9000).await.unwrap();
        sender
            .send_to(b"valid path", SocketAddrV4::new(b.binding.virtual_ip, 9000))
            .await
            .unwrap();
        let mut buf = [0; 32];
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"valid path");
        // A previously installed path can stay selected until the next 2s probe.
        // Wait for the incompatible candidate to actually be exercised.
        while a.client.stats().await.unwrap().path_send_errors == 0 {
            sleep(Duration::from_millis(20)).await;
        }
        a.client.shutdown().await.unwrap();
        b.client.shutdown().await.unwrap();
    })
    .await
    .expect("unsupported candidate killed valid transport");
}
