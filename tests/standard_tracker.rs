#![cfg(feature = "bittorrent")]
use serde::Deserialize;
use std::net::SocketAddr;
use supertrackr::standard_tracker::{TrackerState, router};

#[derive(Deserialize)]
struct AnnounceResponse {
    complete: u64,
    incomplete: u64,
    interval: u64,
    peers: serde_bytes::ByteBuf,
    #[serde(default, with = "serde_bytes")]
    peers6: Vec<u8>,
}

#[tokio::test]
async fn ipv6_http_and_udp_return_family_correct_peers() {
    use std::time::Duration;
    use tokio::{net::UdpSocket, time::timeout};
    let state = TrackerState::new();
    let v4 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let v4_address = v4.local_addr().unwrap();
    let v6 = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let v6_address = v6.local_addr().unwrap();
    let app4 = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let app6 = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let server4 = tokio::spawn(async move { axum::serve(v4, app4).await.unwrap() });
    let server6 = tokio::spawn(async move { axum::serve(v6, app6).await.unwrap() });
    let udp = UdpSocket::bind("[::1]:0").await.unwrap();
    let udp_address = udp.local_addr().unwrap();
    let udp_server = tokio::spawn(supertrackr::standard_tracker::serve_udp(udp, state));
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = |address: SocketAddr, id: &str, port: u16| {
        format!(
            "http://{address}/announce?info_hash=abcdefghijklmnopqrst&peer_id={id}&port={port}&uploaded=0&downloaded=0&left=1&compact=1"
        )
    };
    let v4_url = url(v4_address, "11111111111111111111", 6881);
    client
        .get(&v4_url)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    client
        .get(url(v6_address, "22222222222222222222", 6882))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let bytes = client
        .get(&v4_url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let response: AnnounceResponse = serde_bencode::from_bytes(&bytes).unwrap();
    assert_eq!(response.peers6.len(), 18);
    assert_eq!(
        &response.peers6[..16],
        &std::net::Ipv6Addr::LOCALHOST.octets()
    );
    assert_eq!(&response.peers6[16..], &6882u16.to_be_bytes());
    let udp_client = UdpSocket::bind("[::1]:0").await.unwrap();
    let mut buffer = [0u8; 2048];
    let mut connect = 0x41727101980u64.to_be_bytes().to_vec();
    connect.extend_from_slice(&0u32.to_be_bytes());
    connect.extend_from_slice(&21u32.to_be_bytes());
    udp_client.send_to(&connect, udp_address).await.unwrap();
    let (len, _) = timeout(Duration::from_secs(3), udp_client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(len, 16);
    let mut announce = [0u8; 98];
    announce[..8].copy_from_slice(&buffer[8..16]);
    announce[8..12].copy_from_slice(&1u32.to_be_bytes());
    announce[12..16].copy_from_slice(&22u32.to_be_bytes());
    announce[16..36].copy_from_slice(b"abcdefghijklmnopqrst");
    announce[36..56].copy_from_slice(b"33333333333333333333");
    announce[80..84].copy_from_slice(&2u32.to_be_bytes());
    announce[92..96].copy_from_slice(&(-1i32).to_be_bytes());
    announce[96..98].copy_from_slice(&6883u16.to_be_bytes());
    udp_client.send_to(&announce, udp_address).await.unwrap();
    let (len, _) = timeout(Duration::from_secs(3), udp_client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(len, 38, "IPv6 response should contain only the IPv6 peer");
    assert_eq!(&buffer[20..36], &std::net::Ipv6Addr::LOCALHOST.octets());
    assert_eq!(&buffer[36..38], &6882u16.to_be_bytes());
    server4.abort();
    server6.abort();
    udp_server.abort();
}

#[tokio::test]
async fn udp_client_codec_round_trips_against_listener() {
    use std::time::Duration;
    use supertrackr_bittorrent::{
        standard::{Event, PeerId},
        udp,
    };
    use tokio::{net::UdpSocket, time::timeout};
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(supertrackr::standard_tracker::serve_udp(
        socket,
        TrackerState::new(),
    ));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(address).await.unwrap();
    let mut bytes = [0u8; 2048];
    client.send(&udp::connect_request(51)).await.unwrap();
    let len = timeout(Duration::from_secs(3), client.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let connection = udp::connect_response(&bytes[..len], 51).unwrap();
    let announce = udp::Announce {
        info_hash: [7; 20],
        peer_id: PeerId([8; 20]),
        downloaded: 1,
        left: 1,
        uploaded: 2,
        event: Event::Started,
        key: 9,
        numwant: 10,
        port: 6881,
    };
    let packet = udp::announce_request(connection, 52, &announce, b"/announce?test=1").unwrap();
    client.send(&packet).await.unwrap();
    let len = timeout(Duration::from_secs(3), client.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let response = udp::announce_response(&bytes[..len], 52, false).unwrap();
    assert_eq!((response.seeders, response.leechers), (0, 1));
    assert!(response.peers.is_empty());
    client
        .send(&udp::scrape_request(connection, 53, &[[7; 20]]).unwrap())
        .await
        .unwrap();
    let len = timeout(Duration::from_secs(3), client.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let counts = udp::scrape_response(&bytes[..len], 53, 1).unwrap();
    assert_eq!(
        counts[0],
        udp::ScrapeCounts {
            seeders: 0,
            downloaded: 0,
            leechers: 1
        }
    );
    server.abort();
}
#[tokio::test]
async fn http_announces_and_scrapes_using_observed_peer_address() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router(TrackerState::new()).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let announce = |peer: &str, port: u16, left: u64| {
        format!(
            "http://{addr}/announce?info_hash=abcdefghijklmnopqrst&peer_id={peer}&port={port}&uploaded=0&downloaded=0&left={left}&compact=1"
        )
    };
    let first = client
        .get(announce("11111111111111111111", 6881, 1))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let first: AnnounceResponse = serde_bencode::from_bytes(&first).unwrap();
    assert_eq!(
        (first.complete, first.incomplete, first.interval),
        (0, 1, 900)
    );
    let second = client
        .get(announce("22222222222222222222", 6882, 0))
        .header("x-forwarded-for", "203.0.113.77")
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let second: AnnounceResponse = serde_bencode::from_bytes(&second).unwrap();
    assert_eq!((second.complete, second.incomplete), (1, 1));
    assert_eq!(second.peers.as_ref(), &[127, 0, 0, 1, 0x1a, 0xe1]);
    let response = client
        .get(format!(
            "http://{addr}/scrape?info_hash=abcdefghijklmnopqrst"
        ))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let _: serde_bencode::value::Value = serde_bencode::from_bytes(&response).unwrap();
    assert!(response.windows(20).any(|w| w == b"abcdefghijklmnopqrst"));
    server.abort();
}

#[tokio::test]
async fn udp_connection_ids_bind_source_and_support_announce_scrape() {
    use std::time::Duration;
    use tokio::{net::UdpSocket, time::timeout};
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(supertrackr::standard_tracker::serve_udp(
        socket,
        TrackerState::new(),
    ));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0u8; 2048];
    let mut connect = 0x41727101980u64.to_be_bytes().to_vec();
    connect.extend_from_slice(&0u32.to_be_bytes());
    connect.extend_from_slice(&7u32.to_be_bytes());
    client.send_to(&connect, address).await.unwrap();
    let (n, _) = timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 16);
    assert_eq!(&buf[..8], &[0, 0, 0, 0, 0, 0, 0, 7]);
    let id: [u8; 8] = buf[8..16].try_into().unwrap();
    let mut announce = vec![0u8; 98];
    announce[..8].copy_from_slice(&id);
    announce[8..12].copy_from_slice(&1u32.to_be_bytes());
    announce[12..16].copy_from_slice(&8u32.to_be_bytes());
    announce[16..36].copy_from_slice(b"abcdefghijklmnopqrst");
    announce[36..56].copy_from_slice(b"11111111111111111111");
    announce[64..72].copy_from_slice(&1u64.to_be_bytes());
    announce[80..84].copy_from_slice(&2u32.to_be_bytes());
    announce[92..96].copy_from_slice(&(-1i32).to_be_bytes());
    announce[96..98].copy_from_slice(&6881u16.to_be_bytes());
    other.send_to(&announce, address).await.unwrap();
    assert!(
        timeout(Duration::from_millis(100), other.recv_from(&mut buf))
            .await
            .is_err()
    );
    client.send_to(&announce, address).await.unwrap();
    let (n, _) = timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 20);
    assert_eq!(&buf[..8], &[0, 0, 0, 1, 0, 0, 0, 8]);
    assert_eq!(u32::from_be_bytes(buf[12..16].try_into().unwrap()), 1);
    let mut scrape = id.to_vec();
    scrape.extend_from_slice(&2u32.to_be_bytes());
    scrape.extend_from_slice(&9u32.to_be_bytes());
    scrape.extend_from_slice(b"abcdefghijklmnopqrst");
    client.send_to(&scrape, address).await.unwrap();
    let (n, _) = timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 20);
    assert_eq!(&buf[..8], &[0, 0, 0, 2, 0, 0, 0, 9]);
    assert_eq!(u32::from_be_bytes(buf[16..20].try_into().unwrap()), 1);
    task.abort();
}

#[tokio::test]
async fn http_and_udp_share_membership_and_stops() {
    use std::time::Duration;
    use tokio::{net::UdpSocket, time::timeout};
    let state = TrackerState::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_address = listener.local_addr().unwrap();
    let app = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let http_server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_address = udp.local_addr().unwrap();
    let udp_server = tokio::spawn(supertrackr::standard_tracker::serve_udp(udp, state));
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let http_url = format!(
        "http://{http_address}/announce?info_hash=abcdefghijklmnopqrst&peer_id=11111111111111111111&port=6881&uploaded=0&downloaded=0&left=1&compact=1"
    );
    client
        .get(&http_url)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buffer = [0u8; 2048];
    let mut connect = 0x41727101980u64.to_be_bytes().to_vec();
    connect.extend_from_slice(&0u32.to_be_bytes());
    connect.extend_from_slice(&10u32.to_be_bytes());
    udp_client.send_to(&connect, udp_address).await.unwrap();
    let (len, _) = timeout(Duration::from_secs(3), udp_client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(len, 16);
    let mut announce = [0u8; 98];
    announce[..8].copy_from_slice(&buffer[8..16]);
    announce[8..12].copy_from_slice(&1u32.to_be_bytes());
    announce[12..16].copy_from_slice(&11u32.to_be_bytes());
    announce[16..36].copy_from_slice(b"abcdefghijklmnopqrst");
    announce[36..56].copy_from_slice(b"22222222222222222222");
    announce[92..96].copy_from_slice(&(-1i32).to_be_bytes());
    announce[96..98].copy_from_slice(&6882u16.to_be_bytes());
    announce[80..84].copy_from_slice(&99u32.to_be_bytes());
    udp_client.send_to(&announce, udp_address).await.unwrap();
    let (len, _) = timeout(Duration::from_secs(3), udp_client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert!(len >= 8);
    assert_eq!(&buffer[..8], &[0, 0, 0, 3, 0, 0, 0, 11]);
    announce[80..84].copy_from_slice(&2u32.to_be_bytes());
    udp_client.send_to(&announce, udp_address).await.unwrap();
    let (len, _) = timeout(Duration::from_secs(3), udp_client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(len, 26);
    assert_eq!(&buffer[20..26], &[127, 0, 0, 1, 0x1a, 0xe1]);
    let bytes = client
        .get(&http_url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let response: AnnounceResponse = serde_bencode::from_bytes(&bytes).unwrap();
    assert_eq!((response.complete, response.incomplete), (1, 1));
    assert_eq!(response.peers.as_ref(), &[127, 0, 0, 1, 0x1a, 0xe2]);
    announce[80..84].copy_from_slice(&3u32.to_be_bytes());
    udp_client.send_to(&announce, udp_address).await.unwrap();
    timeout(Duration::from_secs(3), udp_client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let bytes = client
        .get(&http_url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let response: AnnounceResponse = serde_bencode::from_bytes(&bytes).unwrap();
    assert_eq!((response.complete, response.incomplete), (0, 1));
    assert!(response.peers.is_empty());
    http_server.abort();
    udp_server.abort();
}
