//! Connected BEP 15 client sessions. The caller controls destination policy and
//! may cancel operations; connection IDs never leave their source socket.
use std::{collections::HashSet, net::SocketAddr, time::Duration};
use supertrackr_bittorrent::udp;
use tokio::{
    net::UdpSocket,
    time::{Instant, timeout_at},
};

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Protocol(udp::Error),
    Timeout,
}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<udp::Error> for Error {
    fn from(value: udp::Error) -> Self {
        Self::Protocol(value)
    }
}

#[derive(Clone, Copy)]
struct Policy {
    base: Duration,
    attempts: u32,
    lifetime: Duration,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(15),
            attempts: 9,
            lifetime: Duration::from_secs(60),
        }
    }
}
/// A session is bound to the selected address and local source socket. It is
/// deliberately not shared between tracker addresses or concurrent requests.
pub struct Session {
    socket: UdpSocket,
    ipv6: bool,
    connection: [u8; 8],
    received_at: Instant,
    policy: Policy,
}
impl Session {
    /// Resolve a tracker and race a bounded set of addresses. A silent address
    /// must not prevent another address or IP family from being tried.
    pub async fn connect_host(host: &str, port: u16) -> Result<Self, Error> {
        let addresses = tokio::net::lookup_host((host, port)).await?;
        connect_addresses(addresses, Policy::default()).await
    }
    /// Connect using a previously resolved, caller-authorized tracker address.
    pub async fn connect(address: SocketAddr) -> Result<Self, Error> {
        Self::connect_with_policy(address, Policy::default()).await
    }
    async fn connect_with_policy(address: SocketAddr, policy: Policy) -> Result<Self, Error> {
        let address = match address.ip().to_canonical() {
            std::net::IpAddr::V4(ip) if address.is_ipv6() => {
                SocketAddr::new(ip.into(), address.port())
            }
            _ => address,
        };
        let bind = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(address).await?;
        let (connection, received_at, _) = obtain_connection(&socket, policy, 0).await?;
        Ok(Self {
            socket,
            ipv6: address.is_ipv6(),
            connection,
            received_at,
            policy,
        })
    }
    async fn renew_if_needed(&mut self, attempt: &mut u32) -> Result<(), Error> {
        if self.received_at.elapsed() >= self.policy.lifetime {
            let (connection, received_at, used) =
                obtain_connection(&self.socket, self.policy, *attempt).await?;
            self.connection = connection;
            self.received_at = received_at;
            *attempt = used;
        }
        Ok(())
    }
    /// Send a BEP 15 announce and optional BEP 41 path/query data.
    pub async fn announce(
        &mut self,
        request: &udp::Announce,
        url_data: &[u8],
    ) -> Result<udp::AnnounceResponse, Error> {
        let transaction = rand::random();
        // Validate caller input before doing any network work.
        udp::announce_request(self.connection, transaction, request, url_data)?;
        let mut attempt = 0;
        while attempt < self.policy.attempts {
            self.renew_if_needed(&mut attempt).await?;
            let packet = udp::announce_request(self.connection, transaction, request, url_data)?;
            self.socket.send(&packet).await?;
            if let Some(response) = receive(
                &self.socket,
                1,
                transaction,
                self.policy.base * (1 << attempt),
            )
            .await?
            {
                return Ok(udp::announce_response(&response, transaction, self.ipv6)?);
            }
            attempt += 1;
        }
        Err(Error::Timeout)
    }
    /// BEP 15 scrape has no URL-data extension; private tracker authorization
    /// carried only in a URL path/query cannot be assumed to apply to scrapes.
    pub async fn scrape(&mut self, hashes: &[[u8; 20]]) -> Result<Vec<udp::ScrapeCounts>, Error> {
        let transaction = rand::random();
        udp::scrape_request(self.connection, transaction, hashes)?;
        let mut attempt = 0;
        while attempt < self.policy.attempts {
            self.renew_if_needed(&mut attempt).await?;
            let packet = udp::scrape_request(self.connection, transaction, hashes)?;
            self.socket.send(&packet).await?;
            if let Some(response) = receive(
                &self.socket,
                2,
                transaction,
                self.policy.base * (1 << attempt),
            )
            .await?
            {
                return Ok(udp::scrape_response(&response, transaction, hashes.len())?);
            }
            attempt += 1;
        }
        Err(Error::Timeout)
    }
}

async fn connect_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
    policy: Policy,
) -> Result<Session, Error> {
    let mut tasks = tokio::task::JoinSet::new();
    for address in select_addresses(addresses) {
        tasks.spawn(async move { Session::connect_with_policy(address, policy).await });
    }
    let mut last_error = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(session)) => return Ok(session),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                last_error = Some(Error::Io(std::io::Error::other(
                    "tracker connection task failed",
                )))
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no tracker addresses",
        ))
    }))
}

fn select_addresses(addresses: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut families = [0usize; 2];
    let mut selected = Vec::new();
    for address in addresses {
        let address = SocketAddr::new(address.ip().to_canonical(), address.port());
        let family = usize::from(address.is_ipv6());
        if address.port() == 0 || families[family] == 4 || !seen.insert(address) {
            continue;
        }
        families[family] += 1;
        selected.push(address);
        if families == [4, 4] {
            break;
        }
    }
    selected
}
async fn obtain_connection(
    socket: &UdpSocket,
    policy: Policy,
    first_attempt: u32,
) -> Result<([u8; 8], Instant, u32), Error> {
    let transaction = rand::random();
    let packet = udp::connect_request(transaction);
    for attempt in first_attempt..policy.attempts {
        socket.send(&packet).await?;
        if let Some(response) =
            receive(socket, 0, transaction, policy.base * (1 << attempt)).await?
        {
            return Ok((
                udp::connect_response(&response, transaction)?,
                Instant::now(),
                attempt,
            ));
        }
    }
    Err(Error::Timeout)
}
async fn receive(
    socket: &UdpSocket,
    expected_action: u32,
    transaction: u32,
    delay: Duration,
) -> Result<Option<Vec<u8>>, Error> {
    let deadline = Instant::now() + delay;
    let mut buffer = vec![0u8; 65535];
    loop {
        let len = match timeout_at(deadline, socket.recv(&mut buffer)).await {
            Ok(result) => result?,
            Err(_) => return Ok(None),
        };
        if len < 8 {
            continue;
        }
        let action = u32::from_be_bytes(buffer[..4].try_into().unwrap());
        let reply_id = u32::from_be_bytes(buffer[4..8].try_into().unwrap());
        if reply_id != transaction {
            continue;
        }
        if action == 3 {
            return Err(Error::Protocol(udp::Error::TrackerError(
                buffer[8..len].iter().copied().take(512).collect(),
            )));
        }
        if action != expected_action {
            continue;
        }
        buffer.truncate(len);
        return Ok(Some(buffer));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use supertrackr_bittorrent::standard::{Event, PeerId};

    #[test]
    fn address_selection_limits_each_family_and_deduplicates_mapped_ipv4() {
        let addresses = [
            "127.0.0.1:80",
            "[::ffff:127.0.0.1]:80",
            "127.0.0.2:80",
            "127.0.0.3:80",
            "127.0.0.4:80",
            "127.0.0.5:80",
            "[::1]:80",
            "[::2]:80",
            "[::3]:80",
            "[::4]:80",
            "[::5]:80",
        ]
        .map(|address| address.parse().unwrap());
        let selected = select_addresses(addresses);
        assert_eq!(selected.len(), 8);
        assert_eq!(
            selected.iter().filter(|address| address.is_ipv4()).count(),
            4
        );
        assert_eq!(
            selected.iter().filter(|address| address.is_ipv6()).count(),
            4
        );
        assert!(!selected.contains(&"127.0.0.5:80".parse().unwrap()));
        assert!(!selected.contains(&"[::5]:80".parse().unwrap()));
    }

    #[tokio::test]
    async fn silent_address_does_not_block_another_tracker_address() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let good = server.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut packet = [0u8; 16];
            let (len, peer) = server.recv_from(&mut packet).await.unwrap();
            assert_eq!(len, 16);
            let mut response = 0u32.to_be_bytes().to_vec();
            response.extend_from_slice(&packet[12..16]);
            response.extend_from_slice(&[9; 8]);
            server.send_to(&response, peer).await.unwrap();
        });
        let policy = Policy {
            base: Duration::from_secs(15),
            attempts: 9,
            lifetime: Duration::from_secs(60),
        };
        let session = tokio::time::timeout(
            Duration::from_secs(2),
            connect_addresses([silent.local_addr().unwrap(), good], policy),
        )
        .await
        .expect("responsive tracker should win without waiting for retries")
        .unwrap();
        assert_eq!(session.socket.peer_addr().unwrap(), good);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn retries_and_ignores_mismatched_transactions() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let address = match address {
            SocketAddr::V4(v4) => SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port()),
            _ => unreachable!(),
        };
        let task = tokio::spawn(async move {
            let mut packet = [0u8; 2048];
            let (len, peer) = server.recv_from(&mut packet).await.unwrap();
            assert_eq!(len, 16);
            let tx: [u8; 4] = packet[12..16].try_into().unwrap();
            let mut wrong = 0u32.to_be_bytes().to_vec();
            wrong.extend_from_slice(&(u32::from_be_bytes(tx).wrapping_add(1)).to_be_bytes());
            wrong.extend_from_slice(&[7; 8]);
            server.send_to(&wrong, peer).await.unwrap();
            let (len, retried_peer) = server.recv_from(&mut packet).await.unwrap();
            assert_eq!((len, retried_peer), (16, peer));
            assert_eq!(&packet[12..16], &tx);
            let mut response = 0u32.to_be_bytes().to_vec();
            response.extend_from_slice(&tx);
            response.extend_from_slice(&[7; 8]);
            server.send_to(&response, peer).await.unwrap();
            let (len, announce_peer) = server.recv_from(&mut packet).await.unwrap();
            assert_eq!((len, announce_peer), (98, peer));
            assert_eq!(&packet[..8], &[7; 8]);
            let tx = &packet[12..16];
            let mut response = 1u32.to_be_bytes().to_vec();
            response.extend_from_slice(tx);
            response.extend_from_slice(&60u32.to_be_bytes());
            response.extend_from_slice(&1u32.to_be_bytes());
            response.extend_from_slice(&2u32.to_be_bytes());
            response.extend_from_slice(&[127, 0, 0, 1, 0x1a, 0xe1]);
            server.send_to(&response, peer).await.unwrap();
        });
        let policy = Policy {
            base: Duration::from_millis(30),
            attempts: 3,
            lifetime: Duration::from_secs(60),
        };
        let mut session = Session::connect_with_policy(address, policy).await.unwrap();
        let request = udp::Announce {
            info_hash: [1; 20],
            peer_id: PeerId([2; 20]),
            downloaded: 3,
            left: 4,
            uploaded: 5,
            event: Event::Started,
            key: 6,
            numwant: 10,
            port: 6881,
        };
        let response = session.announce(&request, &[]).await.unwrap();
        assert_eq!((response.seeders, response.leechers), (2, 1));
        assert_eq!(response.peers, vec!["127.0.0.1:6881".parse().unwrap()]);
        task.await.unwrap();
    }
    #[tokio::test]
    async fn renewed_connection_uses_current_backoff_attempt() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(server.local_addr().unwrap()).await.unwrap();
        let task = tokio::spawn(async move {
            let mut packet = [0u8; 64];
            let (len, peer) = server.recv_from(&mut packet).await.unwrap();
            assert_eq!(len, 16);
            let tx = packet[12..16].to_vec();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), server.recv_from(&mut packet))
                    .await
                    .is_err()
            );
            let (len, second_peer) =
                tokio::time::timeout(Duration::from_millis(500), server.recv_from(&mut packet))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!((len, second_peer), (16, peer));
            assert_eq!(&packet[12..16], tx);
            let mut response = 0u32.to_be_bytes().to_vec();
            response.extend_from_slice(&tx);
            response.extend_from_slice(&[3; 8]);
            server.send_to(&response, peer).await.unwrap();
        });
        let policy = Policy {
            base: Duration::from_millis(20),
            attempts: 4,
            lifetime: Duration::from_secs(60),
        };
        let (cookie, _, used_attempt) = obtain_connection(&socket, policy, 2).await.unwrap();
        assert_eq!(cookie, [3; 8]);
        assert_eq!(used_attempt, 3);
        task.await.unwrap();
    }
    #[tokio::test]
    async fn expired_connection_is_renewed_on_the_same_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut packet = [0u8; 2048];
            let mut original = None;
            for cookie in [7u8, 8] {
                let (len, peer) = server.recv_from(&mut packet).await.unwrap();
                assert_eq!(len, 16);
                if let Some(old) = original {
                    assert_eq!(peer, old);
                } else {
                    original = Some(peer);
                }
                let mut response = 0u32.to_be_bytes().to_vec();
                response.extend_from_slice(&packet[12..16]);
                response.extend_from_slice(&[cookie; 8]);
                server.send_to(&response, peer).await.unwrap();
            }
            let (len, peer) = server.recv_from(&mut packet).await.unwrap();
            assert_eq!((len, Some(peer)), (36, original));
            assert_eq!(&packet[..8], &[8; 8]);
            let mut response = 2u32.to_be_bytes().to_vec();
            response.extend_from_slice(&packet[12..16]);
            for n in [1u32, 2, 3] {
                response.extend_from_slice(&n.to_be_bytes());
            }
            server.send_to(&response, peer).await.unwrap();
        });
        let policy = Policy {
            base: Duration::from_millis(200),
            attempts: 3,
            lifetime: Duration::from_millis(20),
        };
        let mut session = Session::connect_with_policy(address, policy).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let counts = session.scrape(&[[1; 20]]).await.unwrap();
        assert_eq!(
            counts[0],
            udp::ScrapeCounts {
                seeders: 1,
                downloaded: 2,
                leechers: 3
            }
        );
        task.await.unwrap();
    }
}
