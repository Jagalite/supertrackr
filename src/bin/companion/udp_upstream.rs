//! Bounded background UDP announces for the loopback tracker bridge.
//! A request can return promptly while the BEP 15 retry schedule continues.
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use supertrackr::udp_tracker::Session;
use supertrackr_bittorrent::{standard::PeerId, udp};
use tokio::{
    sync::{Semaphore, watch},
    task::AbortHandle,
    time::Instant,
};

const MAX_ENTRIES: usize = 256;
const MAX_WORKERS: usize = 4;
const RESULT_LIFETIME: Duration = Duration::from_secs(30);
const SCRAPE_RESULT_LIFETIME: Duration = Duration::from_secs(300);
const WORK_LIFETIME: Duration = Duration::from_secs(300);
type Key = ([u8; 20], PeerId);

pub fn valid_url(url: &reqwest::Url) -> bool {
    url.scheme() == "udp"
        && url.host_str().is_some()
        && url.port().is_some_and(|port| port != 0)
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url
            .path()
            .len()
            .saturating_add(url.query().map_or(0, |query| 1 + query.len()))
            <= 1024
}

#[derive(Clone)]
enum State {
    Pending,
    Done(Option<udp::AnnounceResponse>, Instant),
}
struct Entry {
    request: udp::Announce,
    state: watch::Receiver<State>,
    task: AbortHandle,
    previous: Option<(udp::AnnounceResponse, Instant)>,
}
fn fresh(response: &udp::AnnounceResponse, completed: Instant) -> bool {
    completed.elapsed() < Duration::from_secs((u64::from(response.interval).max(60) * 2).min(3600))
}
fn reusable(entry: &Entry) -> bool {
    match &*entry.state.borrow() {
        State::Pending => true,
        State::Done(Some(response), completed) => {
            completed.elapsed() < Duration::from_secs(u64::from(response.interval).clamp(1, 3600))
        }
        State::Done(None, completed) => completed.elapsed() < RESULT_LIFETIME,
    }
}
#[derive(Clone)]
enum ScrapeState {
    Pending,
    Done(Option<Vec<udp::ScrapeCounts>>, Instant),
}
struct ScrapeEntry {
    state: watch::Receiver<ScrapeState>,
    task: AbortHandle,
    previous: Option<(Vec<udp::ScrapeCounts>, Instant)>,
}
fn reusable_scrape(entry: &ScrapeEntry) -> bool {
    match &*entry.state.borrow() {
        ScrapeState::Pending => true,
        ScrapeState::Done(_, completed) => completed.elapsed() < RESULT_LIFETIME,
    }
}
impl Drop for ScrapeEntry {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub struct Announcements {
    entries: Mutex<HashMap<Key, Entry>>,
    scrapes: Mutex<HashMap<Vec<[u8; 20]>, ScrapeEntry>>,
    workers: Arc<Semaphore>,
    stop_workers: Arc<Semaphore>,
    secret: [u8; 32],
}
impl Announcements {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            scrapes: Mutex::new(HashMap::new()),
            workers: Arc::new(Semaphore::new(MAX_WORKERS)),
            stop_workers: Arc::new(Semaphore::new(1)),
            secret: rand::random(),
        }
    }

    pub fn key(&self, hash: &[u8; 20], peer: PeerId) -> u32 {
        let digest = Sha256::new()
            .chain_update(self.secret)
            .chain_update(hash)
            .chain_update(peer.0)
            .finalize();
        u32::from_be_bytes(digest[..4].try_into().unwrap())
    }

    /// BEP 15 has no URL-data extension for scrape. Refuse paths or queries
    /// that could carry private-tracker authorization rather than dropping it.
    pub async fn scrape(
        &self,
        url: &reqwest::Url,
        hashes: Vec<[u8; 20]>,
    ) -> Option<Vec<udp::ScrapeCounts>> {
        if !valid_url(url)
            || url.query().is_some()
            || !matches!(url.path(), "" | "/" | "/announce")
            || hashes.is_empty()
            || hashes.len() > 32
        {
            return None;
        }
        let (mut receiver, previous) = {
            let mut entries = self.scrapes.lock().ok()?;
            entries.retain(|_, entry| {
                reusable_scrape(entry)
                    || matches!(&*entry.state.borrow(), ScrapeState::Done(Some(_), completed) if completed.elapsed() < SCRAPE_RESULT_LIFETIME)
                    || entry.previous.as_ref().is_some_and(|(_, completed)| completed.elapsed() < SCRAPE_RESULT_LIFETIME)
            });
            let previous = entries
                .get(&hashes)
                .and_then(|entry| match &*entry.state.borrow() {
                    ScrapeState::Done(Some(result), completed)
                        if completed.elapsed() < SCRAPE_RESULT_LIFETIME =>
                    {
                        Some((result.clone(), *completed))
                    }
                    _ => entry
                        .previous
                        .clone()
                        .filter(|(_, completed)| completed.elapsed() < SCRAPE_RESULT_LIFETIME),
                });
            if entries.get(&hashes).is_some_and(reusable_scrape) {
                (entries.get(&hashes)?.state.clone(), previous)
            } else {
                entries.remove(&hashes);
                if entries.len() >= 64 {
                    let oldest = entries
                        .iter()
                        .filter_map(|(key, entry)| match &*entry.state.borrow() {
                            ScrapeState::Done(_, completed) => Some((key.clone(), *completed)),
                            ScrapeState::Pending => None,
                        })
                        .min_by_key(|(_, completed)| *completed)
                        .map(|(key, _)| key);
                    entries.remove(&oldest?);
                }
                let host = url
                    .host_str()?
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned();
                let port = url.port()?;
                let workers = self.workers.clone();
                let (sender, state) = watch::channel(ScrapeState::Pending);
                let work = hashes.clone();
                let task = tokio::spawn(async move {
                    let Ok(_permit) = workers.acquire_owned().await else {
                        return;
                    };
                    let result = tokio::time::timeout(WORK_LIFETIME, async {
                        let mut session = Session::connect_host(&host, port).await.ok()?;
                        session.scrape(&work).await.ok()
                    })
                    .await
                    .ok()
                    .flatten();
                    let _ = sender.send(ScrapeState::Done(result, Instant::now()));
                });
                let receiver = state.clone();
                entries.insert(
                    hashes,
                    ScrapeEntry {
                        state,
                        task: task.abort_handle(),
                        previous: previous.clone(),
                    },
                );
                (receiver, previous)
            }
        };
        tokio::time::timeout(Duration::from_millis(1500), async {
            loop {
                match receiver.borrow_and_update().clone() {
                    ScrapeState::Done(result, _) => return result,
                    ScrapeState::Pending => {}
                }
                if receiver.changed().await.is_err() {
                    return None;
                }
            }
        })
        .await
        .ok()
        .flatten()
        .or_else(|| {
            previous
                .filter(|(_, completed)| completed.elapsed() < SCRAPE_RESULT_LIFETIME)
                .map(|(result, _)| result)
        })
    }

    /// Returns a shared result for identical announces, or starts a bounded job.
    /// Replacing a request cancels its retry task and isolates its result channel.
    pub async fn announce(
        &self,
        url: &reqwest::Url,
        request: udp::Announce,
    ) -> Option<udp::AnnounceResponse> {
        if !valid_url(url) {
            return None;
        }
        let key = (request.info_hash, request.peer_id);
        let (mut receiver, previous) = {
            let mut entries = self.entries.lock().ok()?;
            entries.retain(|_, entry| {
                reusable(entry)
                    || matches!(&*entry.state.borrow(), State::Done(Some(response), completed) if fresh(response, *completed))
                    || entry.previous.as_ref().is_some_and(|(response, completed)| fresh(response, *completed))
            });
            let previous = entries.get(&key).and_then(|entry| {
                if request.event == supertrackr_bittorrent::standard::Event::Stopped
                    || entry.request.event == supertrackr_bittorrent::standard::Event::Stopped
                {
                    return None;
                }
                match &*entry.state.borrow() {
                    State::Done(Some(response), completed) if fresh(response, *completed) => {
                        Some((response.clone(), *completed))
                    }
                    _ => entry
                        .previous
                        .clone()
                        .filter(|(response, completed)| fresh(response, *completed)),
                }
            });
            if let Some(entry) = entries.get(&key) {
                if entry.request == request && reusable(entry) {
                    Some((entry.state.clone(), previous.clone()))
                } else {
                    entries.remove(&key);
                    None
                }
            } else {
                None
            }
            .or_else(|| {
                let stopped = request.event == supertrackr_bittorrent::standard::Event::Stopped;
                let limit = MAX_ENTRIES + if stopped { 8 } else { 0 };
                if entries.len() >= limit {
                    let oldest = entries
                        .iter()
                        .filter_map(|(key, entry)| match &*entry.state.borrow() {
                            State::Done(_, completed) => Some((*key, *completed)),
                            State::Pending => None,
                        })
                        .min_by_key(|(_, completed)| *completed)
                        .map(|(key, _)| key);
                    entries.remove(&oldest?);
                    if entries.len() >= limit {
                        return None;
                    }
                }
                let workers = if stopped {
                    self.stop_workers.clone()
                } else {
                    self.workers.clone()
                };
                let host = url
                    .host_str()?
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned();
                let port = url.port()?;
                let mut url_data = url.path().as_bytes().to_vec();
                if let Some(query) = url.query() {
                    url_data.push(b'?');
                    url_data.extend_from_slice(query.as_bytes());
                }
                let (sender, state) = watch::channel(State::Pending);
                let work = request.clone();
                let task = tokio::spawn(async move {
                    let Ok(_permit) = workers.acquire_owned().await else {
                        return;
                    };
                    let response = tokio::time::timeout(WORK_LIFETIME, async {
                        let mut session = Session::connect_host(&host, port).await.ok()?;
                        session.announce(&work, &url_data).await.ok()
                    })
                    .await
                    .ok()
                    .flatten();
                    let _ = sender.send(State::Done(response, Instant::now()));
                });
                let receiver = state.clone();
                entries.insert(
                    key,
                    Entry {
                        request,
                        state,
                        task: task.abort_handle(),
                        previous: previous.clone(),
                    },
                );
                Some((receiver, previous))
            })?
        };
        tokio::time::timeout(Duration::from_millis(1500), async {
            loop {
                match receiver.borrow_and_update().clone() {
                    State::Done(response, _) => return response,
                    State::Pending => {}
                }
                if receiver.changed().await.is_err() {
                    return None;
                }
            }
        })
        .await
        .ok()
        .flatten()
        .or_else(|| {
            previous
                .filter(|(response, completed)| fresh(response, *completed))
                .map(|(response, _)| response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use supertrackr_bittorrent::standard::Event;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn announce_waits_in_queue_and_runs_after_worker_is_released() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let url: reqwest::Url = format!("udp://{}/announce", socket.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            let mut packet = [0u8; 256];
            let (_, peer) = socket.recv_from(&mut packet).await.unwrap();
            let mut connect = 0u32.to_be_bytes().to_vec();
            connect.extend_from_slice(&packet[12..16]);
            connect.extend_from_slice(&[1; 8]);
            socket.send_to(&connect, peer).await.unwrap();
            let (_, peer) = socket.recv_from(&mut packet).await.unwrap();
            let mut response = 1u32.to_be_bytes().to_vec();
            response.extend_from_slice(&packet[12..16]);
            for value in [60u32, 1, 2] {
                response.extend_from_slice(&value.to_be_bytes());
            }
            socket.send_to(&response, peer).await.unwrap();
        });
        let manager = Announcements::new();
        let held = manager
            .workers
            .clone()
            .acquire_many_owned(MAX_WORKERS as u32)
            .await
            .unwrap();
        let request = udp::Announce {
            info_hash: [1; 20],
            peer_id: PeerId([2; 20]),
            downloaded: 0,
            left: 1,
            uploaded: 0,
            event: Event::Started,
            key: 42,
            numwant: 50,
            port: 6881,
        };
        assert!(manager.announce(&url, request.clone()).await.is_none());
        drop(held);
        let response = manager.announce(&url, request).await.unwrap();
        assert_eq!((response.seeders, response.leechers), (2, 1));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn completed_scrape_cache_entries_do_not_block_new_hashes() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let url: reqwest::Url = format!("udp://{}/announce", socket.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            let mut packet = [0u8; 256];
            let (_, peer) = socket.recv_from(&mut packet).await.unwrap();
            let mut connect = 0u32.to_be_bytes().to_vec();
            connect.extend_from_slice(&packet[12..16]);
            connect.extend_from_slice(&[1; 8]);
            socket.send_to(&connect, peer).await.unwrap();
            let (_, peer) = socket.recv_from(&mut packet).await.unwrap();
            let mut response = 2u32.to_be_bytes().to_vec();
            response.extend_from_slice(&packet[12..16]);
            for value in [7u32, 8, 9] {
                response.extend_from_slice(&value.to_be_bytes());
            }
            socket.send_to(&response, peer).await.unwrap();
        });
        let manager = Announcements::new();
        for index in 0..64u8 {
            let (_sender, state) = watch::channel(ScrapeState::Done(Some(vec![]), Instant::now()));
            let task = tokio::spawn(std::future::pending::<()>());
            manager.scrapes.lock().unwrap().insert(
                vec![[index; 20]],
                ScrapeEntry {
                    state,
                    task: task.abort_handle(),
                    previous: None,
                },
            );
        }
        let result = manager.scrape(&url, vec![[255; 20]]).await.unwrap();
        assert_eq!(result[0].seeders, 7);
        assert_eq!(manager.scrapes.lock().unwrap().len(), 64);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn stop_has_capacity_when_regular_workers_are_busy() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let url: reqwest::Url = format!("udp://{}/announce", socket.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            let mut packet = [0u8; 256];
            let (_, peer) = socket.recv_from(&mut packet).await.unwrap();
            let mut connect = 0u32.to_be_bytes().to_vec();
            connect.extend_from_slice(&packet[12..16]);
            connect.extend_from_slice(&[1; 8]);
            socket.send_to(&connect, peer).await.unwrap();
            let (_, peer) = socket.recv_from(&mut packet).await.unwrap();
            assert_eq!(u32::from_be_bytes(packet[80..84].try_into().unwrap()), 3);
            let mut response = 1u32.to_be_bytes().to_vec();
            response.extend_from_slice(&packet[12..16]);
            for value in [60u32, 0, 0] {
                response.extend_from_slice(&value.to_be_bytes());
            }
            socket.send_to(&response, peer).await.unwrap();
        });
        let manager = Announcements::new();
        let _busy = manager
            .workers
            .clone()
            .acquire_many_owned(MAX_WORKERS as u32)
            .await
            .unwrap();
        let request = udp::Announce {
            info_hash: [1; 20],
            peer_id: PeerId([2; 20]),
            downloaded: 0,
            left: 1,
            uploaded: 0,
            event: Event::Stopped,
            key: 42,
            numwant: 0,
            port: 6881,
        };
        assert!(manager.announce(&url, request).await.is_some());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn older_scrape_is_refreshed_before_fallback_expires() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let url: reqwest::Url = format!("udp://{}/announce", socket.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            let mut packet = [0u8; 256];
            let (_, peer) = socket.recv_from(&mut packet).await.unwrap();
            let mut connect = 0u32.to_be_bytes().to_vec();
            connect.extend_from_slice(&packet[12..16]);
            connect.extend_from_slice(&[1; 8]);
            socket.send_to(&connect, peer).await.unwrap();
            let (len, peer) = socket.recv_from(&mut packet).await.unwrap();
            assert_eq!(len, 36);
            let mut response = 2u32.to_be_bytes().to_vec();
            response.extend_from_slice(&packet[12..16]);
            for value in [7u32, 8, 9] {
                response.extend_from_slice(&value.to_be_bytes());
            }
            socket.send_to(&response, peer).await.unwrap();
        });
        let manager = Announcements::new();
        let old = Instant::now() - Duration::from_secs(31);
        let stale = vec![udp::ScrapeCounts {
            seeders: 1,
            downloaded: 2,
            leechers: 3,
        }];
        let (_sender, state) = watch::channel(ScrapeState::Done(Some(stale), old));
        let task = tokio::spawn(std::future::pending::<()>());
        manager.scrapes.lock().unwrap().insert(
            vec![[1; 20]],
            ScrapeEntry {
                state,
                task: task.abort_handle(),
                previous: None,
            },
        );
        let counts = manager.scrape(&url, vec![[1; 20]]).await.unwrap();
        assert_eq!(
            (counts[0].seeders, counts[0].downloaded, counts[0].leechers),
            (7, 8, 9)
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_ipv6_tracker_returns_ipv6_peers() {
        let socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let url: reqwest::Url = format!("udp://{}/announce", socket.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            let mut packet = [0u8; 2048];
            let (_, peer) = socket.recv_from(&mut packet).await.unwrap();
            let mut connect = 0u32.to_be_bytes().to_vec();
            connect.extend_from_slice(&packet[12..16]);
            connect.extend_from_slice(&[1; 8]);
            socket.send_to(&connect, peer).await.unwrap();
            let (_, peer) = socket.recv_from(&mut packet).await.unwrap();
            let mut response = 1u32.to_be_bytes().to_vec();
            response.extend_from_slice(&packet[12..16]);
            for value in [60u32, 1, 2] {
                response.extend_from_slice(&value.to_be_bytes());
            }
            response.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
            response.extend_from_slice(&6881u16.to_be_bytes());
            socket.send_to(&response, peer).await.unwrap();
        });
        let manager = Announcements::new();
        let request = udp::Announce {
            info_hash: [1; 20],
            peer_id: PeerId([2; 20]),
            downloaded: 0,
            left: 1,
            uploaded: 0,
            event: Event::Started,
            key: 42,
            numwant: 50,
            port: 6881,
        };
        let response = manager.announce(&url, request).await.unwrap();
        assert_eq!(response.peers, vec!["[::1]:6881".parse().unwrap()]);
        server.await.unwrap();
    }

    #[test]
    fn validates_udp_destination_and_bep41_length() {
        for (url, expected) in [
            ("udp://tracker.example:80/announce?passkey=secret", true),
            ("udp://[::1]:80/announce", true),
            ("udp://tracker.example/announce", false),
            ("udp://tracker.example:0/announce", false),
            ("udp://user:secret@tracker.example:80/announce", false),
            ("udp://tracker.example:80/announce#fragment", false),
            ("http://tracker.example:80/announce", false),
        ] {
            assert_eq!(valid_url(&url.parse().unwrap()), expected, "{url}");
        }
        let long: reqwest::Url = format!("udp://tracker.example:80/{}", "a".repeat(1024))
            .parse()
            .unwrap();
        assert!(!valid_url(&long));
    }

    #[tokio::test]
    async fn failed_refresh_keeps_fallback_and_expired_success_is_refreshed() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let url: reqwest::Url = format!("udp://{}/announce", socket.local_addr().unwrap())
            .parse()
            .unwrap();
        let manager = Announcements::new();
        let response = udp::AnnounceResponse {
            interval: 60,
            leechers: 1,
            seeders: 2,
            peers: vec![],
            trailing_bytes: vec![],
        };
        let request = udp::Announce {
            info_hash: [1; 20],
            peer_id: PeerId([2; 20]),
            downloaded: 0,
            left: 1,
            uploaded: 0,
            event: Event::Update,
            key: 42,
            numwant: 50,
            port: 6881,
        };
        for failed in [true, false] {
            let old = Instant::now() - Duration::from_secs(if failed { 31 } else { 61 });
            let state = if failed {
                State::Done(None, old)
            } else {
                State::Done(Some(response.clone()), old)
            };
            let (_sender, receiver) = watch::channel(state);
            let task = tokio::spawn(std::future::pending::<()>());
            manager.entries.lock().unwrap().insert(
                (request.info_hash, request.peer_id),
                Entry {
                    request: request.clone(),
                    state: receiver,
                    task: task.abort_handle(),
                    previous: failed.then(|| (response.clone(), old)),
                },
            );
            let result = manager.announce(&url, request.clone()).await;
            assert_eq!(result, Some(response.clone()));
            let mut packet = [0u8; 64];
            let (length, _) =
                tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut packet))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(length, 16, "a new connect request must be sent");
        }
    }

    #[test]
    fn cached_announce_survives_a_normal_tracker_interval_but_expires() {
        let response = udp::AnnounceResponse {
            interval: 120,
            leechers: 0,
            seeders: 0,
            peers: vec![],
            trailing_bytes: vec![],
        };
        let now = Instant::now();
        assert!(fresh(&response, now - Duration::from_secs(120)));
        assert!(!fresh(&response, now - Duration::from_secs(241)));
        let very_long = udp::AnnounceResponse {
            interval: u32::MAX,
            ..response
        };
        assert!(!fresh(&very_long, now - Duration::from_secs(3601)));
    }

    #[tokio::test]
    async fn changed_counters_can_use_previous_result_while_refresh_retries() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let url: reqwest::Url = format!("udp://{}/announce", socket.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            let mut bytes = [0u8; 2048];
            for reply in [true, false] {
                let (_, peer) = socket.recv_from(&mut bytes).await.unwrap();
                let mut connect = 0u32.to_be_bytes().to_vec();
                connect.extend_from_slice(&bytes[12..16]);
                connect.extend_from_slice(&[1; 8]);
                socket.send_to(&connect, peer).await.unwrap();
                let (_, peer) = socket.recv_from(&mut bytes).await.unwrap();
                if reply {
                    let mut response = 1u32.to_be_bytes().to_vec();
                    response.extend_from_slice(&bytes[12..16]);
                    for value in [120u32, 1, 2] {
                        response.extend_from_slice(&value.to_be_bytes());
                    }
                    socket.send_to(&response, peer).await.unwrap();
                } else {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        });
        let manager = Announcements::new();
        let mut request = udp::Announce {
            info_hash: [1; 20],
            peer_id: PeerId([2; 20]),
            downloaded: 0,
            left: 1,
            uploaded: 0,
            event: Event::Started,
            key: 42,
            numwant: 50,
            port: 6881,
        };
        let first = manager.announce(&url, request.clone()).await.unwrap();
        request.downloaded = 1;
        request.event = Event::Update;
        assert_eq!(manager.announce(&url, request).await, Some(first));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn stop_supersedes_an_unanswered_announce() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let url: reqwest::Url = format!("udp://{}/announce", socket.local_addr().unwrap())
            .parse()
            .unwrap();
        let (seen, ready) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut bytes = [0u8; 2048];
            let mut seen = Some(seen);
            for event in [2u32, 3] {
                let (_, peer) = socket.recv_from(&mut bytes).await.unwrap();
                let mut connect = 0u32.to_be_bytes().to_vec();
                connect.extend_from_slice(&bytes[12..16]);
                connect.extend_from_slice(&[1; 8]);
                socket.send_to(&connect, peer).await.unwrap();
                let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
                assert!(len >= 98);
                assert_eq!(u32::from_be_bytes(bytes[80..84].try_into().unwrap()), event);
                if let Some(seen) = seen.take() {
                    seen.send(()).unwrap();
                } else {
                    let mut response = 1u32.to_be_bytes().to_vec();
                    response.extend_from_slice(&bytes[12..16]);
                    for value in [60u32, 0, 0] {
                        response.extend_from_slice(&value.to_be_bytes());
                    }
                    socket.send_to(&response, peer).await.unwrap();
                }
            }
        });
        let manager = Arc::new(Announcements::new());
        let request = udp::Announce {
            info_hash: [1; 20],
            peer_id: PeerId([2; 20]),
            downloaded: 0,
            left: 1,
            uploaded: 0,
            event: Event::Started,
            key: 42,
            numwant: 50,
            port: 6881,
        };
        let first_manager = manager.clone();
        let first_url = url.clone();
        let first_request = request.clone();
        let first =
            tokio::spawn(async move { first_manager.announce(&first_url, first_request).await });
        tokio::time::timeout(Duration::from_secs(2), ready)
            .await
            .unwrap()
            .unwrap();
        let mut stopped = request;
        stopped.event = Event::Stopped;
        assert!(manager.announce(&url, stopped).await.is_some());
        assert!(first.await.unwrap().is_none());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn scrape_uses_udp_and_does_not_drop_url_credentials() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let url: reqwest::Url = format!("udp://{}/announce", socket.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            let mut bytes = [0u8; 2048];
            let (_, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let mut connect = 0u32.to_be_bytes().to_vec();
            connect.extend_from_slice(&bytes[12..16]);
            connect.extend_from_slice(&[1; 8]);
            socket.send_to(&connect, peer).await.unwrap();
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            assert_eq!(len, 56);
            assert_eq!(&bytes[16..36], &[1; 20]);
            assert_eq!(&bytes[36..len], &[2; 20]);
            let mut scrape = 2u32.to_be_bytes().to_vec();
            scrape.extend_from_slice(&bytes[12..16]);
            for count in [1u32, 2, 3, 4, 5, 6] {
                scrape.extend_from_slice(&count.to_be_bytes());
            }
            socket.send_to(&scrape, peer).await.unwrap();
        });
        let manager = Announcements::new();
        let counts = manager.scrape(&url, vec![[1; 20], [2; 20]]).await.unwrap();
        assert_eq!((counts[0].seeders, counts[1].downloaded), (1, 5));
        server.await.unwrap();
        let mut private = url.clone();
        private.set_query(Some("passkey=secret"));
        assert!(manager.scrape(&private, vec![[1; 20]]).await.is_none());
    }

    #[tokio::test]
    async fn repeated_announce_reuses_completed_response() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let url = format!("udp://{}/announce", socket.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            let mut bytes = [0u8; 2048];
            let (size, peer) = socket.recv_from(&mut bytes).await.unwrap();
            assert_eq!(size, 16);
            let mut connect = 0u32.to_be_bytes().to_vec();
            connect.extend_from_slice(&bytes[12..16]);
            connect.extend_from_slice(&[1; 8]);
            socket.send_to(&connect, peer).await.unwrap();
            let (size, peer) = socket.recv_from(&mut bytes).await.unwrap();
            assert!(size >= 98);
            assert_eq!(&bytes[98..size], b"\x02\x09/announce");
            let mut announce = 1u32.to_be_bytes().to_vec();
            announce.extend_from_slice(&bytes[12..16]);
            announce.extend_from_slice(&60u32.to_be_bytes());
            announce.extend_from_slice(&1u32.to_be_bytes());
            announce.extend_from_slice(&2u32.to_be_bytes());
            socket.send_to(&announce, peer).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(150), socket.recv_from(&mut bytes))
                    .await
                    .is_err()
            );
        });
        let manager = Announcements::new();
        let request = udp::Announce {
            info_hash: [1; 20],
            peer_id: PeerId([2; 20]),
            downloaded: 0,
            left: 1,
            uploaded: 0,
            event: Event::Started,
            key: 42,
            numwant: 50,
            port: 6881,
        };
        let first = manager.announce(&url, request.clone()).await.unwrap();
        let second = manager.announce(&url, request).await.unwrap();
        assert_eq!(first, second);
        assert_eq!((first.seeders, first.leechers), (2, 1));
        server.await.unwrap();
    }
}
