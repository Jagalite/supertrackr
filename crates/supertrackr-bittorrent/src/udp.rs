//! BEP 15 request and response encoding; networking and retransmission are caller-owned.
use crate::standard::{Event, PeerId};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const PROTOCOL_ID: u64 = 0x41727101980;
const MAX_HASHES: usize = 32;
const MAX_PEERS: usize = 200;
const MAX_URL_DATA: usize = 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    InvalidResponse,
    WrongTransaction,
    /// Raw tracker message, capped at 512 bytes; callers decide how to display it.
    TrackerError(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announce {
    pub info_hash: [u8; 20],
    pub peer_id: PeerId,
    pub downloaded: u64,
    pub left: u64,
    pub uploaded: u64,
    pub event: Event,
    pub key: u32,
    pub numwant: i32,
    pub port: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnounceResponse {
    pub interval: u32,
    pub leechers: u32,
    pub seeders: u32,
    pub peers: Vec<SocketAddr>,
    /// Bytes shorter than one peer record, which may be a future extension.
    pub trailing_bytes: Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScrapeCounts {
    pub seeders: u32,
    pub downloaded: u32,
    pub leechers: u32,
}

pub fn connect_request(transaction: u32) -> [u8; 16] {
    let mut result = [0; 16];
    result[..8].copy_from_slice(&PROTOCOL_ID.to_be_bytes());
    result[12..].copy_from_slice(&transaction.to_be_bytes());
    result
}
fn response_header(packet: &[u8], action: u32, transaction: u32) -> Result<(), Error> {
    if packet.len() < 8 {
        return Err(Error::InvalidResponse);
    }
    let received_action = u32::from_be_bytes(packet[..4].try_into().unwrap());
    if u32::from_be_bytes(packet[4..8].try_into().unwrap()) != transaction {
        return Err(Error::WrongTransaction);
    }
    if received_action == 3 {
        return Err(Error::TrackerError(
            packet[8..].iter().copied().take(512).collect(),
        ));
    }
    if received_action != action {
        return Err(Error::InvalidResponse);
    }
    Ok(())
}
pub fn connect_response(packet: &[u8], transaction: u32) -> Result<[u8; 8], Error> {
    response_header(packet, 0, transaction)?;
    if packet.len() < 16 {
        return Err(Error::InvalidResponse);
    }
    Ok(packet[8..16].try_into().unwrap())
}
/// URL data contains the configured URL path and query, not client announce fields.
/// BEP 41 permits this extension only on announces; it does not authenticate scrapes.
pub fn announce_request(
    connection: [u8; 8],
    transaction: u32,
    announce: &Announce,
    url_data: &[u8],
) -> Result<Vec<u8>, Error> {
    if announce.port == 0 || url_data.len() > MAX_URL_DATA || announce.numwant < -1 {
        return Err(Error::InvalidInput);
    }
    let mut packet = Vec::with_capacity(98 + url_data.len() + 10);
    packet.extend_from_slice(&connection);
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.extend_from_slice(&transaction.to_be_bytes());
    packet.extend_from_slice(&announce.info_hash);
    packet.extend_from_slice(&announce.peer_id.0);
    packet.extend_from_slice(&announce.downloaded.to_be_bytes());
    packet.extend_from_slice(&announce.left.to_be_bytes());
    packet.extend_from_slice(&announce.uploaded.to_be_bytes());
    let event: u32 = match announce.event {
        Event::Update => 0,
        Event::Completed => 1,
        Event::Started => 2,
        Event::Stopped => 3,
    };
    packet.extend_from_slice(&event.to_be_bytes());
    packet.extend_from_slice(&0u32.to_be_bytes()); // tracker observes source IP
    packet.extend_from_slice(&announce.key.to_be_bytes());
    packet.extend_from_slice(&announce.numwant.to_be_bytes());
    packet.extend_from_slice(&announce.port.to_be_bytes());
    if !url_data.is_empty() {
        for part in url_data.chunks(255) {
            packet.push(2);
            packet.push(part.len() as u8);
            packet.extend_from_slice(part);
        }
    }
    Ok(packet)
}
/// BEP 15 does not frame announce extensions separately from peer records.
/// Complete strides are decoded as peers; an incomplete trailing stride is
/// exposed to the caller. Callers must validate each returned address.
pub fn announce_response(
    packet: &[u8],
    transaction: u32,
    ipv6: bool,
) -> Result<AnnounceResponse, Error> {
    response_header(packet, 1, transaction)?;
    if packet.len() < 20 {
        return Err(Error::InvalidResponse);
    }
    let stride = if ipv6 { 18 } else { 6 };
    let bytes = &packet[20..];
    let mut peers = Vec::with_capacity((bytes.len() / stride).min(MAX_PEERS));
    for peer in bytes.chunks_exact(stride).take(MAX_PEERS) {
        let (ip, offset) = if ipv6 {
            (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&peer[..16]).unwrap())),
                16,
            )
        } else {
            (
                IpAddr::V4(Ipv4Addr::new(peer[0], peer[1], peer[2], peer[3])),
                4,
            )
        };
        peers.push(SocketAddr::new(
            ip,
            u16::from_be_bytes([peer[offset], peer[offset + 1]]),
        ));
    }
    Ok(AnnounceResponse {
        interval: u32::from_be_bytes(packet[8..12].try_into().unwrap()),
        leechers: u32::from_be_bytes(packet[12..16].try_into().unwrap()),
        seeders: u32::from_be_bytes(packet[16..20].try_into().unwrap()),
        peers,
        trailing_bytes: bytes[bytes.len() - bytes.len() % stride..].to_vec(),
    })
}
pub fn scrape_request(
    connection: [u8; 8],
    transaction: u32,
    hashes: &[[u8; 20]],
) -> Result<Vec<u8>, Error> {
    if hashes.is_empty() || hashes.len() > MAX_HASHES {
        return Err(Error::InvalidInput);
    }
    let mut packet = Vec::with_capacity(16 + 20 * hashes.len());
    packet.extend_from_slice(&connection);
    packet.extend_from_slice(&2u32.to_be_bytes());
    packet.extend_from_slice(&transaction.to_be_bytes());
    for hash in hashes {
        packet.extend_from_slice(hash);
    }
    Ok(packet)
}
pub fn scrape_response(
    packet: &[u8],
    transaction: u32,
    expected: usize,
) -> Result<Vec<ScrapeCounts>, Error> {
    if expected == 0 || expected > MAX_HASHES {
        return Err(Error::InvalidInput);
    }
    response_header(packet, 2, transaction)?;
    if packet.len() < 8 + expected * 12 {
        return Err(Error::InvalidResponse);
    }
    Ok(packet[8..8 + expected * 12]
        .as_chunks::<12>()
        .0
        .iter()
        .map(|row| ScrapeCounts {
            seeders: u32::from_be_bytes(row[..4].try_into().unwrap()),
            downloaded: u32::from_be_bytes(row[4..8].try_into().unwrap()),
            leechers: u32::from_be_bytes(row[8..12].try_into().unwrap()),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn announce_layout_and_bep41_url_chunks() {
        let data = vec![b'x'; 300];
        let input = Announce {
            info_hash: [1; 20],
            peer_id: PeerId([2; 20]),
            downloaded: 3,
            left: 4,
            uploaded: 5,
            event: Event::Completed,
            key: 6,
            numwant: -1,
            port: 6881,
        };
        let packet = announce_request([9; 8], 42, &input, &data).unwrap();
        assert_eq!(&packet[..8], &[9; 8]);
        assert_eq!(&packet[8..16], &[0, 0, 0, 1, 0, 0, 0, 42]);
        assert_eq!(&packet[16..36], &[1; 20]);
        assert_eq!(&packet[36..56], &[2; 20]);
        assert_eq!(&packet[56..64], &3u64.to_be_bytes());
        assert_eq!(&packet[64..72], &4u64.to_be_bytes());
        assert_eq!(&packet[72..80], &5u64.to_be_bytes());
        assert_eq!(&packet[80..84], &1u32.to_be_bytes());
        assert_eq!(&packet[84..88], &[0; 4]);
        assert_eq!(&packet[88..92], &6u32.to_be_bytes());
        assert_eq!(&packet[92..96], &(-1i32).to_be_bytes());
        assert_eq!(&packet[96..98], &6881u16.to_be_bytes());
        assert_eq!(&packet[98..100], &[2, 255]);
        assert_eq!(&packet[355..357], &[2, 45]);
        assert!(announce_request([9; 8], 42, &input, &[0; 1025]).is_err());
    }
    #[test]
    fn responses_validate_transaction_family_and_bounds() {
        let mut connect = 0u32.to_be_bytes().to_vec();
        connect.extend_from_slice(&42u32.to_be_bytes());
        connect.extend_from_slice(&[9; 8]);
        assert_eq!(connect_response(&connect, 42), Ok([9; 8]));
        assert_eq!(connect_response(&connect, 43), Err(Error::WrongTransaction));
        assert_eq!(
            connect_response(&connect[..12], 42),
            Err(Error::InvalidResponse)
        );
        let mut response = 1u32.to_be_bytes().to_vec();
        response.extend_from_slice(&42u32.to_be_bytes());
        response.extend_from_slice(&30u32.to_be_bytes());
        response.extend_from_slice(&2u32.to_be_bytes());
        response.extend_from_slice(&3u32.to_be_bytes());
        response.extend_from_slice(&[127, 0, 0, 1, 0x1a, 0xe1]);
        assert_eq!(
            announce_response(&response, 42, false).unwrap().peers,
            vec!["127.0.0.1:6881".parse().unwrap()]
        );
        let mut many = response[..20].to_vec();
        for _ in 0..201 {
            many.extend_from_slice(&[127, 0, 0, 1, 0x1a, 0xe1]);
        }
        assert_eq!(
            announce_response(&many, 42, false).unwrap().peers.len(),
            200
        );
        assert_eq!(
            announce_response(&response, 42, true)
                .unwrap()
                .trailing_bytes,
            [127, 0, 0, 1, 0x1a, 0xe1]
        );
        response.truncate(20);
        response.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        response.extend_from_slice(&6882u16.to_be_bytes());
        assert_eq!(
            announce_response(&response, 42, true).unwrap().peers,
            vec!["[::1]:6882".parse().unwrap()]
        );
        response.truncate(8);
        response[..4].copy_from_slice(&3u32.to_be_bytes());
        response.extend_from_slice(b"failure");
        assert_eq!(
            announce_response(&response, 42, true),
            Err(Error::TrackerError(b"failure".to_vec()))
        );
    }
    #[test]
    fn scrape_requires_matching_number_of_rows() {
        let request = scrape_request([3; 8], 42, &[[1; 20], [2; 20]]).unwrap();
        assert_eq!(request.len(), 56);
        assert_eq!(&request[8..16], &[0, 0, 0, 2, 0, 0, 0, 42]);
        let mut response = 2u32.to_be_bytes().to_vec();
        response.extend_from_slice(&42u32.to_be_bytes());
        for n in 1u32..=6 {
            response.extend_from_slice(&n.to_be_bytes());
        }
        let rows = scrape_response(&response, 42, 2).unwrap();
        assert_eq!(
            rows[0],
            ScrapeCounts {
                seeders: 1,
                downloaded: 2,
                leechers: 3
            }
        );
        assert_eq!(
            rows[1],
            ScrapeCounts {
                seeders: 4,
                downloaded: 5,
                leechers: 6
            }
        );
        assert_eq!(
            scrape_response(&response[..31], 42, 2),
            Err(Error::InvalidResponse)
        );
        assert_eq!(
            scrape_response(&response, 41, 2),
            Err(Error::WrongTransaction)
        );
    }
}
