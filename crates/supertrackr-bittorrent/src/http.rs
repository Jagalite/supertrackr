//! Byte-preserving tracker query parsing. This module performs no I/O.
use crate::standard::{Event, PeerId};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    Malformed,
    Missing,
    Duplicate,
    Invalid,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Announce {
    pub info_hash: [u8; 20],
    pub peer_id: PeerId,
    pub port: u16,
    pub left: u64,
    pub downloaded: u64,
    pub uploaded: u64,
    pub event: Event,
    pub compact: bool,
    pub no_peer_id: bool,
    pub numwant: usize,
}
fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' => {
                if i + 2 >= input.len() {
                    return Err(Error::Malformed);
                }
                let digit = |x: u8| -> Option<u8> {
                    match x {
                        b'0'..=b'9' => Some(x - b'0'),
                        b'a'..=b'f' => Some(x - b'a' + 10),
                        b'A'..=b'F' => Some(x - b'A' + 10),
                        _ => None,
                    }
                };
                out.push(
                    (digit(input[i + 1]).ok_or(Error::Malformed)? << 4)
                        | digit(input[i + 2]).ok_or(Error::Malformed)?,
                );
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}
type QueryFields = Vec<(Vec<u8>, Vec<u8>)>;
fn fields(query: &str) -> Result<QueryFields, Error> {
    if query.len() > 8192 {
        return Err(Error::TooLarge);
    }
    let mut result = Vec::new();
    for field in query.as_bytes().split(|&b| b == b'&') {
        if result.len() >= 64 {
            return Err(Error::TooLarge);
        }
        let pos = field
            .iter()
            .position(|&b| b == b'=')
            .ok_or(Error::Malformed)?;
        result.push((decode(&field[..pos])?, decode(&field[pos + 1..])?));
    }
    Ok(result)
}
fn single<'a>(fields: &'a [(Vec<u8>, Vec<u8>)], key: &[u8]) -> Result<Option<&'a [u8]>, Error> {
    let mut found = fields
        .iter()
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value.as_slice());
    let first = found.next();
    if found.next().is_some() {
        return Err(Error::Duplicate);
    }
    Ok(first)
}
fn number(value: &[u8]) -> Result<u64, Error> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(Error::Invalid);
    }
    std::str::from_utf8(value)
        .map_err(|_| Error::Invalid)?
        .parse()
        .map_err(|_| Error::Invalid)
}
pub fn announce(query: &str) -> Result<Announce, Error> {
    let f = fields(query)?;
    let hash = single(&f, b"info_hash")?
        .ok_or(Error::Missing)?
        .try_into()
        .map_err(|_| Error::Invalid)?;
    let peer = PeerId(
        single(&f, b"peer_id")?
            .ok_or(Error::Missing)?
            .try_into()
            .map_err(|_| Error::Invalid)?,
    );
    let port = u16::try_from(number(single(&f, b"port")?.ok_or(Error::Missing)?)?)
        .map_err(|_| Error::Invalid)?;
    if port == 0 {
        return Err(Error::Invalid);
    }
    let left = number(single(&f, b"left")?.ok_or(Error::Missing)?)?;
    let uploaded = number(single(&f, b"uploaded")?.ok_or(Error::Missing)?)?;
    let downloaded = number(single(&f, b"downloaded")?.ok_or(Error::Missing)?)?;
    let event = match single(&f, b"event")? {
        None | Some(b"") => Event::Update,
        Some(b"started") => Event::Started,
        Some(b"completed") => Event::Completed,
        Some(b"stopped") => Event::Stopped,
        _ => return Err(Error::Invalid),
    };
    let compact = match single(&f, b"compact")? {
        None | Some(b"0") => false,
        Some(b"1") => true,
        _ => return Err(Error::Invalid),
    };
    let no_peer_id = match single(&f, b"no_peer_id")? {
        None | Some(b"0") => false,
        Some(b"1") => true,
        _ => return Err(Error::Invalid),
    };
    let numwant = match single(&f, b"numwant")? {
        None => 50,
        Some(b"-1") => 50,
        Some(value) => number(value)?.min(50) as usize,
    };
    Ok(Announce {
        info_hash: hash,
        peer_id: peer,
        port,
        left,
        downloaded,
        uploaded,
        event,
        compact,
        no_peer_id,
        numwant,
    })
}
pub fn scrape(query: &str) -> Result<Vec<[u8; 20]>, Error> {
    let f = fields(query)?;
    let hashes: Result<Vec<_>, _> = f
        .iter()
        .filter(|(key, _)| key == b"info_hash")
        .map(|(_, value)| value.as_slice().try_into().map_err(|_| Error::Invalid))
        .collect();
    let hashes = hashes?;
    if hashes.is_empty() {
        return Err(Error::Missing);
    }
    if hashes.len() > 32 {
        return Err(Error::TooLarge);
    }
    Ok(hashes)
}
/// Preserve binary query values while forcing compact upstream responses.
pub fn compact_query(query: &str) -> Result<String, Error> {
    upstream_query(query, true, false)
}
/// Preserve binary query values while selecting an upstream response format.
pub fn upstream_query(query: &str, compact: bool, no_peer_id: bool) -> Result<String, Error> {
    let _ = announce(query)?;
    let mut parts = Vec::new();
    for field in query.split('&') {
        let (key, _) = field.split_once('=').ok_or(Error::Malformed)?;
        let key = decode(key.as_bytes())?;
        if !matches!(
            key.as_slice(),
            b"compact" | b"no_peer_id" | b"ip" | b"ipv4" | b"ipv6"
        ) {
            parts.push(field);
        }
    }
    parts.push(if compact { "compact=1" } else { "compact=0" });
    if no_peer_id {
        parts.push("no_peer_id=1");
    }
    Ok(parts.join("&"))
}

fn string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(bytes);
}
fn integer(out: &mut Vec<u8>, value: u64) {
    out.push(b'i');
    out.extend_from_slice(value.to_string().as_bytes());
    out.push(b'e');
}
/// Encode an announce response, including IPv6 peers in BEP 7 compact form.
pub fn announce_response(
    peers: &[crate::standard::Peer],
    counts: crate::standard::Counts,
    interval: u64,
    compact: bool,
    no_peer_id: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(b'd');
    string(&mut out, b"complete");
    integer(&mut out, counts.complete as u64);
    string(&mut out, b"incomplete");
    integer(&mut out, counts.incomplete as u64);
    string(&mut out, b"interval");
    integer(&mut out, interval);
    string(&mut out, b"peers");
    if compact {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for peer in peers {
            match peer.address.ip() {
                std::net::IpAddr::V4(ip) => {
                    v4.extend_from_slice(&ip.octets());
                    v4.extend_from_slice(&peer.address.port().to_be_bytes());
                }
                std::net::IpAddr::V6(ip) => {
                    v6.extend_from_slice(&ip.octets());
                    v6.extend_from_slice(&peer.address.port().to_be_bytes());
                }
            }
        }
        string(&mut out, &v4);
        if !v6.is_empty() {
            string(&mut out, b"peers6");
            string(&mut out, &v6);
        }
    } else {
        out.push(b'l');
        for peer in peers {
            out.push(b'd');
            string(&mut out, b"ip");
            string(&mut out, peer.address.ip().to_string().as_bytes());
            if !no_peer_id {
                string(&mut out, b"peer id");
                string(&mut out, &peer.id.0);
            }
            string(&mut out, b"port");
            integer(&mut out, peer.address.port() as u64);
            out.push(b'e');
        }
        out.push(b'e');
    }
    out.push(b'e');
    out
}
/// Encode bounded multi-hash scrape results in canonical dictionary order.
pub fn scrape_response(entries: &[([u8; 20], crate::standard::Counts)]) -> Vec<u8> {
    let mut entries = entries.to_vec();
    entries.sort_unstable_by_key(|(hash, _)| *hash);
    entries.dedup_by_key(|(hash, _)| *hash);
    let mut out = Vec::new();
    out.push(b'd');
    string(&mut out, b"files");
    out.push(b'd');
    for (hash, counts) in entries {
        string(&mut out, &hash);
        out.push(b'd');
        string(&mut out, b"complete");
        integer(&mut out, counts.complete as u64);
        string(&mut out, b"downloaded");
        integer(&mut out, counts.downloaded);
        string(&mut out, b"incomplete");
        integer(&mut out, counts.incomplete as u64);
        out.push(b'e');
    }
    out.extend_from_slice(b"ee");
    out
}
pub fn failure(reason: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(b'd');
    string(&mut out, b"failure reason");
    string(&mut out, reason.as_bytes());
    out.push(b'e');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_values_duplicate_fields_and_bounds() {
        let hash = "%00%ff".repeat(10);
        let id = "%80%2B".repeat(10);
        let q = format!(
            "info_hash={hash}&peer_id={id}&port=6881&uploaded=0&downloaded=0&left=1&compact=1"
        );
        let parsed = announce(&q).unwrap();
        assert_eq!(&parsed.info_hash[..2], &[0, 255]);
        assert_eq!(&parsed.peer_id.0[..2], &[128, b'+']);
        assert_eq!(announce(&format!("{q}&port=2")), Err(Error::Duplicate));
        assert_eq!(
            scrape(&format!("info_hash={hash}&info_hash={hash}"))
                .unwrap()
                .len(),
            2
        );
        assert_eq!(scrape("info_hash=%zz"), Err(Error::Malformed));
    }
    #[test]
    fn upstream_query_preserves_binary_values_and_removes_address_overrides() {
        let query = format!(
            "info_hash={}&peer_id={}&port=6881&uploaded=0&downloaded=0&left=1&ip=10.203.0.1&%69pv4=1.2.3.4&ipv6=%3A%3A1&compact=0&key=abc",
            "%ff".repeat(20),
            "%00".repeat(20)
        );
        let forwarded = upstream_query(&query, true, false).unwrap();
        assert_eq!(
            forwarded,
            format!(
                "info_hash={}&peer_id={}&port=6881&uploaded=0&downloaded=0&left=1&key=abc&compact=1",
                "%ff".repeat(20),
                "%00".repeat(20)
            )
        );
    }
    #[test]
    fn responses_encode_compact_dual_stack_and_sorted_scrapes() {
        let peers = [
            crate::standard::Peer {
                id: PeerId([1; 20]),
                address: "127.0.0.1:6881".parse().unwrap(),
                complete: false,
                expires: 10,
            },
            crate::standard::Peer {
                id: PeerId([2; 20]),
                address: "[::1]:6882".parse().unwrap(),
                complete: true,
                expires: 10,
            },
        ];
        let encoded =
            announce_response(&peers, crate::standard::Counts::default(), 60, true, false);
        assert!(
            encoded
                .windows(6)
                .any(|part| part == [127, 0, 0, 1, 0x1a, 0xe1])
        );
        assert!(encoded.windows(8).any(|part| part == b"6:peers6"));
        let scrape =
            scrape_response(&[([2; 20], Default::default()), ([1; 20], Default::default())]);
        assert!(
            scrape.windows(20).position(|part| part == [1; 20]).unwrap()
                < scrape.windows(20).position(|part| part == [2; 20]).unwrap()
        );
        assert_eq!(failure("bad"), b"d14:failure reason3:bade");
        assert_eq!(scrape_response(&[]), b"d5:filesdee");
    }
}
