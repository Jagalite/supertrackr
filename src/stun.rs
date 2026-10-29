//! Minimal unauthenticated STUN Binding usage (RFC 8489). Mapping is a hint, not identity.
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::time::Instant;
const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
pub fn request(id: [u8; 12]) -> [u8; 20] {
    let mut p = [0; 20];
    p[1] = 1;
    p[4..8].copy_from_slice(&COOKIE);
    p[8..].copy_from_slice(&id);
    p
}
pub fn response(p: &[u8], id: [u8; 12]) -> Option<SocketAddr> {
    if p.len() < 20 || p[..2] != [1, 1] || p[4..8] != COOKIE || p[8..20] != id {
        return None;
    }
    let len = u16::from_be_bytes([p[2], p[3]]) as usize;
    if !len.is_multiple_of(4) || p.len() != 20 + len {
        return None;
    }
    let mut at = 20;
    let mut mapped = None;
    while at < p.len() {
        let header = p.get(at..at + 4)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let n = u16::from_be_bytes([header[2], header[3]]) as usize;
        let v = p.get(at + 4..at + 4 + n)?;
        if kind == 0x20 {
            if v.len() < 4 {
                return None;
            }
            let port = u16::from_be_bytes([v[2] ^ COOKIE[0], v[3] ^ COOKIE[1]]);
            let ip = match v[1] {
                1 if n == 8 => IpAddr::V4(Ipv4Addr::new(
                    v[4] ^ COOKIE[0],
                    v[5] ^ COOKIE[1],
                    v[6] ^ COOKIE[2],
                    v[7] ^ COOKIE[3],
                )),
                2 if n == 20 => {
                    let mut bytes = [0; 16];
                    let mut mask = [0; 16];
                    mask[..4].copy_from_slice(&COOKIE);
                    mask[4..].copy_from_slice(&id);
                    for i in 0..16 {
                        bytes[i] = v[4 + i] ^ mask[i];
                    }
                    IpAddr::V6(Ipv6Addr::from(bytes))
                }
                _ => return None,
            };
            let addr = SocketAddr::new(ip, port);
            if !crate::core::traversal::valid_endpoint(addr) {
                return None;
            }
            if mapped.is_none() {
                mapped = Some(addr);
            }
        } else if kind == 0x8028 {
            if n != 4 || at + 8 != p.len() {
                return None;
            }
            let mut crc = 0xffffffffu32;
            for &b in &p[..at] {
                crc ^= u32::from(b);
                for _ in 0..8 {
                    crc = (crc >> 1) ^ ((0u32.wrapping_sub(crc & 1)) & 0xedb88320);
                }
            }
            if u32::from_be_bytes(v.try_into().ok()?) != (!crc ^ 0x5354554e) {
                return None;
            }
        } else if kind < 0x8000 && kind != 1 {
            // Unknown comprehension-required attribute.
            return None;
        }
        at = at.checked_add(4 + n.div_ceil(4) * 4)?;
        if at > p.len() {
            return None;
        }
    }
    mapped
}
struct Server {
    address: SocketAddr,
    id: [u8; 12],
    attempts: u8,
    next: Instant,
    deadline: Instant,
    mapped: Option<(SocketAddr, Instant)>,
}
pub struct Discovery {
    servers: Vec<Server>,
}
impl Discovery {
    pub fn new(addresses: &[SocketAddr]) -> Self {
        let now = Instant::now();
        Self {
            servers: addresses
                .iter()
                .map(|&address| Server {
                    address,
                    id: rand::random(),
                    attempts: 0,
                    next: now,
                    deadline: now,
                    mapped: None,
                })
                .collect(),
        }
    }
    pub fn due(&mut self, now: Instant) -> Vec<(SocketAddr, [u8; 20])> {
        let mut out = Vec::new();
        for s in &mut self.servers {
            if now < s.next {
                continue;
            }
            if s.attempts == 0 {
                s.id = rand::random();
                s.deadline = now + Duration::from_secs(4);
            }
            if s.attempts >= 3 {
                s.attempts = 0;
                s.next = now + Duration::from_secs(10);
                continue;
            }
            out.push((s.address, request(s.id)));
            s.attempts += 1;
            s.next = now + Duration::from_millis(500 * (1 << s.attempts));
        }
        out
    }
    pub fn receive(&mut self, source: SocketAddr, data: &[u8], now: Instant) -> bool {
        let Some(s) = self
            .servers
            .iter_mut()
            .find(|s| s.address == source && s.attempts > 0 && now < s.deadline)
        else {
            return false;
        };
        let Some(addr) = response(data, s.id) else {
            return false;
        };
        s.mapped = Some((addr, now + Duration::from_secs(30)));
        s.attempts = 0;
        s.next = now + Duration::from_secs(10);
        true
    }
    /// Compare fresh same-family observations from distinct server IPs. None means insufficient evidence.
    /// Equal observations describe those destinations only; they do not prove all NAT behavior.
    pub fn mapping_varies_by_destination(&self, now: Instant) -> Option<bool> {
        let mut comparable = false;
        for (i, a) in self.servers.iter().enumerate() {
            let Some((aa, _)) = a.mapped.filter(|(_, until)| *until > now) else {
                continue;
            };
            for b in &self.servers[i + 1..] {
                if a.address.ip() == b.address.ip() {
                    continue;
                }
                if let Some((bb, _)) = b.mapped.filter(|(_, until)| *until > now)
                    && aa.is_ipv4() == bb.is_ipv4()
                {
                    comparable = true;
                    if aa != bb {
                        return Some(true);
                    }
                }
            }
        }
        comparable.then_some(false)
    }
    pub fn candidates(&self, now: Instant) -> Vec<SocketAddr> {
        let mut result = Vec::new();
        for (addr, until) in self.servers.iter().filter_map(|s| s.mapped) {
            if now < until && !result.contains(&addr) {
                result.push(addr);
            }
        }
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn reply(id: [u8; 12], address: SocketAddr) -> Vec<u8> {
        let mut p = request(id).to_vec();
        p[0] = 1;
        let bytes = match address.ip() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let n = 4 + bytes.len();
        p[2..4].copy_from_slice(&((n + 4) as u16).to_be_bytes());
        p.extend_from_slice(&[
            0,
            0x20,
            0,
            n as u8,
            0,
            if address.is_ipv4() { 1 } else { 2 },
        ]);
        p.extend_from_slice(&(address.port() ^ 0x2112).to_be_bytes());
        let mut mask = COOKIE.to_vec();
        mask.extend_from_slice(&id);
        p.extend(bytes.iter().zip(mask).map(|(a, b)| a ^ b));
        p
    }
    #[test]
    fn fingerprint_and_required_attributes_are_checked() {
        // Fingerprint computed independently using Python zlib.crc32, then XOR 0x5354554e.
        let mut p = hex::decode(
            "010100142112a4422a2a2a2a2a2a2a2a2a2a2a2a00200008000130c5ea12d543802800048b72e1a9",
        )
        .unwrap();
        assert_eq!(
            response(&p, [42; 12]),
            Some("203.0.113.1:4567".parse().unwrap())
        );
        *p.last_mut().unwrap() ^= 1;
        assert_eq!(response(&p, [42; 12]), None);
        let mut p = reply([42; 12], "203.0.113.1:4567".parse().unwrap());
        p[2..4].copy_from_slice(&16u16.to_be_bytes());
        p.extend_from_slice(&[0, 0x7f, 0, 0]);
        assert_eq!(response(&p, [42; 12]), None);
    }
    #[test]
    fn validates_ipv4_ipv6_transactions_lengths_and_source() {
        let id = [42; 12];
        for addr in ["203.0.113.1:4567", "[2001:db8::1234]:4567"] {
            let addr = addr.parse().unwrap();
            let p = reply(id, addr);
            assert_eq!(response(&p, id), Some(addr));
            assert_eq!(response(&p, [0; 12]), None);
            for n in 0..p.len() {
                assert_eq!(response(&p[..n], id), None);
            }
            let mut bad = p.clone();
            bad.push(0);
            assert_eq!(response(&bad, id), None);
        }
        let source = "127.0.0.1:3478".parse().unwrap();
        let mut d = Discovery::new(&[source]);
        let now = Instant::now();
        let probes = d.due(now);
        let id = probes[0].1[8..].try_into().unwrap();
        let p = reply(id, "203.0.113.1:1234".parse().unwrap());
        assert!(!d.receive("127.0.0.1:3479".parse().unwrap(), &p, now));
        assert!(d.receive(source, &p, now));
        assert!(!d.receive(source, &p, now));
        assert_eq!(d.candidates(now).len(), 1);
        assert!(d.candidates(now + Duration::from_secs(31)).is_empty());
    }
}

/// Stateless response for this prototype's attribute-free Binding request usage.
/// Never uses a claimed address from the packet; only the UDP source address.
pub fn binding_response(data: &[u8], source: SocketAddr) -> Option<Vec<u8>> {
    if data.len() != 20 || data[..8] != [0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42] {
        return None;
    }
    let ip = match source.ip() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    let mut out = data.to_vec();
    out[0] = 1;
    out[2..4].copy_from_slice(&((8 + ip.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[
        0,
        0x20,
        0,
        (4 + ip.len()) as u8,
        0,
        if source.is_ipv4() { 1 } else { 2 },
    ]);
    out.extend_from_slice(&(source.port() ^ 0x2112).to_be_bytes());
    let mask = &data[4..20];
    out.extend(ip.iter().zip(mask).map(|(a, b)| a ^ b));
    Some(out)
}
/// Optional mapping reflector, capped globally at 1,000 responses per second.
pub async fn serve(socket: tokio::net::UdpSocket) -> std::io::Result<()> {
    let mut data = [0; 64];
    let mut window = Instant::now();
    let mut sent = 0;
    loop {
        let (n, source) = socket.recv_from(&mut data).await?;
        if window.elapsed() >= Duration::from_secs(1) {
            sent = 0;
            window = Instant::now();
        }
        if sent >= 1000 {
            continue;
        }
        if let Some(reply) = binding_response(&data[..n], source) {
            sent += 1;
            let _ = socket.send_to(&reply, source).await;
        }
    }
}
#[cfg(test)]
mod server_tests {
    use super::*;
    #[tokio::test]
    async fn actual_udp_reflector_reports_source_socket() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap();
        let task = tokio::spawn(serve(server));
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let id = [7; 12];
        client.send_to(&request(id), target).await.unwrap();
        let mut buf = [0; 64];
        let (n, source) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, target);
        assert_eq!(response(&buf[..n], id), Some(client.local_addr().unwrap()));
        task.abort();
        assert!(binding_response(&[0; 20], target).is_none());
        let ipv6 = "[2001:db8::1]:9999".parse().unwrap();
        assert_eq!(
            response(&binding_response(&request(id), ipv6).unwrap(), id),
            Some(ipv6)
        );
    }
}

#[cfg(test)]
mod classification_tests {
    use super::*;
    #[test]
    fn classification_requires_fresh_observations_from_distinct_destinations() {
        let now = Instant::now();
        let mut d = Discovery::new(&[
            "192.0.2.1:3478".parse().unwrap(),
            "192.0.2.2:3478".parse().unwrap(),
        ]);
        assert_eq!(d.mapping_varies_by_destination(now), None);
        d.servers[0].mapped = Some((
            "198.51.100.1:1234".parse().unwrap(),
            now + Duration::from_secs(2),
        ));
        assert_eq!(d.mapping_varies_by_destination(now), None);
        d.servers[1].mapped = d.servers[0].mapped;
        assert_eq!(d.mapping_varies_by_destination(now), Some(false));
        d.servers[1].mapped = Some((
            "198.51.100.1:5678".parse().unwrap(),
            now + Duration::from_secs(2),
        ));
        assert_eq!(d.mapping_varies_by_destination(now), Some(true));
        assert_eq!(
            d.mapping_varies_by_destination(now + Duration::from_secs(2)),
            None
        );
        d.servers[1].address = "192.0.2.1:3479".parse().unwrap();
        assert_eq!(d.mapping_varies_by_destination(now), None);
    }
}
