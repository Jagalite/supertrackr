//! Minimal lab IPv4/UDP ping/pong packets, carried inside WireGuard.
use std::net::Ipv4Addr;
const PORT: u16 = 33999;
const LEN: usize = 44;
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|w| u16::from_be_bytes([w[0], w[1]]) as u32)
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
pub fn encode(src: Ipv4Addr, dst: Ipv4Addr, kind: u8, nonce: u64) -> [u8; LEN] {
    let mut out = [0u8; LEN];
    out[0] = 0x45;
    out[2..4].copy_from_slice(&(LEN as u16).to_be_bytes());
    out[8] = 64;
    out[9] = 17;
    out[12..16].copy_from_slice(&src.octets());
    out[16..20].copy_from_slice(&dst.octets());
    let check = checksum(&out[..20]);
    out[10..12].copy_from_slice(&check.to_be_bytes());
    out[20..22].copy_from_slice(&PORT.to_be_bytes());
    out[22..24].copy_from_slice(&PORT.to_be_bytes());
    out[24..26].copy_from_slice(&24u16.to_be_bytes()); // UDP checksum zero is valid for IPv4.
    out[28..32].copy_from_slice(b"STR1");
    out[32] = kind;
    out[36..44].copy_from_slice(&nonce.to_be_bytes());
    out
}
pub fn decode(bytes: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Option<(u8, u64)> {
    if bytes.len() != LEN
        || bytes[0] != 0x45
        || bytes[2..4] != (LEN as u16).to_be_bytes()
        || bytes[6..8] != [0, 0]
        || bytes[9] != 17
        || checksum(&bytes[..20]) != 0
        || bytes[12..16] != src.octets()
        || bytes[16..20] != dst.octets()
        || bytes[20..22] != PORT.to_be_bytes()
        || bytes[22..24] != PORT.to_be_bytes()
        || bytes[24..28] != [0, 24, 0, 0]
        || &bytes[28..32] != b"STR1"
        || !(1..=2).contains(&bytes[32])
        || bytes[33..36] != [0, 0, 0]
    {
        return None;
    }
    Some((
        bytes[32],
        u64::from_be_bytes(bytes[36..44].try_into().ok()?),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_binding_length_and_checksum_are_checked() {
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let b = Ipv4Addr::new(10, 0, 0, 2);
        let mut p = encode(a, b, 1, 42);
        assert_eq!(decode(&p, a, b), Some((1, 42)));
        assert_eq!(decode(&p, b, a), None);
        assert_eq!(decode(&p[..43], a, b), None);
        p[8] ^= 1;
        assert_eq!(decode(&p, a, b), None);
    }
}
