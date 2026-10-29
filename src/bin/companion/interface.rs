use super::*;
use std::{os::unix::fs::PermissionsExt, path::Path};
use tun::AbstractDevice;
pub enum Adapter {
    Native(tun::AsyncDevice, String),
    Packet(UnixDatagram, PathBuf, PathBuf),
}
pub fn preflight() -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Err("native companion currently supports macOS only".into());
    }
    // SAFETY: geteuid has no pointer arguments.
    if unsafe { libc::geteuid() } != 0 {
        return Err(
            "native utun requires administrator privileges; run companion with sudo".into(),
        );
    }
    // Check the whole subnet, including more-specific routes that a single route get misses.
    let routes = std::process::Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", "inet"])
        .output()?;
    if !routes.status.success() {
        return Err("route inspection failed".into());
    }
    let routes = String::from_utf8(routes.stdout)?;
    let rows = routes
        .lines()
        .skip_while(|line| !line.starts_with("Destination"));
    let mut found = false;
    for line in rows.skip(1) {
        let Some(destination) = line.split_whitespace().next() else {
            continue;
        };
        found = true;
        if overlaps(destination)? {
            return Err(format!("existing route {destination} overlaps companion subnet").into());
        }
    }
    if !found {
        return Err("no readable IPv4 route table".into());
    }
    Ok(())
}
impl Adapter {
    pub async fn new(ip: Ipv4Addr, path: Option<&Path>, peer: Option<&Path>) -> Result<Self> {
        if let Some(path) = path {
            // Require an owner-only parent so socket creation has no permission race.
            use std::os::unix::fs::MetadataExt;
            let parent = std::fs::metadata(path.parent().ok_or("socket needs parent directory")?)?;
            if parent.uid() != unsafe { libc::geteuid() } || parent.mode() & 0o077 != 0 {
                return Err("packet socket needs an owner-only parent directory".into());
            }
            let socket = UnixDatagram::bind(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            return Ok(Self::Packet(
                socket,
                path.to_owned(),
                peer.ok_or("missing packet peer")?.to_owned(),
            ));
        }
        preflight()?;
        let mut config = tun::Configuration::default();
        config
            .address(ip)
            .destination(ip)
            .netmask(Ipv4Addr::new(255, 255, 255, 255))
            .mtu(MTU as u16)
            .up();
        #[cfg(target_os = "macos")]
        config.platform_config(|p| {
            p.enable_routing(false);
        });
        let device = tun::create_as_async(&config)?;
        let name = device.tun_name()?;
        let route = std::process::Command::new("/sbin/route")
            .args(["-n", "add", "-net", "10.203.0.0/16", "-interface", &name])
            .output()?;
        if !route.status.success() {
            return Err(format!(
                "overlay route failed: {}",
                String::from_utf8_lossy(&route.stderr)
            )
            .into());
        }
        Ok(Self::Native(device, name))
    }
    pub fn name(&self) -> &str {
        match self {
            Self::Native(_, name) => name,
            Self::Packet(..) => "packet-socket-test-adapter",
        }
    }
    pub async fn recv(&self, p: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Native(d, _) => d.recv(p).await,
            Self::Packet(d, _, _) => d.recv(p).await,
        }
    }
    pub async fn send(&self, p: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Native(d, _) => d.send(p).await,
            Self::Packet(d, _, peer) => d.send_to(p, peer).await,
        }
    }
}
impl Drop for Adapter {
    fn drop(&mut self) {
        match self {
            Self::Packet(_, path, _) => {
                let _ = std::fs::remove_file(path);
            }
            Self::Native(_, name) => {
                // Scope deletion to our own interface, then close the utun descriptor.
                let _ = std::process::Command::new("/sbin/route")
                    .args(["-n", "delete", "-net", "10.203.0.0/16", "-interface", name])
                    .output();
            }
        }
    }
}

// netstat abbreviates network destinations (10.203, 10/8); host routes have four octets.
fn overlaps(destination: &str) -> Result<bool> {
    if destination == "default" {
        return Ok(false);
    }
    let (address, prefix) = destination
        .split_once('/')
        .map_or((destination, None), |(a, p)| (a, Some(p)));
    let octets = address
        .split('.')
        .map(str::parse::<u8>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if octets.is_empty() || octets.len() > 4 {
        return Err("invalid route address".into());
    }
    let prefix = prefix
        .map(str::parse::<u32>)
        .transpose()?
        .unwrap_or(octets.len() as u32 * 8);
    if prefix > 32 {
        return Err("invalid route prefix".into());
    }
    if prefix == 0 {
        return Ok(false);
    }
    let mut bytes = [0; 4];
    bytes[..octets.len()].copy_from_slice(&octets);
    let mask = u32::MAX << (32 - prefix.min(16));
    Ok(u32::from_be_bytes(bytes) & mask == 0x0acb0000 & mask)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conflicts_include_parent_subnet_and_host_routes() {
        for route in [
            "10/8",
            "10.203",
            "10.203.20/24",
            "10.203.10.1",
            "10.203.0.0/16",
        ] {
            assert!(overlaps(route).unwrap(), "{route}");
        }
        for route in ["default", "0/0", "100.64/10", "192.168.1", "10.204"] {
            assert!(!overlaps(route).unwrap(), "{route}");
        }
        assert!(overlaps("unparseable").is_err());
    }
}
