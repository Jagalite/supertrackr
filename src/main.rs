use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};
use supertrackr::{Config, Coordinator, router};
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    /// Canonical public origin binding anonymous enrollment proofs (required for HTTPS).
    #[arg(long)]
    public_origin: Option<reqwest::Url>,
    #[arg(long)]
    cert: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,
    /// Optional UDP STUN mapping reflector (separate from the HTTP tracker).
    #[arg(long)]
    stun_listen: Option<SocketAddr>,
    /// Explicit plaintext HTTP for loopback benchmarks only.
    #[arg(long)]
    lab_http: bool,
    /// Prototype policy: anyone may register; all live registrations may discover and verify peers.
    #[arg(long)]
    open_registration: bool,
    #[arg(long, default_value_t = 100_000)]
    capacity: usize,
    #[arg(long, default_value_t = 300)]
    ttl_seconds: u64,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a = Args::parse();
    if a.capacity == 0 || !(1..=86400).contains(&a.ttl_seconds) {
        return Err("invalid capacity or TTL".into());
    }
    if a.lab_http && !a.listen.ip().is_loopback() {
        return Err("--lab-http requires loopback".into());
    }
    if a.lab_http && a.stun_listen.is_some_and(|addr| !addr.ip().is_loopback()) {
        return Err("lab STUN listener must be loopback".into());
    }
    let stun_socket = if let Some(addr) = a.stun_listen {
        Some(tokio::net::UdpSocket::bind(addr).await?)
    } else {
        None
    };
    let tls = if a.lab_http {
        None
    } else {
        Some(
            axum_server::tls_rustls::RustlsConfig::from_pem_file(
                a.cert
                    .ok_or("HTTPS requires --cert (or explicit loopback --lab-http)")?,
                a.key.ok_or("HTTPS requires --key")?,
            )
            .await?,
        )
    };
    let origin = match a.public_origin {
        Some(origin) => origin,
        None if a.lab_http => format!("http://{}/", a.listen).parse()?,
        None => {
            return Err("HTTPS server requires --public-origin https://tracker.example/".into());
        }
    };
    if origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || (!a.lab_http && origin.scheme() != "https")
        || (a.lab_http
            && (origin.scheme() != "http"
                || !origin.host_str().is_some_and(|s| {
                    s.parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
                })))
    {
        return Err("invalid public origin".into());
    }
    let state = Coordinator::with_audience(
        Config {
            capacity: a.capacity,
            ttl_seconds: a.ttl_seconds,
            open_registration: a.open_registration,
        },
        origin.to_string(),
    );
    eprintln!(
        "Listening on {}; RAM-only prototype; open_registration={}",
        a.listen, a.open_registration
    );
    let http = async {
        if let Some(tls) = tls {
            axum_server::bind_rustls(a.listen, tls)
                .serve(router(state).into_make_service())
                .await?;
        } else {
            axum::serve(
                tokio::net::TcpListener::bind(a.listen).await?,
                router(state),
            )
            .await?;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let stun = async {
        match stun_socket {
            Some(socket) => supertrackr::stun::serve(socket).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! { result=http=>result, result=stun=>{result?;Err("STUN task stopped".into())} }
}
