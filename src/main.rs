use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use supertrackr::{Config, Coordinator, router};
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    #[arg(long)]
    cert: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,
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
    let state = Coordinator::new(Config {
        capacity: a.capacity,
        ttl_seconds: a.ttl_seconds,
        open_registration: a.open_registration,
    });
    let cleaner = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            cleaner.cleanup();
        }
    });
    eprintln!(
        "Listening on {}; RAM-only prototype; open_registration={}",
        a.listen, a.open_registration
    );
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
    Ok(())
}
