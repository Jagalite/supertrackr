//! Run with `cargo run --example userspace_echo` (build through Kyoto).
//! Local HTTP tracker + two userspace endpoints; no utun, routes, or root required.
use boringtun::x25519::{PublicKey, StaticSecret};
use std::{
    net::SocketAddrV4,
    time::{Duration, Instant},
};
use supertrackr::{
    CandidatePeer, Config, Coordinator, async_userspace::Client, userspace::Network,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct Peer {
    client: Client,
    key: String,
    token: String,
    ip: std::net::Ipv4Addr,
}
impl Peer {
    async fn enroll(http: &reqwest::Client, base: &reqwest::Url) -> Result<Self> {
        let secret = StaticSecret::from(rand::random::<[u8; 32]>());
        let key = hex::encode(PublicKey::from(&secret).as_bytes());
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = udp.local_addr()?;
        let started = Instant::now();
        let registration = supertrackr::enrollment::register(http, base, &secret, addr).await?;
        let token = registration.token;
        http.post(base.join("v1/candidates")?)
            .header("x-peer-key", &key)
            .bearer_auth(&token)
            .json(&serde_json::json!({"candidates":[addr]}))
            .send()
            .await?
            .error_for_status()?;
        let interface: serde_json::Value = http
            .get(base.join("v1/interface")?)
            .header("x-peer-key", &key)
            .bearer_auth(&token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let ip = interface["virtual_ip"]
            .as_str()
            .ok_or("no virtual IP")?
            .parse()?;
        let network = Network::new(
            secret,
            ip,
            started + Duration::from_secs(registration.expires_in_seconds.saturating_sub(1)),
        )?;
        let (client, _resolutions) = Client::spawn(network, udp);
        Ok(Self {
            client,
            key,
            token,
            ip,
        })
    }
    async fn install(
        &mut self,
        http: &reqwest::Client,
        base: &reqwest::Url,
        key: &str,
    ) -> Result<()> {
        let started = Instant::now();
        let binding: CandidatePeer = http
            .post(base.join("v1/binding")?)
            .header("x-peer-key", &self.key)
            .bearer_auth(&self.token)
            .json(&serde_json::json!({"public_key":key}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let until = started + Duration::from_secs(binding.remaining_seconds.saturating_sub(1));
        self.client.install_peer(binding, until).await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base: reqwest::Url = format!("http://{}/", listener.local_addr()?).parse()?;
    let state = Coordinator::with_audience(
        Config {
            open_registration: true,
            ttl_seconds: 60,
            ..Config::default()
        },
        base.to_string(),
    );
    let server =
        tokio::spawn(async move { axum::serve(listener, supertrackr::router(state)).await });
    let result=tokio::time::timeout(Duration::from_secs(10),async {
        let http=reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(2)).build()?;
        let mut a=Peer::enroll(&http,&base).await?;let mut b=Peer::enroll(&http,&base).await?;
        a.install(&http,&base,&b.key).await?;b.install(&http,&base,&a.key).await?;
        let mut listener=b.client.listen_tcp(8080).await?;
        let mut bu=b.client.bind_udp(9000).await?;
        let mut au=a.client.bind_udp(9000).await?;
        let tcp_echo=async {
            let (mut stream,_)=listener.accept().await?;
            let mut data=Vec::new();stream.read_to_end(&mut data).await?;
            stream.write_all(&data).await?;stream.shutdown().await?;
            Ok::<(),std::io::Error>(())
        };
        let tcp_client=async {
            let mut stream=a.client.connect(SocketAddrV4::new(b.ip,8080)).await?;
            stream.write_all(b"userspace async TCP").await?;stream.shutdown().await?;
            let mut data=Vec::new();stream.read_to_end(&mut data).await?;
            assert_eq!(data,b"userspace async TCP");Ok::<(),std::io::Error>(())
        };
        let udp_echo=async {
            let mut data=[0;128];let(n,from)=bu.recv_from(&mut data).await?;
            bu.send_to(&data[..n],from).await?;Ok::<(),std::io::Error>(())
        };
        let udp_client=async {
            au.send_to(b"userspace async UDP",SocketAddrV4::new(b.ip,9000)).await?;
            let mut data=[0;128];let(n,_)=au.recv_from(&mut data).await?;
            assert_eq!(&data[..n],b"userspace async UDP");Ok::<(),std::io::Error>(())
        };
        tokio::try_join!(tcp_echo,tcp_client,udp_echo,udp_client)?;
        a.client.shutdown().await?;b.client.shutdown().await?;
        println!("PASS: tracker-enrolled async TCP and UDP echo over WireGuard; no application polling or virtual interface");
        Ok::<(),Box<dyn std::error::Error+Send+Sync>>(())
    }).await;
    server.abort();
    let _ = server.await;
    result??;
    Ok(())
}
