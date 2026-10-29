//! HTTP control runs independently of UDP processing. Bounded channels separate data and control.
use super::*;
use supertrackr::{Events, RegistrationResponse};
use tokio::sync::{mpsc, watch};
pub enum Event {
    Lease(Instant, u64),
    Peer(CandidatePeer, Instant),
    Packet(String, Vec<u8>),
    RelayDropped,
}
pub struct Relay {
    pub target: String,
    pub data: Vec<u8>,
}
pub struct Control {
    http: reqwest::Client,
    base: reqwest::Url,
    public: String,
    token: String,
    endpoint: SocketAddr,
    expires: Instant,
    refresh_at: Instant,
    refreshes: u64,
}
impl Control {
    pub async fn register(
        base: reqwest::Url,
        public: String,
        endpoint: SocketAddr,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()?;
        let start = Instant::now();
        let r: RegistrationResponse = http
            .post(base.join("v1/register")?)
            .json(&json!({"public_key":public,"endpoint":endpoint}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let mut raw = [0; 32];
        if !(1..=86400).contains(&r.expires_in_seconds)
            || hex::decode_to_slice(&r.token, &mut raw).is_err()
        {
            return Err("invalid registration response".into());
        }
        let ttl = Duration::from_secs(r.expires_in_seconds);
        Ok(Self {
            http,
            base,
            public,
            token: r.token,
            endpoint,
            expires: start + ttl,
            refresh_at: start + ttl / 2,
            refreshes: 0,
        })
    }
    pub fn expires(&self) -> Instant {
        self.expires
    }
    fn auth(&self, r: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        r.header("x-peer-key", &self.public)
            .bearer_auth(&self.token)
    }
    async fn connect(&self, target: &str) -> Result<Option<(CandidatePeer, Instant)>> {
        let start = Instant::now();
        let r = self
            .auth(self.http.post(self.base.join("v1/connect")?))
            .json(&json!({"public_key":target}))
            .send()
            .await?;
        if matches!(r.status().as_u16(), 404 | 409 | 503) {
            return Ok(None);
        }
        let p: CandidatePeer = r.error_for_status()?.json().await?;
        if p.public_key != target || !(1..=86400).contains(&p.remaining_seconds) {
            return Err("invalid connection metadata".into());
        }
        let expires = start + Duration::from_secs(p.remaining_seconds);
        Ok(Some((p, expires)))
    }
    pub async fn run(
        mut self,
        mut wanted: Option<String>,
        passive: bool,
        mut candidates: watch::Receiver<Vec<SocketAddr>>,
        mut relay: mpsc::Receiver<Relay>,
        events: mpsc::Sender<Event>,
    ) -> Result<()> {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut discover_at = Instant::now();
        let mut published = Vec::new();
        events.send(Event::Lease(self.expires, 0)).await?;
        loop {
            tokio::select! {
                _=events.closed()=>return Ok(()),
                _=tick.tick()=>{
                    let now=Instant::now();
                    if now>=self.expires {return Err("local registration expired".into());}
                    if now>=self.refresh_at {
                        let start=Instant::now();
                        let r:RegistrationResponse=self.auth(self.http.post(self.base.join("v1/register")?)).json(&json!({"public_key":self.public,"endpoint":self.endpoint})).send().await?.error_for_status()?.json().await?;
                        if r.token!=self.token || !(1..=86400).contains(&r.expires_in_seconds) {return Err("invalid refresh".into());}
                        let ttl=Duration::from_secs(r.expires_in_seconds);self.expires=start+ttl;self.refresh_at=start+ttl/2;self.refreshes+=1;
                        events.send(Event::Lease(self.expires,self.refreshes)).await?;
                    }
                    let current=candidates.borrow_and_update().clone();
                    if current!=published {
                        self.auth(self.http.post(self.base.join("v1/candidates")?)).json(&json!({"candidates":current})).send().await?.error_for_status()?;
                        published=current;
                    }
                    if Instant::now()>=discover_at {
                        if wanted.is_none() && !passive {
                            let peers:Vec<Peer>=self.auth(self.http.get(self.base.join("v1/peers?limit=100")?)).send().await?.error_for_status()?.json().await?;
                            for p in peers {
                                if key(&p.public_key).is_ok() && let Some((peer,until))=self.connect(&p.public_key).await? {
                                    wanted=Some(p.public_key);events.send(Event::Peer(peer,until)).await?;break;
                                }
                            }
                        } else if let Some(target)=&wanted && let Some((peer,until))=self.connect(target).await? {
                            events.send(Event::Peer(peer,until)).await?;
                        }
                        // Refresh before a one-second remaining peer lease can lapse.
                        discover_at=Instant::now()+Duration::from_millis(500);
                    }
                    let data:Events=self.auth(self.http.get(self.base.join("v1/events")?)).send().await?.error_for_status()?.json().await?;
                    for p in data.requests {
                        if wanted.as_ref().is_none_or(|w|*w==p.public_key) && key(&p.public_key).is_ok()
                            && let Some((peer,until))=self.connect(&p.public_key).await? {
                            wanted=Some(p.public_key);events.send(Event::Peer(peer,until)).await?;
                        }
                    }
                    for packet in data.packets {
                        if wanted.as_ref()==Some(&packet.public_key) && packet.packet.len()<=supertrackr::core::traversal::MAX_DATAGRAM*2 {
                            events.send(Event::Packet(packet.public_key,hex::decode(packet.packet)?)).await?;
                        }
                    }
                },
                Some(r)=relay.recv()=>{
                    let response=self.auth(self.http.post(self.base.join("v1/relay")?)).json(&json!({"public_key":r.target,"packet":hex::encode(r.data)})).send().await?;
                    if matches!(response.status().as_u16(),404|409|503) {events.send(Event::RelayDropped).await?;}
                    else {response.error_for_status()?;}
                }
            }
        }
    }
}
