use super::*;
use serde_json::json;
use supertrackr::{CandidatePeer, InterfaceInfo, PunchHint, RegistrationResponse};
use tokio::sync::{mpsc, watch};
pub enum Request {
    Peer(String),
    Resolve(Ipv4Addr),
    Verify(introduction::Ticket),
    Track(String, Instant),
}
pub enum Event {
    Lease(Instant),
    Punch(Vec<PunchHint>, Instant),
    RendezvousUnavailable,
    Discovered(CandidatePeer, Instant),
    Verified(introduction::Ticket, CandidatePeer, Instant),
    Refreshed(CandidatePeer, Instant),
}
pub struct Control {
    http: reqwest::Client,
    base: reqwest::Url,
    public: String,
    token: String,
    endpoint: SocketAddr,
    expires: Instant,
    refresh: Instant,
    introduction: IntroductionMode,
}
#[cfg(feature = "bittorrent")]
#[derive(Clone)]
pub struct TrackerAccess {
    pub http: reqwest::Client,
    pub base: reqwest::Url,
    pub public: String,
    pub token: String,
}
#[cfg(feature = "bittorrent")]
impl TrackerAccess {
    pub fn auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request
            .header("x-peer-key", &self.public)
            .bearer_auth(&self.token)
    }
}
impl Control {
    #[cfg(feature = "bittorrent")]
    pub fn tracker_access(&self) -> TrackerAccess {
        TrackerAccess {
            http: self.http.clone(),
            base: self.base.clone(),
            public: self.public.clone(),
            token: self.token.clone(),
        }
    }
    pub async fn new(
        base: reqwest::Url,
        public: String,
        endpoint: SocketAddr,
        candidates: Vec<SocketAddr>,
        introduction: IntroductionMode,
        secret: &boringtun::x25519::StaticSecret,
    ) -> Result<(Self, InterfaceInfo)> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()?;
        let at = Instant::now();
        let r: RegistrationResponse =
            supertrackr::enrollment::register(&http, &base, secret, endpoint).await?;
        if !(3..=86400).contains(&r.expires_in_seconds) {
            return Err("companion requires server TTL of at least three seconds".into());
        }
        let c = Self {
            introduction,
            http,
            base,
            public,
            token: r.token,
            endpoint,
            expires: at + Duration::from_secs(r.expires_in_seconds - 1),
            refresh: at + Duration::from_secs(r.expires_in_seconds) / 2,
        };
        c.publish(candidates).await?;
        let info: InterfaceInfo = c
            .auth(c.http.get(c.base.join("v1/interface")?))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if info.public_key != c.public
            || info.network != supertrackr::core::traversal::OVERLAY_NETWORK
            || !supertrackr::peer_manager::overlay(info.virtual_ip)
        {
            return Err("invalid assigned interface".into());
        }
        Ok((c, info))
    }
    fn auth(&self, r: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        r.header("x-peer-key", &self.public)
            .bearer_auth(&self.token)
    }
    pub fn expires(&self) -> Instant {
        self.expires
    }
    async fn publish(&self, candidates: Vec<SocketAddr>) -> Result<()> {
        self.auth(self.http.post(self.base.join("v1/candidates")?))
            .json(&json!({"candidates":candidates}))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
    async fn connect(
        &self,
        path: &str,
        query: serde_json::Value,
    ) -> Result<Option<(CandidatePeer, Instant)>> {
        let at = Instant::now();
        let response = self
            .auth(self.http.post(self.base.join(path)?))
            .json(&query)
            .send()
            .await?;
        if matches!(response.status().as_u16(), 404 | 409 | 503) {
            return Ok(None);
        }
        let p: CandidatePeer = response.error_for_status()?.json().await?;
        if query
            .get("public_key")
            .and_then(|v| v.as_str())
            .is_some_and(|k| k != p.public_key)
        {
            return Err("connect key mismatch".into());
        }
        if !(1..=86400).contains(&p.remaining_seconds) {
            return Err("invalid peer lifetime".into());
        }
        // Whole-second server clock: round down rather than extending permission.
        let until = at + Duration::from_secs(p.remaining_seconds - 1);
        Ok(Some((p, until)))
    }
    pub async fn run(
        mut self,
        mut requests: mpsc::Receiver<Request>,
        events: mpsc::Sender<Event>,
        mut candidates: watch::Receiver<Vec<SocketAddr>>,
    ) -> Result<()> {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut pinned = std::collections::HashSet::new();
        let mut peers = std::collections::HashMap::<String, Instant>::new();
        fn next(until: Instant) -> Instant {
            let now = Instant::now();
            now + until
                .saturating_duration_since(now)
                .div_f32(2.0)
                .min(Duration::from_secs(30))
        }
        loop {
            tokio::select! {
                _=events.closed()=>return Ok(()),
                _=tick.tick()=>{
                    if Instant::now()>=self.expires{return Err("registration expired".into());}
                    if Instant::now()>=self.refresh {
                        let at=Instant::now();let r:RegistrationResponse=self.auth(self.http.post(self.base.join("v1/register")?)).json(&json!({"public_key":self.public,"endpoint":self.endpoint})).send().await?.error_for_status()?.json().await?;
                        if r.token!=self.token || !(3..=86400).contains(&r.expires_in_seconds){return Err("invalid refresh".into());}
                        self.expires=at+Duration::from_secs(r.expires_in_seconds-1);self.refresh=at+Duration::from_secs(r.expires_in_seconds)/2;events.send(Event::Lease(self.expires)).await?;
                    }
                    if candidates.has_changed()? {let c=candidates.borrow_and_update().clone();self.publish(c).await?;}
                    let at=Instant::now();
                    let hints:Vec<PunchHint>=self.auth(self.http.get(self.base.join("v1/rendezvous")?)).send().await?.error_for_status()?.json().await?;
                    if hints.len()>8 {return Err("oversized punch hint batch".into());}
                    if !hints.is_empty(){events.send(Event::Punch(hints,at)).await?;}
                    let due=peers.iter().filter(|(_,at)|**at<=Instant::now()).min_by_key(|(_,at)|**at).map(|(k,_)|k.clone());
                    if let Some(key)=due {
                        if let Some((p,until))=self.connect("v1/binding",json!({"public_key":key})).await? {
                            if pinned.contains(&key) {let _=self.auth(self.http.post(self.base.join("v1/rendezvous")?)).json(&json!({"public_key":key,"include_binding":true})).send().await?;}
                            peers.insert(key,next(until));events.send(Event::Refreshed(p,until)).await?;
                        }else if pinned.contains(&key){peers.insert(key,Instant::now()+Duration::from_secs(2));}else{peers.remove(&key);}
                    }
                },
                request=requests.recv()=>match request.ok_or("request channel closed")? {
                    Request::Peer(key)=>{
                        if pinned.len()>=9 && !pinned.contains(&key){continue;}pinned.insert(key.clone());
                        if let Some((p,until))=self.connect("v1/binding",json!({"public_key":key})).await? {
                            let _=self.auth(self.http.post(self.base.join("v1/rendezvous")?)).json(&json!({"public_key":p.public_key,"include_binding":true})).send().await?;
                            peers.insert(p.public_key.clone(),next(until));
                            events.send(Event::Refreshed(p,until)).await?;
                        } else { peers.insert(key,Instant::now()+Duration::from_secs(2)); }
                    },
                    Request::Resolve(ip)=>{
                        if peers.len()>=64 {continue;}
                        if let Some((p,until))=self.connect("v1/lookup",json!({"virtual_ip":ip})).await? {
                            if p.virtual_ip!=ip {return Err("lookup address mismatch".into());}
                            let r=self.auth(self.http.post(self.base.join("v1/rendezvous")?)).json(&json!({"public_key":p.public_key,"include_binding":self.introduction==IntroductionMode::Server})).send().await?;
                            if matches!(r.status().as_u16(),404|409|503){events.send(Event::RendezvousUnavailable).await?;if self.introduction==IntroductionMode::Server{continue;}}else{r.error_for_status()?;}
                            events.send(Event::Discovered(p,until)).await?;
                        }
                    },
                    Request::Verify(ticket)=>{
                        let key=hex::encode(ticket.key);
                        if peers.len()>=64 && !peers.contains_key(&key){continue;}
                        if let Some((p,until))=self.connect("v1/binding",json!({"public_key":key})).await? {
                            events.send(Event::Verified(ticket,p,until)).await?;
                        }
                    },
                    Request::Track(key,until)=>{if peers.len()<64 || peers.contains_key(&key){peers.insert(key,next(until));}},
                }
            }
        }
    }
}
