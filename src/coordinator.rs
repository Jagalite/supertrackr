//! Async command handle. The spawned task exclusively owns the synchronous registry.
use crate::core::traversal::{CandidatePeer, Events, InterfaceInfo, PunchHint};
use crate::core::{Config, Credentials, Error, Key, PeerInfo, Registry, Result};
use std::{
    io::Write,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
type Reply<T> = oneshot::Sender<Result<T>>;
enum Command {
    Register {
        key: Key,
        endpoint: SocketAddr,
        credentials: Option<Credentials>,
        token_hash: Key,
        reply: Reply<u64>,
    },
    Peers {
        credentials: Credentials,
        limit: usize,
        reply: Reply<Vec<PeerInfo>>,
    },
    Verify {
        credentials: Credentials,
        target: Key,
        endpoint: SocketAddr,
        reply: Reply<PeerInfo>,
    },
    Candidates {
        who: Credentials,
        candidates: Vec<SocketAddr>,
        reply: Reply<()>,
    },
    Connect {
        who: Credentials,
        target: Key,
        reply: Reply<CandidatePeer>,
    },
    Relay {
        who: Credentials,
        target: Key,
        packet: Vec<u8>,
        reply: Reply<()>,
    },
    Events {
        who: Credentials,
        reply: Reply<Events>,
    },
    Interface {
        who: Credentials,
        reply: Reply<InterfaceInfo>,
    },
    Resolve {
        who: Credentials,
        ip: std::net::Ipv4Addr,
        reply: Reply<CandidatePeer>,
    },
    Lookup {
        who: Credentials,
        ip: std::net::Ipv4Addr,
        reply: Reply<CandidatePeer>,
    },
    Binding {
        who: Credentials,
        target: Key,
        reply: Reply<CandidatePeer>,
    },
    Rendezvous {
        who: Credentials,
        target: Key,
        include_binding: bool,
        reply: Reply<()>,
    },
    PunchHints {
        who: Credentials,
        reply: Reply<Vec<PunchHint>>,
    },
    Cleanup(Reply<()>),
    Len(Reply<usize>),
}
pub struct Coordinator {
    commands: mpsc::UnboundedSender<Command>,
}
impl Coordinator {
    /// Must be called inside a Tokio runtime. Dropping all handles closes the owner task.
    pub fn new(config: Config) -> Arc<Self> {
        let registry = Registry::new(config);
        let (commands, receiver) = mpsc::unbounded_channel();
        let start = Instant::now();
        tokio::spawn(run(registry, receiver, start));
        Arc::new(Self { commands })
    }
    async fn call<T>(&self, command: impl FnOnce(Reply<T>) -> Command) -> Result<T> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(command(reply))
            .map_err(|_| Error::Unavailable)?;
        response.await.map_err(|_| Error::Unavailable)?
    }
    pub async fn register_or_refresh(
        &self,
        key: Key,
        endpoint: SocketAddr,
        credentials: Option<Credentials>,
        token_hash: Key,
    ) -> Result<u64> {
        self.call(|reply| Command::Register {
            key,
            endpoint,
            credentials,
            token_hash,
            reply,
        })
        .await
    }
    pub async fn get_peers(&self, credentials: Credentials, limit: usize) -> Result<Vec<PeerInfo>> {
        self.call(|reply| Command::Peers {
            credentials,
            limit,
            reply,
        })
        .await
    }
    pub async fn verify_peer(
        &self,
        credentials: Credentials,
        target: Key,
        endpoint: SocketAddr,
    ) -> Result<PeerInfo> {
        self.call(|reply| Command::Verify {
            credentials,
            target,
            endpoint,
            reply,
        })
        .await
    }
    pub async fn set_candidates(
        &self,
        who: Credentials,
        candidates: Vec<SocketAddr>,
    ) -> Result<()> {
        self.call(|reply| Command::Candidates {
            who,
            candidates,
            reply,
        })
        .await
    }
    pub async fn connect(&self, who: Credentials, target: Key) -> Result<CandidatePeer> {
        self.call(|reply| Command::Connect { who, target, reply })
            .await
    }
    pub async fn relay(&self, who: Credentials, target: Key, packet: Vec<u8>) -> Result<()> {
        self.call(|reply| Command::Relay {
            who,
            target,
            packet,
            reply,
        })
        .await
    }
    pub async fn events(&self, who: Credentials) -> Result<Events> {
        self.call(|reply| Command::Events { who, reply }).await
    }
    pub async fn interface(&self, who: Credentials) -> Result<InterfaceInfo> {
        self.call(|reply| Command::Interface { who, reply }).await
    }
    pub async fn rendezvous(
        &self,
        who: Credentials,
        target: Key,
        include_binding: bool,
    ) -> Result<()> {
        self.call(|reply| Command::Rendezvous {
            who,
            target,
            include_binding,
            reply,
        })
        .await
    }
    pub async fn punch_hints(&self, who: Credentials) -> Result<Vec<PunchHint>> {
        self.call(|reply| Command::PunchHints { who, reply }).await
    }
    pub async fn lookup(&self, who: Credentials, ip: std::net::Ipv4Addr) -> Result<CandidatePeer> {
        self.call(|reply| Command::Lookup { who, ip, reply }).await
    }
    pub async fn binding(&self, who: Credentials, target: Key) -> Result<CandidatePeer> {
        self.call(|reply| Command::Binding { who, target, reply })
            .await
    }
    pub async fn resolve(&self, who: Credentials, ip: std::net::Ipv4Addr) -> Result<CandidatePeer> {
        self.call(|reply| Command::Resolve { who, ip, reply }).await
    }
    pub async fn cleanup(&self) -> Result<()> {
        self.call(Command::Cleanup).await
    }
    pub async fn len(&self) -> Result<usize> {
        self.call(Command::Len).await
    }
    pub async fn is_empty(&self) -> Result<bool> {
        Ok(self.len().await? == 0)
    }
}

async fn run(
    mut registry: Registry,
    mut receiver: mpsc::UnboundedReceiver<Command>,
    start: Instant,
) {
    let diagnostics = std::env::var_os("SUPERTRACKR_COST_DIAGNOSTICS").is_some();
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            // Run due maintenance even while commands arrive continuously.
            biased;
            _ = tick.tick() => {
                if diagnostics {
                    let wall_us = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok().map(|value| value.as_micros());
                    let begin = Instant::now();
                    let peers = registry.len();
                    registry.cleanup_batch(start.elapsed().as_secs(), 4096);
                    let duration_us = begin.elapsed().as_micros();
                    let _ = writeln!(std::io::stderr().lock(), "{}", serde_json::json!({"diagnostic":"cleanup_batch","wall_start_us":wall_us,"duration_us":duration_us,"peers_before":peers,"peers_after":registry.len()}));
                } else {
                    registry.cleanup_batch(start.elapsed().as_secs(), 4096);
                }
                tick.reset();
            },
            command = receiver.recv() => {
                let Some(command) = command else { break; };
                let now = start.elapsed().as_secs();
                match command {
                    Command::Register { key, endpoint, credentials, token_hash, reply } => {
                        if !reply.is_closed() { let _ = reply.send(registry.register_or_refresh(key, endpoint, credentials, token_hash, now)); }
                    },
                    Command::Peers { credentials, limit, reply } => {
                        if !reply.is_closed() { let _ = reply.send(registry.get_peers(credentials, limit, now)); }
                    },
                    Command::Verify { credentials, target, endpoint, reply } => {
                        if !reply.is_closed() { let _ = reply.send(registry.verify_peer(credentials, target, endpoint, now)); }
                    },
                    Command::Candidates {who,candidates,reply} => {
                        if !reply.is_closed() { let _ = reply.send(registry.set_candidates(who,candidates,now)); }
                    },
                    Command::Connect {who,target,reply} => {
                        if !reply.is_closed() { let _ = reply.send(registry.connect(who,target,now)); }
                    },
                    Command::Relay {who,target,packet,reply} => {
                        if !reply.is_closed() { let _ = reply.send(registry.relay(who,target,packet,now)); }
                    },
                    Command::Events {who,reply} => {
                        if !reply.is_closed() { let _ = reply.send(registry.events(who,now)); }
                    },
                    Command::Rendezvous {who,target,include_binding,reply}=>{if !reply.is_closed(){let _=reply.send(registry.rendezvous_with_binding(who,target,include_binding,now));}},
                    Command::PunchHints {who,reply}=>{if !reply.is_closed(){let _=reply.send(registry.punch_hints(who,now));}},
                    Command::Lookup {who,ip,reply}=>{if !reply.is_closed(){let _=reply.send(registry.lookup(who,ip,now));}},
                    Command::Binding {who,target,reply}=>{if !reply.is_closed(){let _=reply.send(registry.binding(who,target,now));}},
                    Command::Interface {who,reply}=>{if !reply.is_closed(){let _=reply.send(registry.interface(who,now));}},
                    Command::Resolve {who,ip,reply}=>{if !reply.is_closed(){let _=reply.send(registry.resolve(who,ip,now));}},
                    Command::Cleanup(reply) => {
                        if !reply.is_closed() { registry.cleanup(now); let _ = reply.send(Ok(())); }
                    },
                    Command::Len(reply) => { let _ = reply.send(Ok(registry.len())); },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cancelled_queued_mutation_is_skipped_and_owner_exits() {
        let registry = Registry::new(Config {
            open_registration: true,
            ..Config::default()
        });
        let (sender, receiver) = mpsc::unbounded_channel();
        let (reply, response) = oneshot::channel();
        sender
            .send(Command::Register {
                key: [1; 32],
                endpoint: "127.0.0.1:51820".parse().unwrap(),
                credentials: None,
                token_hash: [2; 32],
                reply,
            })
            .ok()
            .unwrap();
        drop(response); // cancelled before the owner can process this command
        let (reply, count) = oneshot::channel();
        sender.send(Command::Len(reply)).ok().unwrap();
        let task = tokio::spawn(run(registry, receiver, Instant::now()));
        assert_eq!(count.await.unwrap().unwrap(), 0);
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn owner_failure_is_reported_as_unavailable() {
        let (commands, receiver) = mpsc::unbounded_channel();
        let handle = Coordinator { commands };
        drop(receiver);
        assert_eq!(handle.len().await, Err(Error::Unavailable));
    }
    #[tokio::test]
    async fn commands_use_processing_time_for_expiry() {
        let mut registry = Registry::new(Config {
            ttl_seconds: 1,
            open_registration: true,
            ..Config::default()
        });
        registry
            .register_or_refresh(
                [1; 32],
                "127.0.0.1:51820".parse().unwrap(),
                None,
                [2; 32],
                0,
            )
            .unwrap();
        let (sender, receiver) = mpsc::unbounded_channel();
        let (reply, response) = oneshot::channel();
        sender
            .send(Command::Peers {
                credentials: Credentials {
                    key: [1; 32],
                    token_hash: [2; 32],
                },
                limit: 1,
                reply,
            })
            .ok()
            .unwrap();
        // Simulate a command that waits until the registration has expired.
        let task = tokio::spawn(run(
            registry,
            receiver,
            Instant::now() - Duration::from_secs(2),
        ));
        assert!(matches!(response.await.unwrap(), Err(Error::Unauthorized)));
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }
}
