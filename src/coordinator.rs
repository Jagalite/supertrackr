//! Async command handle. The spawned task exclusively owns the synchronous registry.
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
