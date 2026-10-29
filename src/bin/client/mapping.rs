//! Optional router mapping adapter; no router traffic unless explicitly enabled.
use super::Result;
use std::net::SocketAddr;
pub struct Mapping {
    #[cfg(feature = "router-mapping")]
    client: Option<portmapper::Client>,
}
impl Mapping {
    pub fn new(enabled: bool, port: u16) -> Result<Self> {
        #[cfg(feature = "router-mapping")]
        {
            let client = if enabled {
                let client = portmapper::Client::default();
                client
                    .update_local_port(std::num::NonZeroU16::new(port).ok_or("zero mapping port")?);
                Some(client)
            } else {
                None
            };
            Ok(Self { client })
        }
        #[cfg(not(feature = "router-mapping"))]
        {
            let _ = port;
            if enabled {
                return Err("--portmap needs a build with --features router-mapping".into());
            }
            Ok(Self {})
        }
    }
    pub async fn shutdown(&self) {
        #[cfg(feature = "router-mapping")]
        if let Some(client) = &self.client {
            let mut watch = client.watch_external_address();
            client.deactivate();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while watch.borrow_and_update().is_some() {
                    if watch.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await;
        }
    }
    pub fn retry(&self) {
        #[cfg(feature = "router-mapping")]
        if let Some(client) = &self.client {
            client.procure_mapping();
        }
    }
    pub fn address(&self) -> Option<SocketAddr> {
        #[cfg(feature = "router-mapping")]
        {
            self.client
                .as_ref()
                .and_then(|c| *c.watch_external_address().borrow())
                .map(SocketAddr::V4)
        }
        #[cfg(not(feature = "router-mapping"))]
        {
            None
        }
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        #[cfg(feature = "router-mapping")]
        if let Some(client) = &self.client {
            client.deactivate();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disabled_mapping_does_not_start_router_discovery() {
        let mapping = Mapping::new(false, 51820).unwrap();
        assert_eq!(mapping.address(), None);
        #[cfg(not(feature = "router-mapping"))]
        assert!(Mapping::new(true, 51820).is_err());
    }
}
