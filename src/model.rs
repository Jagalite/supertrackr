//! Small per-registration model: production uses this exact Statelessness step.
use stateless::{Check, Model, ModelError, ModelMetadata, Transition};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lease {
    pub expires: u64,
    pub active: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Register { ttl: u64 },
    Check,
    Refresh { ttl: u64 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input {
    pub now: u64,
    pub op: Operation,
}
pub struct Registration;
impl Model for Registration {
    type State = Lease;
    type Input = Input;
    type Output = ();
    fn metadata(&self) -> ModelMetadata {
        ModelMetadata {
            name: "registration".into(),
            model_version: 2,
            properties_version: 1,
            codec_version: 1,
            build: env!("CARGO_PKG_VERSION").into(),
        }
    }
    fn initial_state(&self) -> Result<Lease, ModelError> {
        Ok(Lease::default())
    }
    fn step(&self, s: &Lease, i: &Input) -> Result<Transition<Lease, ()>, ModelError> {
        let state = match i.op {
            Operation::Register { ttl } if !s.active && ttl > 0 => Lease {
                active: true,
                expires: i
                    .now
                    .checked_add(ttl)
                    .ok_or_else(|| ModelError::new("deadline overflow"))?,
            },
            Operation::Check if valid(*s, i.now) => *s,
            Operation::Refresh { ttl } if valid(*s, i.now) && ttl > 0 => Lease {
                active: true,
                expires: i
                    .now
                    .checked_add(ttl)
                    .ok_or_else(|| ModelError::new("deadline overflow"))?,
            },
            _ => return Err(ModelError::new("registration unavailable")),
        };
        Ok(Transition::accepted(state, vec![]))
    }
    fn check_state(&self, s: &Lease) -> Result<Vec<Check>, ModelError> {
        Ok(vec![if !s.active || s.expires > 0 {
            Check::passed("active_has_deadline")
        } else {
            Check::failed("active_has_deadline", "missing deadline")
        }])
    }
}
/// Shared eligibility predicate: expected expiry is not an allocating error path.
pub fn valid(lease: Lease, now: u64) -> bool {
    lease.active && now < lease.expires
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eligibility_and_check_transition_agree_at_boundaries() {
        for active in [false, true] {
            for expires in [0, 1, 10, u64::MAX] {
                for now in [0, 1, 9, 10, u64::MAX - 1, u64::MAX] {
                    let lease = Lease { active, expires };
                    assert_eq!(
                        valid(lease, now),
                        Registration
                            .step(
                                &lease,
                                &Input {
                                    now,
                                    op: Operation::Check
                                }
                            )
                            .is_ok()
                    );
                }
            }
        }
    }
    #[test]
    fn expiry_refresh_and_overflow() {
        let initial = Registration.initial_state().unwrap();
        let s = Registration
            .step(
                &initial,
                &Input {
                    now: 10,
                    op: Operation::Register { ttl: 5 },
                },
            )
            .unwrap()
            .state;
        assert!(valid(s, 14));
        assert!(!valid(s, 15));
        let refreshed = Registration
            .step(
                &s,
                &Input {
                    now: 14,
                    op: Operation::Refresh { ttl: 5 },
                },
            )
            .unwrap()
            .state;
        assert!(valid(refreshed, 18));
        assert!(!valid(refreshed, 19));
        assert!(
            Registration
                .step(
                    &s,
                    &Input {
                        now: 15,
                        op: Operation::Refresh { ttl: 5 }
                    }
                )
                .is_err()
        );
        assert!(
            Registration
                .step(
                    &initial,
                    &Input {
                        now: u64::MAX,
                        op: Operation::Register { ttl: 1 }
                    }
                )
                .is_err()
        );
        assert!(
            Registration
                .step(
                    &s,
                    &Input {
                        now: 11,
                        op: Operation::Register { ttl: 5 }
                    }
                )
                .is_err()
        );
    }
}

/// Pure access policy. The host supplies a constant-time credential comparison
/// and records protected by its storage synchronization; this model performs no I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub lease: Lease,
    pub endpoint: std::net::SocketAddr,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessQuery {
    Caller,
    Peer {
        same_peer: bool,
        target: Option<Binding>,
        claimed_endpoint: Option<std::net::SocketAddr>,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessInput {
    pub now: u64,
    pub caller: Option<Lease>,
    pub token_matches: bool,
    pub query: AccessQuery,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Unauthorized,
    SelfPeer,
    Unavailable,
    EndpointMismatch,
    Allowed { remaining_seconds: u64 },
}
pub struct Access;
impl Model for Access {
    // The state records the most recent decision. It is recomputed from facts
    // on every call and is never retained as a grant or cached authorization.
    type State = Decision;
    type Input = AccessInput;
    type Output = ();
    fn metadata(&self) -> ModelMetadata {
        ModelMetadata {
            name: "peer-access".into(),
            model_version: 1,
            ..Registration.metadata()
        }
    }
    fn initial_state(&self) -> Result<Decision, ModelError> {
        Ok(Decision::Unauthorized)
    }
    fn step(&self, _: &Decision, i: &AccessInput) -> Result<Transition<Decision, ()>, ModelError> {
        let decision = match i
            .caller
            .filter(|lease| i.token_matches && valid(*lease, i.now))
        {
            None => Decision::Unauthorized,
            Some(caller) => match i.query {
                AccessQuery::Caller => Decision::Allowed {
                    remaining_seconds: caller.expires - i.now,
                },
                AccessQuery::Peer {
                    same_peer: true, ..
                } => Decision::SelfPeer,
                AccessQuery::Peer {
                    target,
                    claimed_endpoint,
                    ..
                } => match target.filter(|b| valid(b.lease, i.now)) {
                    None => Decision::Unavailable,
                    Some(b) if claimed_endpoint.is_some_and(|claimed| claimed != b.endpoint) => {
                        Decision::EndpointMismatch
                    }
                    Some(b) => Decision::Allowed {
                        remaining_seconds: b.lease.expires - i.now,
                    },
                },
            },
        };
        Ok(Transition::accepted(decision, vec![]))
    }
    fn check_state(&self, s: &Decision) -> Result<Vec<Check>, ModelError> {
        Ok(vec![if matches!(
            s,
            Decision::Allowed {
                remaining_seconds: 0
            }
        ) {
            Check::failed("allowed_has_lifetime", "zero remaining lifetime")
        } else {
            Check::passed("allowed_has_lifetime")
        }])
    }
}
impl Access {
    pub fn decide(&self, input: &AccessInput) -> Decision {
        self.step(&Decision::Unauthorized, input)
            .expect("access decision is total")
            .state
    }
}

#[cfg(test)]
mod access_tests {
    use super::*;
    fn fixture() -> AccessInput {
        AccessInput {
            now: 10,
            caller: Some(Lease {
                active: true,
                expires: 20,
            }),
            token_matches: true,
            query: AccessQuery::Peer {
                same_peer: false,
                target: Some(Binding {
                    lease: Lease {
                        active: true,
                        expires: 15,
                    },
                    endpoint: "127.0.0.1:51820".parse().unwrap(),
                }),
                claimed_endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            },
        }
    }
    #[test]
    fn caller_authentication_precedes_every_peer_decision() {
        for query in [
            AccessQuery::Caller,
            AccessQuery::Peer {
                same_peer: true,
                target: None,
                claimed_endpoint: None,
            },
            AccessQuery::Peer {
                same_peer: false,
                target: None,
                claimed_endpoint: None,
            },
            fixture().query,
        ] {
            let mut input = fixture();
            input.query = query;
            input.token_matches = false;
            assert_eq!(Access.decide(&input), Decision::Unauthorized);
            input.token_matches = true;
            input.caller = None;
            assert_eq!(Access.decide(&input), Decision::Unauthorized);
            input.caller = Some(Lease {
                active: true,
                expires: input.now,
            });
            assert_eq!(Access.decide(&input), Decision::Unauthorized);
        }
    }
    #[test]
    fn peer_lifetime_and_endpoint_policy_is_recomputed() {
        let mut input = fixture();
        assert_eq!(
            Access.decide(&input),
            Decision::Allowed {
                remaining_seconds: 5
            }
        );
        input.now = 15;
        assert_eq!(Access.decide(&input), Decision::Unavailable);
        input.now = 10;
        if let AccessQuery::Peer {
            ref mut claimed_endpoint,
            ..
        } = input.query
        {
            *claimed_endpoint = Some("127.0.0.1:9999".parse().unwrap());
        }
        assert_eq!(Access.decide(&input), Decision::EndpointMismatch);
        if let AccessQuery::Peer {
            ref mut claimed_endpoint,
            ..
        } = input.query
        {
            *claimed_endpoint = None;
        }
        assert_eq!(
            Access.decide(&input),
            Decision::Allowed {
                remaining_seconds: 5
            }
        );
        if let AccessQuery::Peer {
            ref mut same_peer, ..
        } = input.query
        {
            *same_peer = true;
        }
        assert_eq!(Access.decide(&input), Decision::SelfPeer);
        input.query = AccessQuery::Peer {
            same_peer: false,
            target: None,
            claimed_endpoint: None,
        };
        // Prior success cannot become a cached grant when a peer disappears.
        assert_eq!(
            Access
                .step(
                    &Decision::Allowed {
                        remaining_seconds: 5
                    },
                    &input
                )
                .unwrap()
                .state,
            Decision::Unavailable
        );
    }
}
