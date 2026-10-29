//! Account-free proof of possession of the registered X25519/WireGuard key.
//! NaCl box encrypts a random challenge; a scoped HMAC response proves decryption.
use boringtun::x25519::{PublicKey as WgPublic, StaticSecret};
use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead, AeadCore, OsRng},
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    pub public_key: String,
    pub endpoint: SocketAddr,
    pub client_nonce: String,
}
#[derive(Serialize, Deserialize)]
pub struct Challenge {
    pub id: String,
    pub server_key: String,
    pub nonce: String,
    pub ciphertext: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub id: String,
    pub response: String,
}
pub struct Pending {
    pub key: [u8; 32],
    pub endpoint: SocketAddr,
    pub answer_hash: [u8; 32],
    pub until: u64,
}
fn answer(
    secret: &[u8],
    audience: &str,
    key: [u8; 32],
    endpoint: SocketAddr,
    client_nonce: [u8; 32],
    id: [u8; 32],
) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts arbitrary key length");
    mac.update(b"supertrackr/enrollment/v1\0");
    for field in [
        audience.as_bytes(),
        &key,
        endpoint.to_string().as_bytes(),
        &client_nonce,
        &id,
    ] {
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field);
    }
    mac.finalize().into_bytes().into()
}
pub fn issue(
    key: [u8; 32],
    endpoint: SocketAddr,
    client_nonce: [u8; 32],
    audience: &str,
) -> Result<(Challenge, Pending)> {
    let ephemeral = SecretKey::generate(&mut OsRng);
    let wg_secret = StaticSecret::from(ephemeral.to_bytes());
    if wg_secret.diffie_hellman(&WgPublic::from(key)).as_bytes() == &[0; 32] {
        return Err("non-contributory X25519 key".into());
    }
    let secret = Zeroizing::new(rand::random::<[u8; 32]>());
    let id = rand::random();
    let cipher = SalsaBox::new(&PublicKey::from(key), &ephemeral);
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, secret.as_slice())
        .map_err(|_| "challenge encryption failed")?;
    let response = Zeroizing::new(answer(
        secret.as_slice(),
        audience,
        key,
        endpoint,
        client_nonce,
        id,
    ));
    Ok((
        Challenge {
            id: hex::encode(id),
            server_key: hex::encode(ephemeral.public_key().as_bytes()),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        },
        Pending {
            key,
            endpoint,
            answer_hash: Sha256::digest(response.as_slice()).into(),
            until: 0,
        },
    ))
}
pub fn solve(
    challenge: &Challenge,
    secret: &StaticSecret,
    endpoint: SocketAddr,
    client_nonce: [u8; 32],
    audience: &str,
) -> Result<Proof> {
    let mut server = [0; 32];
    hex::decode_to_slice(&challenge.server_key, &mut server)?;
    if secret.diffie_hellman(&WgPublic::from(server)).as_bytes() == &[0; 32] {
        return Err("non-contributory server key".into());
    }
    let mut nonce = [0; 24];
    hex::decode_to_slice(&challenge.nonce, &mut nonce)?;
    let mut id = [0; 32];
    hex::decode_to_slice(&challenge.id, &mut id)?;
    if challenge.ciphertext.len() != 96 {
        return Err("invalid challenge size".into());
    }
    let boxed = SecretKey::from(secret.to_bytes());
    let cipher = SalsaBox::new(&PublicKey::from(server), &boxed);
    let clear = Zeroizing::new(
        cipher
            .decrypt(
                (&nonce).into(),
                hex::decode(&challenge.ciphertext)?.as_slice(),
            )
            .map_err(|_| "challenge decryption failed")?,
    );
    if clear.len() != 32 {
        return Err("invalid challenge plaintext".into());
    }
    let response = Zeroizing::new(answer(
        &clear,
        audience,
        *WgPublic::from(secret).as_bytes(),
        endpoint,
        client_nonce,
        id,
    ));
    Ok(Proof {
        id: challenge.id.clone(),
        response: hex::encode(response.as_slice()),
    })
}
pub async fn register(
    http: &reqwest::Client,
    base: &reqwest::Url,
    secret: &StaticSecret,
    endpoint: SocketAddr,
) -> Result<crate::RegistrationResponse> {
    let client_nonce = rand::random();
    let key = hex::encode(WgPublic::from(secret).as_bytes());
    let challenge: Challenge = http
        .post(base.join("v1/register/challenge")?)
        .json(&ChallengeRequest {
            public_key: key.clone(),
            endpoint,
            client_nonce: hex::encode(client_nonce),
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let proof = solve(&challenge, secret, endpoint, client_nonce, base.as_str())?;
    Ok(http
        .post(base.join("v1/register")?)
        .json(&serde_json::json!({"public_key":key,"endpoint":endpoint,"proof":proof}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proof_requires_private_key_and_binds_audience_endpoint_nonce_and_challenge() {
        let secret = StaticSecret::from([7; 32]);
        let key = *WgPublic::from(&secret).as_bytes();
        let endpoint = "127.0.0.1:10".parse().unwrap();
        let nonce = [9; 32];
        let (c, p) = issue(key, endpoint, nonce, "https://tracker.example/").unwrap();
        let proof = solve(&c, &secret, endpoint, nonce, "https://tracker.example/").unwrap();
        assert_eq!(
            Sha256::digest(hex::decode(proof.response).unwrap()).as_slice(),
            p.answer_hash
        );
        assert!(
            solve(
                &c,
                &StaticSecret::from([8; 32]),
                endpoint,
                nonce,
                "https://tracker.example/"
            )
            .is_err()
        );
        for (ep, n, a) in [
            (endpoint, nonce, "https://other.example/"),
            (
                "127.0.0.1:11".parse().unwrap(),
                nonce,
                "https://tracker.example/",
            ),
            (endpoint, [8; 32], "https://tracker.example/"),
        ] {
            let proof = solve(&c, &secret, ep, n, a).unwrap();
            assert_ne!(
                <[u8; 32]>::from(Sha256::digest(hex::decode(proof.response).unwrap())),
                p.answer_hash
            );
        }
        assert!(issue([0; 32], endpoint, nonce, "x").is_err());
        let mut low = [0; 32];
        low[0] = 1;
        assert!(issue(low, endpoint, nonce, "x").is_err());
    }
}
