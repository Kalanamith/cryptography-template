use anyhow::{anyhow, Error};
use secp256k1::rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

#[derive(Debug)]
pub struct KeySpace {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl KeySpace {
    pub fn new() -> Self {
        let secp_256k1 = Secp256k1::new();
        let (secret_key, public_key) = secp_256k1.generate_keypair(&mut OsRng);

        KeySpace {
            secret_key,
            public_key,
        }
    }

    pub fn from_bytes_key_space(bytes: &[u8]) -> Result<Self, Error> {
        let secret_key = match SecretKey::from_slice(&bytes[0..32]) {
            Ok(secret_key) => secret_key,
            Err(err) => {
                let message = format!("Invalid secret key: {}", err);
                return Err(anyhow!(message));
            }
        };
        let public_key = match PublicKey::from_slice(&bytes[32..]) {
            Ok(public_key) => public_key,
            Err(err) => {
                let message = format!("Invalid public key: {}", err);
                return Err(anyhow!(message));
            }
        };

        Ok(KeySpace {
            secret_key,
            public_key,
        })
    }

    pub fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey, Error> {
        let public_key = match PublicKey::from_slice(bytes) {
            Ok(public_key) => public_key,
            Err(err) => {
                let message = format!("Invalid public key: {}", err);
                return Err(anyhow!(message));
            }
        };
        Ok(public_key)
    }

    pub fn secret_key_from_bytes(bytes: &[u8]) -> Result<SecretKey, Error> {
        let secret_key = match SecretKey::from_slice(bytes) {
            Ok(secret_key) => secret_key,
            Err(err) => {
                return {
                    let message = format!("Invalid private key: {}", err);
                    Err(anyhow!(message))
                }
            }
        };
        Ok(secret_key)
    }

    pub fn to_bytes_key_space(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.secret_key[..]);
        bytes.extend_from_slice(&self.public_key.serialize()[..]);
        bytes
    }

    pub fn to_bytes_public_key(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.public_key.serialize()[..]);
        bytes
    }

    pub fn to_bytes_secret_key(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.secret_key[..]);
        bytes
    }
}
