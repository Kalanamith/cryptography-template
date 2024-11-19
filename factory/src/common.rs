use k256::ecdsa::{SigningKey, Signature};
use sha3::{Digest, Keccak256};
use serde::Serialize;

pub trait ByteOps {
    fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

impl<T: Serialize> ByteOps for T {
    fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(bincode::serialize(self)?)
    }
}

pub trait SecpVRF {
    fn sign(&self, private_key: SigningKey) -> Result<Signature, Box<dyn std::error::Error>>;
    fn verify(&self, public_key: &k256::PublicKey, signature: Signature) -> Result<(), Box<dyn std::error::Error>>;
}

pub fn get_ethereum_address(public_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut hasher = Keccak256::new();
    hasher.update(&public_key[..]);
    let result = hasher.finalize();
    Ok(result[12..].to_vec())
} 