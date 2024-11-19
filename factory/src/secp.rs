use k256::{
    ecdsa::SigningKey,
    PublicKey,
};

#[derive(Debug, PartialEq)]
pub struct KeySpace {
    pub secret_key: SigningKey,
    pub public_key: PublicKey,
}

impl KeySpace {
    pub fn new() -> Self {
        let secret_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = secret_key.verifying_key();
        let public_key = PublicKey::from(verifying_key);
        
        Self {
            secret_key,
            public_key,
        }
    }

    pub fn to_bytes_public_key(&self) -> Vec<u8> {
        self.public_key.to_sec1_bytes().to_vec()
    }

    pub fn to_bytes_secret_key(&self) -> Vec<u8> {
        self.secret_key.to_bytes().to_vec()
    }

    pub fn to_bytes_key_space(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.to_bytes_secret_key());
        bytes.extend_from_slice(&self.to_bytes_public_key());
        bytes
    }

    pub fn from_bytes_key_space(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let secret_key = SigningKey::from_slice(&bytes[..32])?;
        let public_key = PublicKey::from_sec1_bytes(&bytes[32..])?;
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    pub fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey, Box<dyn std::error::Error>> {
        Ok(PublicKey::from_sec1_bytes(bytes)?)
    }

    pub fn secret_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, Box<dyn std::error::Error>> {
        Ok(SigningKey::from_slice(bytes)?)
    }
} 