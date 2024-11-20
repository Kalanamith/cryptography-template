use k256::ecdsa::{Signature, SigningKey};
use serde::Serialize;
use sha3::{Digest, Keccak256};

/// Trait for converting types to bytes
pub trait ByteOps {
    /// Converts the type to bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use factory::common::ByteOps;
    /// use serde::Serialize;
    ///
    /// #[derive(Serialize)]
    /// struct Test {
    ///     value: String,
    /// }
    ///
    /// let test = Test {
    ///     value: "test".to_string(),
    /// };
    ///
    /// let bytes = test.to_bytes().unwrap();
    /// assert!(!bytes.is_empty());
    /// ```
    fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

impl<T: Serialize> ByteOps for T {
    fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(bincode::serialize(self)?)
    }
}

/// Trait for cryptographic signing and verification
pub trait SecpVRF {
    /// Signs data using a private key
    fn sign(&self, private_key: SigningKey) -> Result<Signature, Box<dyn std::error::Error>>;
    /// Verifies a signature using a public key
    fn verify(
        &self,
        public_key: &k256::PublicKey,
        signature: Signature,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

/// Computes a blockchain address from a public key
///
/// # Examples
///
/// ```
/// use factory::common::get_ethereum_address;
/// use factory::secp::KeySpace;
///
/// let key_space = KeySpace::new();
/// let public_key_bytes = key_space.to_bytes_public_key();
/// let address = get_ethereum_address(&public_key_bytes).unwrap();
///
/// assert_eq!(address.len(), 20); // Address should be 20 bytes
/// ```
pub fn get_ethereum_address(public_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut hasher = Keccak256::new();
    hasher.update(public_key);
    let result = hasher.finalize();
    Ok(result[12..].to_vec())
}
