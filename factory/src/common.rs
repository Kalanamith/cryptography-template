use ethers::utils::keccak256;
use k256::ecdsa::{Signature, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey as K256PublicKey;
use serde::Serialize;
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
    // Convert the public key bytes to a K256PublicKey
    let k_pub_key = K256PublicKey::from_sec1_bytes(public_key)?;

    // Get the encoded point in uncompressed format
    let encoded_point = k_pub_key.to_encoded_point(false);
    let encoded_bytes = encoded_point.as_bytes();
    // Note! It's not from the 0x04 prefix for an uncompressed point.
    // So, we need to exclude the first byte (0x04 prefix for an uncompressed point) when hashing.
    let hash = keccak256(&encoded_bytes[1..]);

    // Take the last 20 bytes as the address
    Ok(hash[12..].to_vec())
}
